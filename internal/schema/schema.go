// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"unsafe"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	Directory = "_schemas"
	File      = "schema.yaml"
)

const attrPath = "attr"

func ValidateSchemaProto(s *schemav1.Schema) error {
	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

type Manager interface {
	Validate(context.Context, *enginev1.CheckInput) error
}

type nopManager struct{}

func (nopManager) Validate(_ context.Context, _ *enginev1.CheckInput) error {
	return nil
}

type manager struct {
	conf            *Conf
	log             *zap.SugaredLogger
	store           storage.Store
	mu              sync.RWMutex
	schema          *schemav1.Schema
	principalSchema *jsonschema.Schema
	resourceSchemas map[string]*jsonschema.Schema
}

func New(ctx context.Context, store storage.Store) (Manager, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewWithConf(ctx, store, conf)
}

func NewWithConf(ctx context.Context, store storage.Store, conf *Conf) (Manager, error) {
	if conf.Enforcement == EnforcementNone {
		return nopManager{}, nil
	}

	mgr := &manager{
		conf:  conf,
		log:   zap.S().Named("schema"),
		store: store,
	}

	if err := mgr.UpdateSchemaFromStore(ctx); err != nil {
		if conf.Enforcement == EnforcementReject {
			return nil, fmt.Errorf("schema file not found: %w", err)
		}
		mgr.log.Warnw("schema file not found", "error", err)
	}

	store.Subscribe(mgr)

	return mgr, nil
}

func (m *manager) Validate(ctx context.Context, input *enginev1.CheckInput) error {
	if m.conf.Enforcement == EnforcementNone {
		m.log.Debug("Ignoring schema validation because enforcement is disabled")
		return nil
	}

	m.mu.RLock()
	if m.schema == nil {
		m.mu.RUnlock()
		return nil
	}

	principalSchema := m.principalSchema
	resourceSchema := m.resourceSchemas[input.Resource.Kind]
	m.mu.RUnlock()

	if resourceSchema == nil {
		if m.conf.Enforcement == EnforcementReject {
			return fmt.Errorf("no schema found for resource kind '%s'", input.Resource.Kind)
		}

		m.log.Debugf("No schema found for kind '%s'", input.Resource.Kind)
		return nil
	}

	ctx, span := tracing.StartSpan(ctx, "schema.Validate")
	defer span.End()

	var principalErrs ValidationErrorList
	if err := m.validateAttr(ErrSourcePrincipal, input.Principal.Attr, principalSchema); err != nil {
		if ok := errors.As(err, &principalErrs); !ok {
			return fmt.Errorf("failed to validate the principal: %w", err)
		}
	}

	var resourceErrs ValidationErrorList
	if err := m.validateAttr(ErrSourceResource, input.Resource.Attr, resourceSchema); err != nil {
		if ok := errors.As(err, &resourceErrs); !ok {
			return fmt.Errorf("failed to validate the resource: %w", err)
		}
	}

	numErrs := len(principalErrs) + len(resourceErrs)
	if numErrs == 0 {
		return nil
	}

	logger := logging.FromContext(ctx)
	logFields := []zapcore.Field{
		zap.Any("input", input),
		zap.Strings("principal_errors", principalErrs.ErrorMessages()),
		zap.Strings("resource_errors", resourceErrs.ErrorMessages()),
	}

	if m.conf.Enforcement == EnforcementReject {
		logger.Error("Schema validation failed for input", logFields...)
		return mergeErrLists(principalErrs, resourceErrs)
	}

	logger.Warn("Schema validation failed for input", logFields...)
	return nil
}

func (m *manager) validateAttr(src ErrSource, attr map[string]*structpb.Value, schema *jsonschema.Schema) error {
	jsonBytes, err := protojson.Marshal(&privatev1.AttrWrapper{Attr: attr})
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", src, err)
	}

	attrJSON := gjson.GetBytes(jsonBytes, attrPath).Value()
	if err := schema.Validate(attrJSON); err != nil {
		var validationErr *jsonschema.ValidationError
		if ok := errors.As(err, &validationErr); !ok {
			return fmt.Errorf("unable to validate %s: %w", src, err)
		}

		return newValidationErrorList(validationErr, src)
	}

	return nil
}

func (m *manager) UpdateSchemaFromStore(ctx context.Context) error {
	sch, err := m.store.GetSchema(ctx)
	if err != nil {
		if !m.conf.IgnoreSchemaNotFound {
			return fmt.Errorf("failed to retrieve schema from store: %w", err)
		}

		return nil
	}

	err = m.doUpdateSchema(sch)
	if err != nil {
		return fmt.Errorf("failed to update the schema using store: %w", err)
	}

	return nil
}

func (m *manager) UpdateSchema(source io.Reader) error {
	sch, err := ReadSchema(source)
	if err != nil {
		return fmt.Errorf("failed to read schema from source: %w", err)
	}

	err = m.doUpdateSchema(sch)
	if err != nil {
		return fmt.Errorf("failed to update the schema: %w", err)
	}

	return nil
}

func (m *manager) doUpdateSchema(sch *schemav1.Schema) error {
	if err := ValidateSchemaProto(sch); err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}

	principalSchema, err := toJSONSchema(sch.PrincipalSchema)
	if err != nil {
		return fmt.Errorf("failed to load principal schema: %w", err)
	}

	resourceSchemas := make(map[string]*jsonschema.Schema, len(sch.ResourceSchemas))
	for kind, schema := range sch.ResourceSchemas {
		s, err := toJSONSchema(schema)
		if err != nil {
			return fmt.Errorf("failed to load resource schema for %q: %w", kind, err)
		}

		resourceSchemas[kind] = s
	}

	m.mu.Lock()
	m.schema = sch
	m.principalSchema = principalSchema
	m.resourceSchemas = resourceSchemas
	m.mu.Unlock()

	return nil
}

func toJSONSchema(schemaProps *structpb.Value) (*jsonschema.Schema, error) {
	schemaBytes, err := protojson.Marshal(schemaProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema props: %w", err)
	}

	schema, err := jsonschema.CompileString(File, *(*string)(unsafe.Pointer(&schemaBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to compile JSON schema: %w", err)
	}

	return schema, nil
}

func (m *manager) ClearSchema() {
	m.mu.Lock()
	m.schema = nil
	m.principalSchema = nil
	m.resourceSchemas = nil
	m.mu.Unlock()
}

func (m *manager) SubscriberID() string {
	return "schema.manager"
}

func (m *manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		//nolint:exhaustive
		switch event.Kind {
		case storage.EventAddOrUpdateSchema:
			if err := m.UpdateSchemaFromStore(context.Background()); err != nil {
				m.log.Warnw("Failed to read schema file from store", "error", err)
				continue
			}
			m.log.Debugw("Handled schema add/update event")
		case storage.EventDeleteSchema:
			m.ClearSchema()
			m.log.Debugw("Handled schema deletion event")
		}
	}
}
