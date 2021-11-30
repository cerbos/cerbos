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

var alwaysValidResult = &ValidationResult{Reject: false}

func ValidateSchemaProto(s *schemav1.Schema) error {
	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

type ValidationResult struct {
	Reject bool
	Errors ValidationErrorList
}

func (vr *ValidationResult) add(errs ...ValidationError) {
	vr.Errors = append(vr.Errors, errs...)
}

type Manager interface {
	Validate(context.Context, *enginev1.CheckInput) (*ValidationResult, error)
}

func NewNopManager() NopManager {
	return NopManager{}
}

type NopManager struct{}

func (NopManager) Validate(_ context.Context, _ *enginev1.CheckInput) (*ValidationResult, error) {
	return alwaysValidResult, nil
}

type manager struct {
	conf            *Conf
	log             *zap.Logger
	store           storage.Store
	mu              sync.RWMutex
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
		return NopManager{}, nil
	}

	mgr := &manager{
		conf:  conf,
		log:   zap.L().Named("schema"),
		store: store,
	}

	if err := mgr.UpdateSchemaFromStore(ctx); err != nil {
		mgr.log.Error("Failed to load schema", zap.Error(err))
		return nil, err
	}

	store.Subscribe(mgr)

	return mgr, nil
}

func (m *manager) Validate(ctx context.Context, input *enginev1.CheckInput) (*ValidationResult, error) {
	m.mu.RLock()
	principalSchema := m.principalSchema
	resourceSchema := m.resourceSchemas[input.Resource.Kind]
	m.mu.RUnlock()

	ctx, span := tracing.StartSpan(ctx, "schema.Validate")
	defer span.End()

	result := &ValidationResult{Reject: m.conf.Enforcement == EnforcementReject}

	if err := m.validateAttr(ErrSourcePrincipal, input.Principal.Attr, principalSchema); err != nil {
		var principalErrs ValidationErrorList
		if ok := errors.As(err, &principalErrs); !ok {
			return result, fmt.Errorf("failed to validate the principal: %w", err)
		}
		result.add(principalErrs...)
	}

	if resourceSchema == nil {
		result.add(newResourceSchemaNotFoundErr(input.Resource.Kind))
		return result, nil
	}

	if err := m.validateAttr(ErrSourceResource, input.Resource.Attr, resourceSchema); err != nil {
		var resourceErrs ValidationErrorList
		if ok := errors.As(err, &resourceErrs); !ok {
			return result, fmt.Errorf("failed to validate the resource: %w", err)
		}
		result.add(resourceErrs...)
	}

	if len(result.Errors) > 0 {
		logging.FromContext(ctx).Warn("Validation failed", zap.Any("input", input), zap.Strings("errors", result.Errors.ErrorMessages()))
	}

	return result, nil
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
		return fmt.Errorf("failed to retrieve schema from store: %w", err)
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
	if sch == nil {
		m.ClearSchema()
		return nil
	}

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
				m.log.Warn("Failed to read schema file from store", zap.Error(err))
				continue
			}
			m.log.Debug("Handled schema add/update event")
		case storage.EventDeleteSchema:
			m.log.Warn("Schema was removed from storage. Continuing to use cached copy of schema but the PDP may fail to start next time unless schema enforcement is disabled in the configuration")
		}
	}
}
