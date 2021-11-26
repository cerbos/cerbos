// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/qri-io/jsonschema"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"
)

const attrPath = "attr"

type propSet map[string]struct{}

func ValidateSchemaProto(s *schemav1.Schema) error {
	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

type Manager struct {
	conf            *Conf
	log             *zap.SugaredLogger
	store           storage.Store
	mu              sync.RWMutex
	principalProps  propSet
	resourceProps   map[string]propSet
	schema          *schemav1.Schema
	principalSchema *jsonschema.Schema
	resourceSchemas map[string]*jsonschema.Schema
}

func New(ctx context.Context, store storage.Store) (*Manager, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewWithConf(ctx, store, conf)
}

func NewWithConf(ctx context.Context, store storage.Store, conf *Conf) (*Manager, error) {
	mgr := &Manager{
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

func (m *Manager) Validate(ctx context.Context, input *enginev1.CheckInput) error {
	if m.conf.Enforcement == EnforcementNone {
		m.log.Debug("Ignoring schema validation because enforcement is disabled")
		return nil
	}

	m.mu.RLock()
	if m.schema == nil {
		m.mu.RUnlock()
		return nil
	}

	principalProps := m.principalProps
	principalSchema := m.principalSchema
	resourceProps := m.resourceProps[input.Resource.Kind]
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
	if err := m.validateAttr(ctx, ErrSourcePrincipal, input.Principal.Attr, principalProps, principalSchema); err != nil {
		if ok := errors.As(err, &principalErrs); !ok {
			return fmt.Errorf("failed to validate the principal: %w", err)
		}
	}

	var resourceErrs ValidationErrorList
	if err := m.validateAttr(ctx, ErrSourceResource, input.Resource.Attr, resourceProps, resourceSchema); err != nil {
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

func (m *Manager) validateAttr(ctx context.Context, src ErrSource, attr map[string]*structpb.Value, props propSet, schema *jsonschema.Schema) error {
	var inputErrs ValidationErrorList
	if !m.conf.IgnoreUnknownFields {
		if err := validateInput(src, attr, props); err != nil {
			if ok := errors.As(err, &inputErrs); !ok {
				return fmt.Errorf("failed to validate properties of %s: %w", src, err)
			}
		}
	}

	jsonBytes, err := protojson.Marshal(&schemav1.AttrWrapper{Attr: attr})
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", src, err)
	}

	attrBytes := []byte(gjson.GetBytes(jsonBytes, attrPath).Raw)
	validationErrs, err := schema.ValidateBytes(ctx, attrBytes)
	if err != nil {
		return fmt.Errorf("failed to validate %s: %w", src, err)
	}

	return mergeErrLists(inputErrs, newValidationErrorList(validationErrs, src))
}

func validateInput(src ErrSource, attr map[string]*structpb.Value, props propSet) error {
	properties := propertiesFromInput(attr)

	var errs ValidationErrorList
	for p := range properties {
		if _, ok := props[p]; !ok {
			errs = append(errs, ValidationError{
				Path:    p,
				Message: "Unexpected field present in the attributes",
				Source:  src,
			})
		}
	}

	return errs.ErrOrNil()
}

func propertiesFromInput(attr map[string]*structpb.Value) map[string]struct{} {
	out := make(map[string]struct{}, len(attr))
	walkPropertiesFromInput("", attr, out)
	return out
}

func walkPropertiesFromInput(path string, attr map[string]*structpb.Value, out map[string]struct{}) {
	for key, value := range attr {
		fullPath := fmt.Sprintf("%s/%s", path, key)
		structVal, ok := value.Kind.(*structpb.Value_StructValue)
		if !ok {
			out[fullPath] = struct{}{}
			continue
		}

		if structVal.StructValue.Fields != nil {
			walkPropertiesFromInput(fullPath, structVal.StructValue.Fields, out)
		}
	}
}

func propertiesFromSchema(schemaProps map[string]*schemav1.JSONSchemaProps) map[string]struct{} {
	out := make(map[string]struct{}, len(schemaProps))
	walkPropertiesFromSchema("", schemaProps, out)
	return out
}

func walkPropertiesFromSchema(path string, schemaProps map[string]*schemav1.JSONSchemaProps, out map[string]struct{}) {
	for name, value := range schemaProps {
		fullPath := fmt.Sprintf("%s/%s", path, name)
		if value.Type != "object" {
			out[fullPath] = struct{}{}
			continue
		}

		if value.Properties != nil {
			walkPropertiesFromSchema(fullPath, value.Properties, out)
		}
	}
}

func (m *Manager) UpdateSchemaFromStore(ctx context.Context) error {
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

func (m *Manager) UpdateSchema(source io.Reader) error {
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

func (m *Manager) ClearSchema() {
	m.mu.Lock()
	m.schema = nil
	m.principalProps = nil
	m.principalSchema = nil
	m.resourceProps = nil
	m.resourceSchemas = nil
	m.mu.Unlock()
}

func (m *Manager) doUpdateSchema(sch *schemav1.Schema) error {
	if err := ValidateSchemaProto(sch); err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}

	principalProps := propertiesFromSchema(sch.PrincipalSchema.Properties)
	principalSchema, err := toJSONSchema(sch.PrincipalSchema)
	if err != nil {
		return fmt.Errorf("failed to load principal schema: %w", err)
	}

	resourceSchemas := make(map[string]*jsonschema.Schema, len(sch.ResourceSchemas))
	resourceProps := make(map[string]propSet, len(sch.ResourceSchemas))

	for kind, schema := range sch.ResourceSchemas {
		resourceProps[kind] = propertiesFromSchema(schema.Properties)
		s, err := toJSONSchema(schema)
		if err != nil {
			return fmt.Errorf("failed to load resource schema for %q: %w", kind, err)
		}

		resourceSchemas[kind] = s
	}

	m.mu.Lock()
	m.schema = sch
	m.principalProps = principalProps
	m.principalSchema = principalSchema
	m.resourceProps = resourceProps
	m.resourceSchemas = resourceSchemas
	m.mu.Unlock()

	return nil
}

func toJSONSchema(schemaProps *schemav1.JSONSchemaProps) (*jsonschema.Schema, error) {
	schemaBytes, err := protojson.Marshal(schemaProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema props: %w", err)
	}

	schema := &jsonschema.Schema{}
	if err := json.Unmarshal(schemaBytes, schema); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON schema: %w", err)
	}

	return schema, nil
}

func (m *Manager) SubscriberID() string {
	return "schema.Manager"
}

func (m *Manager) OnStorageEvent(events ...storage.Event) {
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
