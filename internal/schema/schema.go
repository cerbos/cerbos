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

type Manager struct {
	conf                *Conf
	log                 *zap.SugaredLogger
	store               storage.Store
	mu                  sync.RWMutex
	principalProperties map[string]string
	resourceProperties  map[string]map[string]string
	schema              *schemav1.Schema
	principalSchema     *jsonschema.Schema
	resourceSchemas     map[string]*jsonschema.Schema
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
		conf:                conf,
		log:                 zap.S().Named("schema"),
		store:               store,
		principalProperties: make(map[string]string),
		resourceProperties:  make(map[string]map[string]string),
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
		m.log.Debug("Ignoring schema validation due to enforcement being set to 'none'")
		return nil
	}

	m.mu.RLock()
	if m.schema == nil {
		m.mu.RUnlock()
		return nil
	}

	principalProps := m.principalProperties
	principalSchema := m.principalSchema
	resourceProps := m.resourceProperties[input.Resource.Kind]
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

	allErrs := make([]ValidationError, 0, numErrs)
	errMsgs := make([]string, 0, numErrs)

	for _, err := range principalErrs {
		allErrs = append(allErrs, err)
		errMsgs = append(errMsgs, err.Error())
	}

	for _, err := range resourceErrs {
		allErrs = append(allErrs, err)
		errMsgs = append(errMsgs, err.Error())
	}

	logger := logging.FromContext(ctx)
	if m.conf.Enforcement == EnforcementReject {
		logger.Error("Schema validation failed for input", zap.Any("input", input), zap.Strings("errors", errMsgs))
		return mergeErrLists(principalErrs, resourceErrs)
	}

	logger.Warn("Schema validation failed for input", zap.Any("input", input), zap.Strings("errors", errMsgs))
	return nil
}

func (m *Manager) validateAttr(ctx context.Context, src ErrSource, attr map[string]*structpb.Value, props map[string]string, schema *jsonschema.Schema) error {
	var inputErrs ValidationErrorList
	if err := m.validateInput(src, attr, props); err != nil {
		if ok := errors.As(err, &inputErrs); !ok {
			return fmt.Errorf("failed to validate properties of %s: %w", src, err)
		}
	}

	attrBytes, err := protojson.Marshal(&schemav1.AttrWrapper{Attr: attr})
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", src, err)
	}

	validationErrs, err := schema.ValidateBytes(ctx, []byte(gjson.GetBytes(attrBytes, attrPath).Raw))
	if err != nil {
		return fmt.Errorf("failed to validate %s: %w", src, err)
	}

	return mergeErrLists(inputErrs, newValidationErrorList(validationErrs, src))
}

func (m *Manager) validateInput(src ErrSource, inputProperties map[string]*structpb.Value, schemaProperties map[string]string) error {
	if m.conf.IgnoreUnknownFields {
		return nil
	}

	properties := make(map[string]string)
	m.walkInputProperties("", inputProperties, properties)

	var validationErrors []ValidationError
	for _, property := range properties {
		_, ok := schemaProperties[property]
		if !ok {
			validationErrors = append(validationErrors, ValidationError{
				Path:    property,
				Message: "Unexpected field present in the attributes",
				Source:  src,
			})
		}
	}

	return ValidationErrorList(validationErrors)
}

func (m *Manager) walkInputProperties(path string, properties map[string]*structpb.Value, writeTo map[string]string) {
	for key, value := range properties {
		structVal, ok := value.Kind.(*structpb.Value_StructValue)
		if !ok {
			writeTo[fmt.Sprintf("%s/%s", path, key)] = fmt.Sprintf("%s/%s", path, key)
			continue
		}
		if structVal.StructValue.Fields != nil {
			m.walkInputProperties(fmt.Sprintf("%s/%s", path, key), structVal.StructValue.Fields, writeTo)
		}
	}
}

func (m *Manager) walkSchemaProperties(path string, properties map[string]*schemav1.JSONSchemaProps,
	writeTo map[string]string) {
	for name, value := range properties {
		if value.Type != "object" {
			writeTo[fmt.Sprintf("%s/%s", path, name)] = fmt.Sprintf("%s/%s", path, name)
			continue
		}
		if value.Properties != nil {
			m.walkSchemaProperties(fmt.Sprintf("%s/%s", path, name), value.Properties, writeTo)
		}
	}
}

func (m *Manager) UpdateSchemaFromStore(ctx context.Context) error {
	sch, err := m.store.GetSchema(ctx)
	if err != nil {
		if !m.conf.IgnoreSchemaNotFound {
			return fmt.Errorf("failed to retrieve schema from store: %w", err)
		} else {
			return nil
		}
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
	m.principalProperties = nil
	m.principalSchema = nil
	m.resourceProperties = nil
	m.resourceSchemas = nil
	m.mu.Unlock()
}

func (m *Manager) doUpdateSchema(sch *schemav1.Schema) error {
	if err := Validate(sch); err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}

	principalProperties := make(map[string]string)
	m.walkSchemaProperties("", sch.PrincipalSchema.Properties, principalProperties)

	principalSchema, err := protojson.Marshal(sch.PrincipalSchema)
	if err != nil {
		return fmt.Errorf("failed to marshal principal schema: %w", err)
	}

	principalSchemaObject := &jsonschema.Schema{}
	if err := json.Unmarshal(principalSchema, principalSchemaObject); err != nil {
		return fmt.Errorf("failed to unmarshal into principal schema object: %w", err)
	}

	resourceSchemaMap := make(map[string]*jsonschema.Schema)
	resourceProperties := make(map[string]map[string]string)

	for key, resourceSchema := range sch.ResourceSchemas {
		resourcePropertiesArr := make(map[string]string)
		m.walkSchemaProperties("", resourceSchema.Properties, resourcePropertiesArr)
		resourceProperties[key] = resourcePropertiesArr

		resourceSchemaBytes, err := protojson.Marshal(resourceSchema)
		if err != nil {
			return fmt.Errorf("failed to marshal resource schema: %w", err)
		}

		resourceSchemaObject := &jsonschema.Schema{}
		if err := json.Unmarshal(resourceSchemaBytes, resourceSchemaObject); err != nil {
			return fmt.Errorf("failed to unmarshal into resource schema object: %w", err)
		}

		resourceSchemaMap[key] = resourceSchemaObject
	}

	m.mu.Lock()
	m.schema = sch
	m.principalProperties = principalProperties
	m.principalSchema = principalSchemaObject
	m.resourceProperties = resourceProperties
	m.resourceSchemas = resourceSchemaMap
	m.mu.Unlock()

	return nil
}

func (m *Manager) SubscriberID() string {
	return "schema.Manager"
}

func (m *Manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		if event.Kind == storage.EventAddOrUpdateSchema {
			err := m.UpdateSchemaFromStore(context.Background())
			if err != nil {
				m.log.Warnw("Failed to read schema file from store", "event", event)
				return
			}
			m.log.Debugw("Handled schema add/update event", "event", event)
		} else if event.Kind == storage.EventDeleteSchema {
			m.mu.Lock()
			m.schema = nil
			m.principalSchema = nil
			m.principalProperties = nil
			m.resourceSchemas = nil
			m.resourceProperties = nil
			m.mu.Unlock()
			m.log.Debugw("Handled schema deletion event", "event", event)
		}
	}
}
