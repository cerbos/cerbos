package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"strings"
	"sync"

	"github.com/qri-io/jsonschema"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/storage"
)

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
	ctx, span := tracing.StartSpan(ctx, "schema.Validate")
	defer span.End()
	m.mu.RLock()
	schema := m.schema
	principalProperties := m.principalProperties
	principalSchema := m.principalSchema
	resourceProperties := m.resourceProperties
	resourceSchemas := m.resourceSchemas
	m.mu.RUnlock()
	if schema == nil {
		return nil
	}

	if m.conf.Enforcement == EnforcementNone {
		m.log.Debug("Ignoring schema validation due to enforcement being set to 'none'")
		return nil
	}

	principalValidationErr := m.validatePrincipal(ctx, input.Principal.Attr, principalProperties, principalSchema)
	if principalValidationErr != nil && !IsValidationErrorList(principalValidationErr) {
		return fmt.Errorf("failed to validate the principal: %w", principalValidationErr)
	}

	resourceValidationErr := m.validateResource(ctx, input.Resource.Kind, input.Resource.Attr, resourceProperties,
		resourceSchemas)
	if resourceValidationErr != nil && !IsValidationErrorList(resourceValidationErr) {
		return fmt.Errorf("failed to validate the resource: %w", resourceValidationErr)
	}

	var principalValidationErrorList ValidationErrorList
	ok := errors.As(principalValidationErr, &principalValidationErrorList)
	if !ok {
		principalValidationErrorList = nil
	}

	var resourceValidationErrorList ValidationErrorList
	ok = errors.As(resourceValidationErr, &resourceValidationErrorList)
	if !ok {
		resourceValidationErrorList = nil
	}

	numErrors := len(principalValidationErrorList) + len(resourceValidationErrorList)
	validation := make([]ValidationError, 0, numErrors)
	messages := make([]string, 0, numErrors)

	for _, validationError := range principalValidationErrorList {
		validation = append(validation, validationError)
		messages = append(messages, fmt.Sprintf("%s: %s", validationError.Path,
			validationError.Message))
	}

	for _, validationError := range resourceValidationErrorList {
		validation = append(validation, validationError)
		messages = append(messages, fmt.Sprintf("%s: %s", validationError.Path,
			validationError.Message))
	}

	printFn := logging.FromContext(ctx).Error
	if m.conf.Enforcement == EnforcementWarn {
		printFn = logging.FromContext(ctx).Warn
	}

	if len(validation) != 0 {
		printFn("Schema validation failure", zap.Strings("errors", messages))
	}

	for _, validationData := range validation {
		msg := fmt.Sprintf("Schema validation failed for %s attributes: Path=%s - Message=%s",
			strings.ToLower(validationData.Source.String()),
			validationData.Path, validationData.Message)
		if m.conf.Enforcement == EnforcementWarn {
			logging.FromContext(ctx).Warn(msg)
		} else {
			logging.FromContext(ctx).Error(msg)
		}
	}

	if m.conf.Enforcement == EnforcementReject {
		return MergeValidationErrorLists(principalValidationErrorList, resourceValidationErrorList)
	}

	return nil
}

func (m *Manager) validateInput(inputProperties map[string]*structpb.Value, schemaProperties map[string]string,
	source schemav1.ValidationError_Source) error {
	if m.conf.IgnoreUnknownFields {
		return nil
	}

	var properties = make(map[string]string)
	m.walkInputProperties("", inputProperties, properties)

	var validationErrors []ValidationError
	for _, property := range properties {
		_, ok := schemaProperties[property]
		if !ok {
			validationErrors = append(validationErrors, ValidationError{
				Path:    property,
				Message: "Unexpected field present in the attributes",
				Source:  source,
			})
		}
	}

	return ValidationErrorList(validationErrors)
}

func (m *Manager) validatePrincipal(ctx context.Context,
	principalAttributes map[string]*structpb.Value, principalProperties map[string]string,
	principalSchema *jsonschema.Schema) error {
	inputValidationErr := m.validateInput(principalAttributes, principalProperties, schemav1.ValidationError_SOURCE_PRINCIPAL)
	if inputValidationErr != nil && !IsValidationErrorList(inputValidationErr) {
		return fmt.Errorf("failed to validate the input: %w", inputValidationErr)
	}

	principalAttrBytes, err := protojson.Marshal(&schemav1.AttrWrapper{Attr: principalAttributes})
	if err != nil {
		return fmt.Errorf("failed to marshal principal attributes: %w", err)
	}

	principalValidation, err := principalSchema.ValidateBytes(ctx, principalAttrBytes)
	if err != nil {
		return fmt.Errorf("failed to validate principal attributes: %w", err)
	}

	var inputValidationErrorList ValidationErrorList
	ok := errors.As(inputValidationErr, &inputValidationErrorList)
	if !ok {
		inputValidationErrorList = nil
	}

	return MergeValidationErrorLists(inputValidationErrorList, NewValidationErrorList(principalValidation, schemav1.ValidationError_SOURCE_PRINCIPAL))
}

func (m *Manager) validateResource(ctx context.Context, resourceKind string,
	resourceAttributes map[string]*structpb.Value, resourceProperties map[string]map[string]string,
	resourceSchemas map[string]*jsonschema.Schema) error {
	resourcePropertiesMap, ok := resourceProperties[resourceKind]
	if !ok {
		m.log.Warnf("no schema properties found for the kind '%s'", resourceKind)
		return nil
	}

	inputValidationErr := m.validateInput(resourceAttributes, resourcePropertiesMap, schemav1.ValidationError_SOURCE_RESOURCE)
	if inputValidationErr != nil && !IsValidationErrorList(inputValidationErr) {
		return fmt.Errorf("failed to validate the input: %w", inputValidationErr)
	}

	resourceAttrBytes, err := protojson.Marshal(&schemav1.AttrWrapper{Attr: resourceAttributes})
	if err != nil {
		return fmt.Errorf("failed to marshal resource attributes: %w", err)
	}

	resourceSchema, ok := resourceSchemas[resourceKind]
	if !ok {
		if m.conf.Enforcement == EnforcementReject {
			return fmt.Errorf("no schema found for the kind '%s'", resourceKind)
		}
		m.log.Debugf("no schema found for the kind '%s'", resourceKind)
		return nil
	}

	resourceValidation, err := resourceSchema.ValidateBytes(ctx, resourceAttrBytes)
	if err != nil {
		return fmt.Errorf("failed to validate resource attributes: %w", err)
	}

	var inputValidationErrorList ValidationErrorList
	ok = errors.As(inputValidationErr, &inputValidationErrorList)
	if !ok {
		inputValidationErrorList = nil
	}

	return MergeValidationErrorLists(inputValidationErrorList, NewValidationErrorList(resourceValidation, schemav1.ValidationError_SOURCE_RESOURCE))
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

func (m *Manager) updateSchema(sch *schemav1.Schema) error {
	err := Validate(sch)
	if err != nil {
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

	var resourceSchemaMap = make(map[string]*jsonschema.Schema)
	var resourceProperties = make(map[string]map[string]string)

	for key, resourceSchema := range sch.ResourceSchemas {
		var resourcePropertiesArr = make(map[string]string)
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

func (m *Manager) UpdateSchemaFromStore(ctx context.Context) error {
	sch, err := m.store.GetSchema(ctx)
	if err != nil {
		if !m.conf.IgnoreSchemaNotFound {
			return fmt.Errorf("failed to retrieve schema from store: %w", err)
		} else {
			return nil
		}
	}

	err = m.updateSchema(sch)
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

	err = m.updateSchema(sch)
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

func (m *Manager) SubscriberID() string {
	return "schema.Manager"
}

func (m *Manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		if event.Kind == storage.EventAddOrUpdateSchema {
			err := m.UpdateSchemaFromStore(context.TODO())
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
