package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func New(store storage.Store) (*Manager, error) {
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

	err := mgr.ReadOrUpdateSchemaFromStore()
	if err != nil {
		var msg = fmt.Sprintf("schema file not found: %s", err)
		if conf.Enforcement == EnforcementReject {
			return nil, fmt.Errorf(msg)
		} else {
			mgr.log.Warn(msg)
		}
	}

	store.Subscribe(mgr)

	return mgr, nil
}

func (m *Manager) Validate(ctx context.Context, input *enginev1.CheckInput) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.schema == nil {
		return nil
	}

	if m.conf.Enforcement == EnforcementNone {
		m.log.Debug("Ignoring schema validation due to enforcement being set to 'none'")
		return nil
	}

	principalValidationErr := m.validatePrincipal(ctx, input.Principal.Attr)
	if principalValidationErr != nil && !IsValidationErrorList(principalValidationErr) {
		return fmt.Errorf("failed to validate the principal: %w", principalValidationErr)
	}

	resourceValidationErr := m.validateResource(ctx, input.Resource.Kind, input.Resource.Attr)
	if resourceValidationErr != nil && !IsValidationErrorList(resourceValidationErr) {
		return fmt.Errorf("failed to validate the resource: %w", resourceValidationErr)
	}

	var principalValidationErrorList *ValidationErrorList
	ok := errors.As(principalValidationErr, &principalValidationErrorList)
	if !ok {
		principalValidationErrorList = nil
	}

	var resourceValidationErrorList *ValidationErrorList
	ok = errors.As(resourceValidationErr, &resourceValidationErrorList)
	if !ok {
		resourceValidationErrorList = nil
	}

	numErrors := len(principalValidationErrorList.Errors) + len(resourceValidationErrorList.Errors)
	validation := make([]ValidationError, 0, numErrors)
	messages := make([]string, 0, numErrors)

	for _, validationError := range principalValidationErrorList.Errors {
		validation = append(validation, validationError)
		messages = append(messages, fmt.Sprintf("%s: %s", validationError.Path,
			validationError.Message))
	}

	for _, validationError := range resourceValidationErrorList.Errors {
		validation = append(validation, validationError)
		messages = append(messages, fmt.Sprintf("%s: %s", validationError.Path,
			validationError.Message))
	}

	printFn := logging.FromContext(ctx).Error
	if m.conf.Enforcement == EnforcementWarn {
		printFn = logging.FromContext(ctx).Warn
	}

	if len(validation) != 0 {
		printFn("Schema validation failure", zap.Strings("Errors", messages))
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
	} else {
		return nil
	}
}

func (m *Manager) validateInput(inputProperties map[string]*structpb.Value, schemaProperties map[string]string,
	errorType schemav1.ValidationError_Source) error {
	if m.conf.IgnoreExtraFields {
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
				Source:  errorType,
			})
		}
	}

	return &ValidationErrorList{
		Errors: validationErrors,
	}
}

func (m *Manager) validatePrincipal(ctx context.Context,
	principalAttributes map[string]*structpb.Value) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inputValidationErr := m.validateInput(principalAttributes, m.principalProperties, schemav1.ValidationError_SOURCE_PRINCIPAL)
	if inputValidationErr != nil && !IsValidationErrorList(inputValidationErr) {
		return fmt.Errorf("failed to validate the input: %w", inputValidationErr)
	}

	principalAttrBytes, err := json.Marshal(principalAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal principal attributes: %w", err)
	}

	principalValidation, err := m.principalSchema.ValidateBytes(ctx, principalAttrBytes)
	if err != nil {
		return fmt.Errorf("failed to validate principal attributes: %w", err)
	}

	var inputValidationErrorList *ValidationErrorList
	ok := errors.As(inputValidationErr, &inputValidationErrorList)
	if !ok {
		inputValidationErrorList = nil
	}

	return MergeValidationErrorLists(inputValidationErrorList, NewValidationErrorList(principalValidation, schemav1.ValidationError_SOURCE_PRINCIPAL))
}

func (m *Manager) validateResource(ctx context.Context, resourceKind string,
	resourceAttributes map[string]*structpb.Value) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resourcePropertiesMap, ok := m.resourceProperties[resourceKind]
	if !ok {
		m.log.Warnf("no schema properties found for the kind '%s'", resourceKind)
		return nil
	}

	inputValidationErr := m.validateInput(resourceAttributes, resourcePropertiesMap, schemav1.ValidationError_SOURCE_RESOURCE)
	if inputValidationErr != nil && !IsValidationErrorList(inputValidationErr) {
		return fmt.Errorf("failed to validate the input: %w", inputValidationErr)
	}

	resourceAttrBytes, err := json.Marshal(resourceAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal resource attributes: %w", err)
	}

	resourceSchema, ok := m.resourceSchemas[resourceKind]
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

	var inputValidationErrorList *ValidationErrorList
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

func (m *Manager) ReadOrUpdateSchemaFromStore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sch, err := m.store.GetSchema(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to retrieve schema from store: %w", err)
	}

	err = Validate(sch)
	if err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}

	m.walkSchemaProperties("", sch.PrincipalSchema.Properties, m.principalProperties)

	principalSchema, err := json.Marshal(sch.PrincipalSchema)
	if err != nil {
		return fmt.Errorf("failed to marshal principal schema: %w", err)
	}

	principalSchemaObject := &jsonschema.Schema{}
	if err := json.Unmarshal(principalSchema, principalSchemaObject); err != nil {
		return fmt.Errorf("failed to unmarshal into principal schema object: %w", err)
	}

	resourceSchemaMap := make(map[string]*jsonschema.Schema)

	m.schema = sch
	m.principalSchema = principalSchemaObject

	for key, resourceSchema := range sch.ResourceSchemas {
		var resourcePropertiesArr = make(map[string]string)
		m.walkSchemaProperties("", resourceSchema.Properties, resourcePropertiesArr)
		m.resourceProperties[key] = resourcePropertiesArr

		resourceSchemaBytes, err := json.Marshal(resourceSchema)
		if err != nil {
			return fmt.Errorf("failed to marshal resource schema: %w", err)
		}

		resourceSchemaObject := &jsonschema.Schema{}
		if err := json.Unmarshal(resourceSchemaBytes, resourceSchemaObject); err != nil {
			return fmt.Errorf("failed to unmarshal into resource schema object: %w", err)
		}

		resourceSchemaMap[key] = resourceSchemaObject
	}

	m.resourceSchemas = resourceSchemaMap

	return nil
}

func (m *Manager) SubscriberID() string {
	return "schema.Manager"
}

func (m *Manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		if event.Kind == storage.EventAddOrUpdateSchema {
			err := m.ReadOrUpdateSchemaFromStore()
			if err != nil {
				m.log.Warnw("Failed to read schema file from store", "event", event)
				return
			}
			m.log.Debugw("Handled schema add/update event", "event", event)
		} else if event.Kind == storage.EventDeleteSchema {
			m.mu.Lock()
			m.schema = nil
			m.principalSchema = nil
			m.resourceSchemas = nil
			m.mu.Unlock()
			m.log.Debugw("Handled schema deletion event", "event", event)
		}
	}
}
