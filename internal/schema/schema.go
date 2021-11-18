package schema

import (
	"context"
	"encoding/json"
	"fmt"

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
	conf            *Conf
	log             *zap.SugaredLogger
	store           storage.Store
	schema          *schemav1.Schema
	principalSchema *jsonschema.Schema
	resourceSchemas map[string]*jsonschema.Schema
}

func New(store storage.Store) (*Manager, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	mgr := &Manager{
		conf:  conf,
		log:   zap.S().Named("schema"),
		store: store,
	}

	err := mgr.ReadOrUpdateSchemaFromStore()
	if err != nil {
		mgr.log.Error("Failed to read schema file from store")
	}

	store.Subscribe(mgr)

	return mgr, nil
}

func (m *Manager) Validate(ctx context.Context, input *enginev1.CheckInput) ([]jsonschema.KeyError, error) {
	if m.schema == nil {
		return nil, nil
	}

	if m.conf.Enforcement == EnforcementNone {
		m.log.Warn("Ignoring schema validation due to enforcement being set to 'none'")
		return nil, nil
	}

	principalValidation, err := m.validatePrincipal(ctx, input.Principal.Attr)
	if err != nil {
		return nil, err
	}

	resourceValidation, err := m.validateResource(ctx, input.Resource.Kind, input.Resource.Attr)
	if err != nil {
		return nil, err
	}

	var validation []jsonschema.KeyError
	for _, keyError := range principalValidation {
		validation = append(validation, keyError)
	}

	for _, keyError := range resourceValidation {
		validation = append(validation, keyError)
	}

	for _, validationData := range validation {
		msg := fmt.Sprintf("Schema validation failed: Path=%s - Message=%s", validationData.PropertyPath,
			validationData.Message)
		if m.conf.Enforcement == EnforcementWarn {
			logging.FromContext(ctx).Warn(msg)
		} else {
			logging.FromContext(ctx).Error(msg)
		}
	}

	if m.conf.Enforcement == EnforcementReject {
		return validation, nil
	} else {
		return nil, nil
	}
}

func (m *Manager) validatePrincipal(ctx context.Context, principalAttributes map[string]*structpb.Value) ([]jsonschema.KeyError, error) {
	principalAttrBytes, err := json.Marshal(principalAttributes)
	if err != nil {
		return nil, err
	}

	principalValidation, err := m.principalSchema.ValidateBytes(ctx, principalAttrBytes)
	if err != nil {
		return nil, err
	}

	return principalValidation, nil
}

func (m *Manager) validateResource(ctx context.Context, resourceKind string, resourceAttributes map[string]*structpb.Value) ([]jsonschema.KeyError, error) {
	resourceAttrBytes, err := json.Marshal(resourceAttributes)
	if err != nil {
		return nil, err
	}

	resourceSchema, ok := m.resourceSchemas[resourceKind]
	if !ok {
		m.log.Warnf("no schema found for the kind '%s'", resourceKind)
		return nil, nil
	}

	resourceValidation, err := resourceSchema.ValidateBytes(ctx, resourceAttrBytes)
	if err != nil {
		return nil, err
	}

	return resourceValidation, nil
}

func (m *Manager) ReadOrUpdateSchemaFromStore() error {
	// TODO(oguzhan): How to handle context?
	sch, err := m.store.GetSchema(context.TODO())
	if err != nil {
		return err
	}

	principalSchema, err := json.Marshal(sch.PrincipalSchema)
	if err != nil {
		return err
	}

	principalSchemaObject := &jsonschema.Schema{}
	if err := json.Unmarshal(principalSchema, principalSchemaObject); err != nil {
		return err
	}

	resourceSchemaMap := make(map[string]*jsonschema.Schema)

	m.schema = sch
	m.principalSchema = principalSchemaObject

	for key, resourceSchema := range sch.ResourceSchema {
		resourceSchemaBytes, err := json.Marshal(resourceSchema)
		if err != nil {
			return err
		}

		resourceSchemaObject := &jsonschema.Schema{}
		if err := json.Unmarshal(resourceSchemaBytes, resourceSchemaObject); err != nil {
			return err
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
				m.log.Errorw("Failed to read schema file from store", "event", event)
				return
			}

			m.log.Infow("Handled schema add/update event", "event", event)
		} else if event.Kind == storage.EventDeleteSchema {
			m.schema = nil
			m.principalSchema = nil
			m.resourceSchemas = nil
			m.log.Infow("Handled schema deletion event", "event", event)
		}
	}
}
