// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/bluele/gcache"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	URLScheme    = "cerbos"
	attrPath     = "attr"
	maxCacheSize = 64
)

var alwaysValidResult = &ValidationResult{Reject: false}

type ValidationResult struct {
	Reject bool
	Errors ValidationErrorList
}

func (vr *ValidationResult) add(errs ...ValidationError) {
	vr.Errors = append(vr.Errors, errs...)
}

type Manager interface {
	Validate(context.Context, *policyv1.Schemas, *enginev1.CheckInput) (*ValidationResult, error)
	CheckSchema(context.Context, string) error
}

func NewNopManager() NopManager {
	return NopManager{}
}

type NopManager struct{}

func (NopManager) Validate(_ context.Context, _ *policyv1.Schemas, _ *enginev1.CheckInput) (*ValidationResult, error) {
	return alwaysValidResult, nil
}

func (NopManager) CheckSchema(_ context.Context, _ string) error {
	return nil
}

type manager struct {
	conf  *Conf
	log   *zap.Logger
	store storage.Store
	cache gcache.Cache
}

func New(ctx context.Context, store storage.Store) (Manager, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewWithConf(ctx, store, conf), nil
}

func NewWithConf(ctx context.Context, store storage.Store, conf *Conf) Manager {
	if conf.Enforcement == EnforcementNone {
		return NopManager{}
	}

	mgr := &manager{
		conf:  conf,
		log:   zap.L().Named("schema"),
		store: store,
		cache: gcache.New(maxCacheSize).ARC().Build(),
	}

	store.Subscribe(mgr)

	return mgr
}

func (m *manager) CheckSchema(ctx context.Context, url string) error {
	_, err := m.loadSchema(ctx, url)
	return err
}

func (m *manager) Validate(ctx context.Context, schemas *policyv1.Schemas, input *enginev1.CheckInput) (*ValidationResult, error) {
	ctx, span := tracing.StartSpan(ctx, "schema.Validate")
	defer span.End()

	result := &ValidationResult{Reject: m.conf.Enforcement == EnforcementReject}

	if err := m.validateAttr(ctx, ErrSourcePrincipal, schemas.PrincipalSchema, input.Principal.Attr); err != nil {
		var principalErrs ValidationErrorList
		if ok := errors.As(err, &principalErrs); !ok {
			return result, fmt.Errorf("failed to validate the principal: %w", err)
		}
		result.add(principalErrs...)
	}

	if err := m.validateAttr(ctx, ErrSourceResource, schemas.ResourceSchema, input.Resource.Attr); err != nil {
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

func (m *manager) validateAttr(ctx context.Context, src ErrSource, schemaRef *policyv1.Schemas_Schema, attr map[string]*structpb.Value) error {
	if schemaRef == nil || schemaRef.Ref == "" {
		return nil
	}

	schema, err := m.loadSchema(ctx, schemaRef.Ref)
	if err != nil {
		m.log.Warn("Failed to load schema", zap.String("schema", schemaRef.Ref), zap.Error(err))
		return newSchemaLoadErr(src, schemaRef.Ref)
	}

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

func (m *manager) loadSchema(ctx context.Context, url string) (*jsonschema.Schema, error) {
	entry, err := m.cache.GetIFPresent(url)
	if err == nil {
		if e, ok := entry.(*cacheEntry); ok {
			return e.schema, e.err
		}
	}

	e := &cacheEntry{}
	e.schema, e.err = m.store.LoadSchema(ctx, url)

	if e.err != nil && errors.Is(e.err, fs.ErrNotExist) {
		e.err = fmt.Errorf("schema %q does not exist in the store", url)
	}

	_ = m.cache.Set(url, e)

	return e.schema, e.err
}

func (m *manager) SubscriberID() string {
	return "schema.manager"
}

func (m *manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		//nolint:exhaustive
		switch event.Kind {
		case storage.EventAddOrUpdateSchema:
			cacheKey := fmt.Sprintf("%s/%s", URLScheme, event.SchemaFile)
			_ = m.cache.Remove(cacheKey)
			m.log.Debug("Handled schema add/update event", zap.String("schema", cacheKey))
		case storage.EventDeleteSchema:
			cacheKey := fmt.Sprintf("%s/%s", URLScheme, event.SchemaFile)
			_ = m.cache.Remove(cacheKey)
			m.log.Warn("Handled schema delete event", zap.String("schema", cacheKey))
		}
	}
}

type cacheEntry struct {
	schema *jsonschema.Schema
	err    error
}
