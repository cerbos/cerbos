// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"strings"

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
	"github.com/cerbos/cerbos/internal/util"
)

const (
	Directory = "_schemas"
	URLScheme = "cerbos"
	attrPath  = "attr"
)

var alwaysValidResult = &ValidationResult{Reject: false}

type ValidationResult struct {
	Errors ValidationErrorList
	Reject bool
}

func (vr *ValidationResult) add(errs ...ValidationError) {
	vr.Errors = append(vr.Errors, errs...)
}

type Manager interface {
	Validate(context.Context, *policyv1.Schemas, *enginev1.CheckInput) (*ValidationResult, error)
	CheckSchema(context.Context, string) error
}

type Loader interface {
	storage.Subscribable
	LoadSchema(context.Context, string) (io.ReadCloser, error)
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
	conf   *Conf
	log    *zap.Logger
	loader Loader
	cache  gcache.Cache
}

func New(ctx context.Context, loader Loader) (Manager, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewWithConf(ctx, loader, conf), nil
}

func NewWithConf(ctx context.Context, loader Loader, conf *Conf) Manager {
	if conf.Enforcement == EnforcementNone {
		return NopManager{}
	}

	mgr := &manager{
		conf:   conf,
		log:    zap.L().Named("schema"),
		loader: loader,
		cache:  gcache.New(int(conf.CacheSize)).ARC().Build(),
	}

	loader.Subscribe(mgr)

	return mgr
}

func (m *manager) CheckSchema(ctx context.Context, url string) error {
	_, err := m.loadSchema(ctx, url)
	return err
}

func (m *manager) Validate(ctx context.Context, schemas *policyv1.Schemas, input *enginev1.CheckInput) (*ValidationResult, error) {
	result := &ValidationResult{Reject: m.conf.Enforcement == EnforcementReject}
	if schemas == nil {
		return result, nil
	}

	ctx, span := tracing.StartSpan(ctx, "schema.Validate")
	defer span.End()

	if err := m.validateAttr(ctx, ErrSourcePrincipal, schemas.PrincipalSchema, input.Principal.Attr, input.Actions); err != nil {
		var principalErrs ValidationErrorList
		if ok := errors.As(err, &principalErrs); !ok {
			return result, fmt.Errorf("failed to validate the principal: %w", err)
		}
		result.add(principalErrs...)
	}

	if err := m.validateAttr(ctx, ErrSourceResource, schemas.ResourceSchema, input.Resource.Attr, input.Actions); err != nil {
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

func (m *manager) validateAttr(ctx context.Context, src ErrSource, schemaRef *policyv1.Schemas_Schema, attr map[string]*structpb.Value, actions []string) error {
	if schemaRef == nil || schemaRef.Ref == "" {
		return nil
	}

	// check whether the current actions are excluded from validation
	if ignore := schemaRef.IgnoreWhen; ignore != nil && len(ignore.Actions) > 0 {
		toValidate := filterActionsToValidate(ignore.Actions, actions)
		if len(toValidate) == 0 {
			return nil
		}

		if len(toValidate) != len(actions) {
			m.log.Warn("Schema validation is enabled for some actions but disabled for others",
				zap.Strings("all_actions", actions),
				zap.Strings("actions_requiring_validation", toValidate))
		}
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
	e.schema, e.err = m.loadSchemaFromStore(ctx, url)

	if e.err != nil && errors.Is(e.err, fs.ErrNotExist) {
		e.err = fmt.Errorf("schema %q does not exist in the store", url)
	}

	_ = m.cache.Set(url, e)

	return e.schema, e.err
}

func (m *manager) loadSchemaFromStore(ctx context.Context, schemaURL string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = func(path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		if u.Scheme == "" || u.Scheme == URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")
			return m.loader.LoadSchema(ctx, relativePath)
		}

		loader, ok := jsonschema.Loaders[u.Scheme]
		if !ok {
			return nil, jsonschema.LoaderNotFoundError(path)
		}
		return loader(path)
	}

	return compiler.Compile(schemaURL)
}

func (m *manager) SubscriberID() string {
	return "schema.manager"
}

func (m *manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		//nolint:exhaustive
		switch event.Kind {
		case storage.EventAddOrUpdateSchema:
			cacheKey := fmt.Sprintf("%s:///%s", URLScheme, event.SchemaFile)
			_ = m.cache.Remove(cacheKey)
			m.log.Debug("Handled schema add/update event", zap.String("schema", cacheKey))
		case storage.EventDeleteSchema:
			cacheKey := fmt.Sprintf("%s:///%s", URLScheme, event.SchemaFile)
			_ = m.cache.Remove(cacheKey)
			m.log.Warn("Handled schema delete event", zap.String("schema", cacheKey))
		}
	}
}

type cacheEntry struct {
	schema *jsonschema.Schema
	err    error
}

func filterActionsToValidate(ignore, actions []string) []string {
	filtered := actions
	for _, glob := range ignore {
		filtered = util.FilterGlobNotMatches(glob, filtered)
		if len(filtered) == 0 {
			return nil
		}
	}

	return filtered
}
