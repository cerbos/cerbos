// Copyright 2021-2025 Zenauth Ltd.
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

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	// Register the http and https loaders.
	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/cache"
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
	managerLoader
	ValidateCheckInput(context.Context, *policyv1.Schemas, *enginev1.CheckInput) (*ValidationResult, error)
	ValidatePlanResourcesInput(context.Context, *policyv1.Schemas, *enginev1.PlanResourcesInput) (*ValidationResult, error)
}

type managerLoader interface {
	LoadSchema(context.Context, string) (*jsonschema.Schema, error)
}

type Loader interface {
	LoadSchema(context.Context, string) (io.ReadCloser, error)
}

type Resolver func(context.Context, string) (io.ReadCloser, error)

func NewNopManager() NopManager {
	return NopManager{}
}

type NopManager struct{}

func (NopManager) ValidateCheckInput(_ context.Context, _ *policyv1.Schemas, _ *enginev1.CheckInput) (*ValidationResult, error) {
	return alwaysValidResult, nil
}

func (NopManager) ValidatePlanResourcesInput(_ context.Context, _ *policyv1.Schemas, _ *enginev1.PlanResourcesInput) (*ValidationResult, error) {
	return alwaysValidResult, nil
}

func (NopManager) LoadSchema(_ context.Context, _ string) (*jsonschema.Schema, error) {
	return nil, nil
}

func NewStatic(schemas map[uint64]*policyv1.Schemas, rawSchemas map[string]*runtimev1.RuleTable_JSONSchema) (*StaticManager, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	if conf.Enforcement == EnforcementNone {
		return &StaticManager{}, nil
	}

	sm := &StaticManager{
		conf: conf,
		log:  zap.L().Named("schema"),
	}
	sm.loader = sm

	comp, err := PreCompileSchemas(schemas, rawSchemas)
	if err != nil {
		return nil, err
	}

	sm.CompiledSchemas = comp

	return sm, nil
}

type StaticManager struct {
	conf            *Conf
	log             *zap.Logger
	CompiledSchemas map[string]*jsonschema.Schema
	loader          managerLoader
}

func PreCompileSchemas(schemas map[uint64]*policyv1.Schemas, rawSchemas map[string]*runtimev1.RuleTable_JSONSchema) (map[string]*jsonschema.Schema, error) {
	res := make(map[string]*jsonschema.Schema)

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true

	for ref, raw := range rawSchemas {
		if err := compiler.AddResource(ref, strings.NewReader(raw.GetContent())); err != nil {
			return nil, fmt.Errorf("failed to add schema %s: %w", ref, err)
		}
	}

	for _, schema := range schemas {
		for _, r := range []string{schema.GetPrincipalSchema().GetRef(), schema.GetResourceSchema().GetRef()} {
			if r == "" {
				continue
			}

			if _, ok := res[r]; !ok {
				comp, err := compiler.Compile(r)
				if err != nil {
					return nil, fmt.Errorf("failed to compile schema %s: %w", r, err)
				}

				res[r] = comp
			}
		}
	}

	return res, nil
}

func (m *StaticManager) LoadSchema(ctx context.Context, url string) (*jsonschema.Schema, error) {
	schema, ok := m.CompiledSchemas[url]
	if !ok {
		return nil, fmt.Errorf("schema %q not found", url)
	}
	return schema, nil
}

func (m *StaticManager) ValidateCheckInput(ctx context.Context, schemas *policyv1.Schemas, input *enginev1.CheckInput) (*ValidationResult, error) {
	return m.validate(ctx, schemas, input.Principal.Attr, input.Resource.Attr, input.Actions, nil)
}

func (m *StaticManager) ValidatePlanResourcesInput(ctx context.Context, schemas *policyv1.Schemas, input *enginev1.PlanResourcesInput) (*ValidationResult, error) {
	return m.validate(ctx, schemas, input.Principal.Attr, input.Resource.Attr, input.Actions, func(err *jsonschema.ValidationError) bool {
		// resource attributes are optional for query planning, so ignore errors from required properties
		return !strings.HasSuffix(err.KeywordLocation, "/required")
	})
}

func (m *StaticManager) validate(ctx context.Context, schemas *policyv1.Schemas, principalAttr, resourceAttr map[string]*structpb.Value, actions []string, resourceErrorFilter validationErrorFilter) (*ValidationResult, error) {
	result := &ValidationResult{Reject: m.conf.Enforcement == EnforcementReject}
	if schemas == nil {
		return result, nil
	}

	ctx, span := tracing.StartSpan(ctx, "schema.Validate")
	defer span.End()

	if err := m.validateAttr(ctx, ErrSourcePrincipal, schemas.PrincipalSchema, principalAttr, actions, nil); err != nil {
		var principalErrs ValidationErrorList
		if ok := errors.As(err, &principalErrs); !ok {
			return result, fmt.Errorf("failed to validate the principal: %w", err)
		}
		result.add(principalErrs...)
	}

	if err := m.validateAttr(ctx, ErrSourceResource, schemas.ResourceSchema, resourceAttr, actions, resourceErrorFilter); err != nil {
		var resourceErrs ValidationErrorList
		if ok := errors.As(err, &resourceErrs); !ok {
			return result, fmt.Errorf("failed to validate the resource: %w", err)
		}
		result.add(resourceErrs...)
	}

	if len(result.Errors) > 0 {
		logging.FromContext(ctx).Warn("Validation failed", zap.Strings("errors", result.Errors.ErrorMessages()))
	}

	return result, nil
}

func (m *StaticManager) validateAttr(ctx context.Context, src ErrSource, schemaRef *policyv1.Schemas_Schema, attr map[string]*structpb.Value, actions []string, errorFilter validationErrorFilter) error {
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

	schema, err := m.loader.LoadSchema(ctx, schemaRef.Ref)
	if err != nil {
		m.log.Warn("Failed to load schema", zap.String("schema", schemaRef.Ref), zap.Error(err))
		return newSchemaLoadErr(src, schemaRef.Ref)
	}

	attrJSON, err := attrToJSONObject(src, attr)
	if err != nil {
		return err
	}

	if err := schema.Validate(attrJSON); err != nil {
		var validationErr *jsonschema.ValidationError
		if ok := errors.As(err, &validationErr); !ok {
			return fmt.Errorf("unable to validate %s: %w", src, err)
		}

		return newValidationErrorList(validationErr, src, errorFilter)
	}

	return nil
}

func attrToJSONObject(src ErrSource, attr map[string]*structpb.Value) (any, error) {
	if attr == nil {
		return map[string]any{}, nil
	}

	jsonBytes, err := protojson.Marshal(&privatev1.AttrWrapper{Attr: attr})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s: %w", src, err)
	}

	return gjson.GetBytes(jsonBytes, attrPath).Value(), nil
}

type manager struct {
	StaticManager
	cache    *cache.Cache[string, *cacheEntry]
	resolver Resolver
}

func New(ctx context.Context, loader Loader) (Manager, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewFromConf(ctx, loader, conf), nil
}

func NewFromConf(_ context.Context, loader Loader, conf *Conf) Manager {
	if conf.Enforcement == EnforcementNone {
		return NopManager{}
	}

	mgr := &manager{
		StaticManager: StaticManager{
			conf: conf,
			log:  zap.L().Named("schema"),
		},
		cache:    cache.New[string, *cacheEntry]("schema", conf.CacheSize),
		resolver: defaultResolver(loader),
	}
	mgr.loader = mgr

	if s, ok := loader.(storage.Subscribable); ok {
		s.Subscribe(mgr)
	}

	return mgr
}

func NewEphemeral(resolver Resolver) Manager {
	mgr := &manager{
		StaticManager: StaticManager{
			conf: NewConf(EnforcementReject),
			log:  zap.L().Named("schema"),
		},
		cache:    cache.New[string, *cacheEntry]("schema", defaultCacheSize),
		resolver: resolver,
	}
	mgr.loader = mgr

	return mgr
}

func defaultResolver(loader Loader) Resolver {
	return func(ctx context.Context, path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		if u.Scheme == "" || u.Scheme == URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")
			return loader.LoadSchema(ctx, relativePath)
		}

		schemaLoader, ok := jsonschema.Loaders[u.Scheme]
		if !ok {
			return nil, jsonschema.LoaderNotFoundError(path)
		}
		return schemaLoader(path)
	}
}

func (m *manager) LoadSchema(ctx context.Context, url string) (*jsonschema.Schema, error) {
	entry, ok := m.cache.Get(url)
	if ok {
		return entry.schema, entry.err
	}

	e := &cacheEntry{}
	e.schema, e.err = m.loadSchemaFromStore(ctx, url)

	if e.err != nil && errors.Is(e.err, fs.ErrNotExist) {
		e.err = fmt.Errorf("schema %q does not exist in the store", url)
	}

	m.cache.Set(url, e)
	return e.schema, e.err
}

func (m *manager) loadSchemaFromStore(ctx context.Context, schemaURL string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = func(path string) (io.ReadCloser, error) {
		return m.resolver(ctx, path)
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
		case storage.EventReload:
			m.cache.Purge()
			m.log.Debug("Handled store reload event")
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
