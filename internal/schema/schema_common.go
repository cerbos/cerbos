// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
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

func NewStatic(schemas map[uint64]*policyv1.Schemas, rawSchemas map[string]*runtimev1.RuleTable_JSONSchema) (Manager, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewStaticFromConf(conf, schemas, rawSchemas)
}

func NewStaticFromConf(conf *Conf, schemas map[uint64]*policyv1.Schemas, rawSchemas map[string]*runtimev1.RuleTable_JSONSchema) (Manager, error) {
	if conf.Enforcement == EnforcementNone {
		return NopManager{}, nil
	}

	sm := &StaticManager{
		conf: conf,
		log:  logging.NewLogger("schema"),
	}
	sm.loader = sm

	if err := sm.preCompileSchemas(schemas, rawSchemas); err != nil {
		return nil, err
	}

	return sm, nil
}

type StaticManager struct {
	conf            *Conf
	log             *logging.Logger
	compiledSchemas map[string]*jsonschema.Schema
	loader          managerLoader
}

func (m *StaticManager) preCompileSchemas(schemas map[uint64]*policyv1.Schemas, rawSchemas map[string]*runtimev1.RuleTable_JSONSchema) error {
	m.compiledSchemas = make(map[string]*jsonschema.Schema)

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true

	for ref, raw := range rawSchemas {
		if err := compiler.AddResource(ref, bytes.NewReader(raw.GetContent())); err != nil {
			return fmt.Errorf("failed to add schema %s: %w", ref, err)
		}
	}

	for _, schema := range schemas {
		for _, r := range []string{schema.GetPrincipalSchema().GetRef(), schema.GetResourceSchema().GetRef()} {
			if r == "" {
				continue
			}

			if _, ok := m.compiledSchemas[r]; !ok {
				comp, err := compiler.Compile(r)
				if err != nil {
					return fmt.Errorf("failed to compile schema %s: %w", r, err)
				}

				m.compiledSchemas[r] = comp
			}
		}
	}

	return nil
}

func (m *StaticManager) LoadSchema(ctx context.Context, url string) (*jsonschema.Schema, error) {
	schema, ok := m.compiledSchemas[url]
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
		logging.FromContext(ctx).Warn("Validation failed", logging.Strings("errors", result.Errors.ErrorMessages()))
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
				logging.Strings("all_actions", actions),
				logging.Strings("actions_requiring_validation", toValidate))
		}
	}

	schema, err := m.loader.LoadSchema(ctx, schemaRef.Ref)
	if err != nil {
		m.log.Warn("Failed to load schema", logging.String("schema", schemaRef.Ref), logging.Error(err))
		return NewLoadErr(src, schemaRef.Ref, err)
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

func StaticResolver(loader Loader) Resolver {
	return func(ctx context.Context, path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		if u.Scheme == "" || u.Scheme == URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")
			return loader.LoadSchema(ctx, relativePath)
		}

		return nil, jsonschema.LoaderNotFoundError(path)
	}
}
