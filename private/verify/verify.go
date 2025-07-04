// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"go.uber.org/zap"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	internalengine "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/cerbos/cerbos/private/compile"
	"github.com/cerbos/cerbos/private/engine"
)

// Files runs tests using the policy files in the given file system.
func Files(ctx context.Context, fsys fs.FS, idx compile.Index) (*policyv1.TestResults, error) {
	if idx == nil {
		var err error
		idx, err = index.Build(ctx, fsys, index.WithBuildFailureLogLevel(zap.DebugLevel))
		if err != nil {
			idxErrs := new(index.BuildError)
			if errors.As(err, &idxErrs) {
				return nil, &compile.Errors{
					Errors: &runtimev1.Errors{
						Kind: &runtimev1.Errors_IndexBuildErrors{IndexBuildErrors: idxErrs.IndexBuildErrors},
					},
				}
			}

			return nil, fmt.Errorf("failed to build index: %w", err)
		}
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
	compiler, err := internalcompile.NewManager(ctx, store, schemaMgr)
	if err != nil {
		return nil, err
	}

	rt := ruletable.NewProtoRuletable()

	if err := ruletable.LoadFromPolicyLoader(ctx, rt, compiler); err != nil {
		return nil, err
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, compiler, schemaMgr)
	if err != nil {
		return nil, err
	}

	eng := internalengine.NewEphemeral(nil, ruletableMgr, schemaMgr)

	results, err := verify.Verify(ctx, fsys, eng, verify.Config{Trace: true})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

// Bundle runs tests using the given policy bundle.
func Bundle(ctx context.Context, params engine.BundleParams, testsDir string) (*policyv1.TestResults, error) {
	eng, err := engine.FromBundle(ctx, params)
	if err != nil {
		return nil, err
	}

	results, err := verify.Verify(ctx, os.DirFS(testsDir), eng, verify.Config{Trace: true})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type CheckOptions interface {
	Globals() map[string]any
	NowFunc() func() time.Time
	DefaultPolicyVersion() string
	LenientScopeSearch() bool
}

type Checker interface {
	Check(ctx context.Context, inputs []*enginev1.CheckInput, opts CheckOptions) ([]*enginev1.CheckOutput, error)
}

type Opt func(config *verify.Config)

func WithExcludedResourcePolicyFQNs(fqns ...string) Opt {
	return func(config *verify.Config) {
		if config.ExcludedResourcePolicyFQNs == nil {
			config.ExcludedResourcePolicyFQNs = make(map[string]struct{}, len(fqns))
		}

		for _, fqn := range fqns {
			config.ExcludedResourcePolicyFQNs[fqn] = struct{}{}
		}
	}
}

func WithExcludedPrincipalPolicyFQNs(fqns ...string) Opt {
	return func(config *verify.Config) {
		if config.ExcludedPrincipalPolicyFQNs == nil {
			config.ExcludedPrincipalPolicyFQNs = make(map[string]struct{}, len(fqns))
		}

		for _, fqn := range fqns {
			config.ExcludedPrincipalPolicyFQNs[fqn] = struct{}{}
		}
	}
}

func WithCustomChecker(ctx context.Context, fsys fs.FS, eng Checker, opts ...Opt) (*policyv1.TestResults, error) {
	config := new(verify.Config)
	for _, opt := range opts {
		opt(config)
	}
	results, err := verify.Verify(ctx, fsys, checkFunc(eng.Check), *config)
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type checkFunc func(context.Context, []*enginev1.CheckInput, CheckOptions) ([]*enginev1.CheckOutput, error)

func (f checkFunc) Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error) {
	return f(ctx, inputs, internalengine.ApplyCheckOptions(opts...))
}
