// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/bundle"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/cerbos/cerbos/private/compile"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"go.uber.org/zap"
)

// Files runs tests using the policy files in the given file system.
func Files(ctx context.Context, fsys fs.FS, idx index.Index) (*policyv1.TestResults, error) {
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
	compiler := internalcompile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
	eng, err := engine.NewEphemeral(compiler, schemaMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	results, err := verify.Verify(ctx, fsys, eng, verify.Config{Trace: true})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type BundleParams struct {
	BundlePath string
	TestsDir   string
	WorkDir    string
}

// Bundle runs tests using the given policy bundle.
func Bundle(ctx context.Context, params BundleParams) (*policyv1.TestResults, error) {
	bundleSrc, err := bundle.NewLocalSource(bundle.LocalParams{
		BundlePath: params.BundlePath,
		TempDir:    params.WorkDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create local bundle source from %q: %w", params.BundlePath, err)
	}

	schemaMgr := schema.NewFromConf(ctx, bundleSrc, schema.NewConf(schema.EnforcementReject))
	eng, err := engine.NewEphemeral(bundleSrc, schemaMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	results, err := verify.Verify(ctx, os.DirFS(params.TestsDir), eng, verify.Config{Trace: true})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type simpleChecker interface {
	Check(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error)
}

func WithCustomChecker(ctx context.Context, fsys fs.FS, eng simpleChecker) (*policyv1.TestResults, error) {
	results, err := verify.Verify(ctx, fsys, checkFunc(eng.Check), verify.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type checkFunc func(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error)

func (f checkFunc) Check(ctx context.Context, inputs []*enginev1.CheckInput, _ ...engine.CheckOpt) ([]*enginev1.CheckOutput, error) {
	return f(ctx, inputs)
}
