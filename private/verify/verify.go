// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/cerbos/cerbos/private/compile"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"go.uber.org/zap"
)

func Files(ctx context.Context, fsys fs.FS) (*policyv1.TestResults, error) {
	idx, err := index.Build(ctx, fsys, index.WithBuildFailureLogLevel(zap.DebugLevel))
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

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
	compiler := internalcompile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
	eng, err := engine.NewEphemeral(compiler, schemaMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	results, err := verify.Verify(ctx, fsys, eng, verify.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type simpleChecker interface {
	Check(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error)
}

func WithCustomChecker(ctx context.Context, fsys fs.FS, eng simpleChecker) (*policyv1.TestResults, error) {
	results, err := verify.Verify(ctx, fsys, inputCheckFunc(eng.Check), verify.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to run tests: %w", err)
	}

	return results, nil
}

type inputCheckFunc func(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error)

func (f inputCheckFunc) Check(ctx context.Context, inputs []*enginev1.CheckInput, _opts ...engine.CheckOpt) ([]*enginev1.CheckOutput, error) {
	return f(ctx, inputs)
}
