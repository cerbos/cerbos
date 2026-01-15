// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/private/compile"
)

func Compile(ctx context.Context, fsys fs.FS, attrs ...compile.SourceAttribute) (*runtimev1.RuleTable, error) {
	idx, err := compile.BuildIndex(ctx, fsys, attrs...)
	if err != nil {
		return nil, err
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})

	mgr, err := internalcompile.NewManager(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create compile manager: %w", err)
	}

	rt := ruletable.NewProtoRuletable()

	if err := ruletable.LoadPolicies(ctx, rt, mgr); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	if err := ruletable.LoadSchemas(ctx, rt, idx); err != nil {
		return nil, fmt.Errorf("failed to load schemas: %w", err)
	}

	conditions.WalkExprs(rt, conditions.MakeExprBackwardsCompatible)

	return rt, nil
}
