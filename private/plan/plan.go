// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package plan

import (
	"context"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/private/compile"
)

func Resources(ctx context.Context, idx compile.Index, input *enginev1.PlanResourcesInput) (*enginev1.PlanResourcesOutput, error) {
	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
	compiler := internalcompile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
	eng, err := engine.NewEphemeral(compiler, schemaMgr)
	if err != nil {
		return nil, err
	}

	return eng.PlanResources(ctx, input)
}
