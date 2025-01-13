// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package plan

import (
	"context"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	internalengine "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/private/compile"
	"github.com/cerbos/cerbos/private/engine"
)

func Resources(ctx context.Context, conf *engine.Conf, idx compile.Index, input *enginev1.PlanResourcesInput) (*enginev1.PlanResourcesOutput, error) {
	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
	compiler := internalcompile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
	eng := internalengine.NewEphemeral(conf, compiler, schemaMgr)
	return eng.PlanResources(ctx, input)
}
