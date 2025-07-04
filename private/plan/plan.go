// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package plan

import (
	"context"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	internalengine "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/private/compile"
	"github.com/cerbos/cerbos/private/engine"
)

func Resources(ctx context.Context, conf *engine.Conf, idx compile.Index, input *enginev1.PlanResourcesInput) (*enginev1.PlanResourcesOutput, error) {
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

	eng := internalengine.NewEphemeral(conf, ruletableMgr, schemaMgr)
	return eng.Plan(ctx, input)
}
