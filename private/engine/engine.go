// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cloud-api/bundle"
)

type (
	Conf         = engine.Conf
	BundleParams = hub.LocalParams
	Engine       = engine.Engine
)

const (
	BundleVersion1 = bundle.Version1
	BundleVersion2 = bundle.Version2
)

func FromBundle(ctx context.Context, params BundleParams) (*Engine, error) {
	bundleSrc, err := hub.NewLocalSource(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create local bundle source from %q: %w", params.BundlePath, err)
	}

	schemaMgr := schema.NewFromConf(ctx, bundleSrc, schema.NewConf(schema.EnforcementReject))

	rt := &runtimev1.RuleTable{}
	rps, err := bundleSrc.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	for _, p := range rps {
		ruletable.AddPolicy(rt, p)
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, schemaMgr)
	if err != nil {
		return nil, err
	}

	return engine.NewEphemeral(nil, ruletableMgr, schemaMgr), nil
}
