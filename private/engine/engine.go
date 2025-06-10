// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"

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

	rt := ruletable.NewRuletable()

	if err := ruletable.LoadFromPolicyLoader(ctx, rt, bundleSrc); err != nil {
		return nil, err
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, bundleSrc, schemaMgr)
	if err != nil {
		return nil, err
	}

	return engine.NewEphemeral(nil, ruletableMgr, schemaMgr), nil
}
