// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"

	"github.com/cerbos/cloud-api/bundle"

	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/hub"
)

type (
	Conf         = evaluator.Conf
	BundleParams = hub.LocalParams
	Engine       = engine.Engine
)

const (
	BundleVersion1 = bundle.Version1
	BundleVersion2 = bundle.Version2
)

func FromBundle(ctx context.Context, conf *evaluator.Conf, params BundleParams) (*Engine, error) {
	bundleSrc, err := hub.NewLocalSource(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create local bundle source from %q: %w", params.BundlePath, err)
	}

	schemaMgr := schema.NewFromConf(ctx, bundleSrc, schema.NewConf(schema.EnforcementReject))

	ruleTable, err := ruletable.NewRuleTableFromLoader(ctx, bundleSrc, conf.DefaultPolicyVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table from loader: %w", err)
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, bundleSrc, schemaMgr, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create ruletable manager: %w", err)
	}

	return engine.NewEphemeral(nil, ruletableMgr, schemaMgr), nil
}
