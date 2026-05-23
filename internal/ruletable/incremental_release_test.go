// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
)

// TestIncrementalAddReleasesCheckedExprs verifies that a policy added through the
// incremental path (processPolicyEvent -> addPolicy, not a full reload) has its retained
// CheckedExpr trees released, and that it still evaluates correctly by recompiling from
// Expr.Original on demand.
func TestIncrementalAddReleasesCheckedExprs(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(t.Context())
	defer cancelFunc()

	memFsys := afero.NewMemMapFs()
	fsys := afero.NewIOFS(memFsys)

	idx, err := index.Build(ctx, fsys)
	require.NoError(t, err)

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	subMgr := storage.NewSubscriptionManager(ctx)
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementNone))

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(t, err)

	// Start from an empty rule table so the policy below can only be released by the
	// incremental addPolicy path (a full reload would release it via init instead).
	ruleTable, err := ruletable.NewRuleTable(ruletable.NewProtoRuletable())
	require.NoError(t, err)

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, compiler, schemaMgr)
	require.NoError(t, err)

	subMgr.Subscribe(ruletableMgr)

	// Policy with a CEL condition, so it carries CheckedExpr trees that must be released.
	p := &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource: "album",
				Version:  "default",
				Rules: []*policyv1.ResourceRule{
					{
						Actions: []string{"view"},
						Roles:   []string{"user"},
						Effect:  effectv1.Effect_EFFECT_ALLOW,
						Condition: &policyv1.Condition{
							Condition: &policyv1.Condition_Match{
								Match: &policyv1.Match{
									Op: &policyv1.Match_Expr{Expr: "request.resource.attr.public == true"},
								},
							},
						},
					},
				},
			},
		},
	}

	addOrUpdatePolicy(t, "resource_policies/album.yaml", p, memFsys, idx, subMgr)

	conf := &evaluator.Conf{}
	conf.SetDefaults()
	evalParams := evaluator.EvalParams{
		DefaultPolicyVersion: conf.DefaultPolicyVersion,
		DefaultScope:         conf.DefaultScope,
		NowFunc:              conditions.Now(),
	}
	tctx := tracer.Start(nil)

	checkView := func(public bool) *enginev1.CheckInput {
		return &enginev1.CheckInput{
			RequestId: "1",
			Resource: &enginev1.Resource{
				Kind: "album",
				Id:   "1",
				Attr: map[string]*structpb.Value{"public": structpb.NewBoolValue(public)},
			},
			Principal: &enginev1.Principal{Id: "sam", Roles: []string{"user"}},
			Actions:   []string{"view"},
		}
	}

	// The condition must evaluate to ALLOW for a public album, proving the incrementally
	// added policy is functional via recompile-from-Original.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		output, _, err := ruletableMgr.Check(ctx, tctx, evalParams, checkView(true))
		require.NoError(c, err)
		require.Contains(c, output.Actions, "view")
		require.Equal(c, effectv1.Effect_EFFECT_ALLOW, output.Actions["view"].GetEffect())
	}, 2*time.Second, 50*time.Millisecond)

	// A non-public album must NOT be allowed, proving the condition is genuinely evaluated
	// (not short-circuited to a constant) by the recompiled program.
	output, _, err := ruletableMgr.Check(ctx, tctx, evalParams, checkView(false))
	require.NoError(t, err)
	require.NotEqual(t, effectv1.Effect_EFFECT_ALLOW, output.Actions["view"].GetEffect())

	// Every CheckedExpr retained in the rule table must have been released by addPolicy.
	asserted := 0
	assertReleased := func(e *runtimev1.Expr) {
		asserted++
		require.NotEmpty(t, e.Original, "released expr must keep its source for recompilation")
		require.Nil(t, e.GetChecked(), "incrementally added expr %q retained its CheckedExpr", e.Original)
	}
	for _, b := range ruletableMgr.GetAllRows() {
		core := b.Core
		if core.Condition != nil {
			conditions.WalkExprs(core.Condition, assertReleased)
		}
		if core.DerivedRoleCondition != nil {
			conditions.WalkExprs(core.DerivedRoleCondition, assertReleased)
		}
		if core.EmitOutput != nil {
			conditions.WalkExprs(core.EmitOutput, assertReleased)
		}
		if core.Params != nil {
			for _, v := range core.Params.Variables {
				conditions.WalkExprs(v, assertReleased)
			}
		}
		if core.DerivedRoleParams != nil {
			for _, v := range core.DerivedRoleParams.Variables {
				conditions.WalkExprs(v, assertReleased)
			}
		}
	}
	require.Positive(t, asserted, "expected at least one CheckedExpr to assert on")
}
