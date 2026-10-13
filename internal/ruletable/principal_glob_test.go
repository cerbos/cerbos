// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
)

// Principal policy resource globs used to be matched against the sanitized resource kind.
// A deny rule that relied on that must keep denying.
func TestPrincipalPolicyDenyGlobOnSanitizedKind(t *testing.T) {
	testCases := []struct {
		name string
		kind string
		glob string
	}{
		{
			// Glob written against the sanitized form of the kind.
			name: "sanitized_form_glob",
			kind: "udm:module:users/x",
			glob: "udm_module_*",
		},
		{
			// A single "*" spanning a ":", which only matched because sanitizing removed the separator.
			name: "star_across_separator",
			kind: "hr:secret-doc",
			glob: "*secret*",
		},
	}

	const (
		action      = "view"
		principalID = "alice"
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourcePolicy := compilePolicy(t, &policyv1.Policy{
				ApiVersion: "api.cerbos.dev/v1",
				PolicyType: &policyv1.Policy_ResourcePolicy{
					ResourcePolicy: &policyv1.ResourcePolicy{
						Resource: tc.kind,
						Version:  "default",
						Rules: []*policyv1.ResourceRule{
							{
								Actions: []string{action},
								Roles:   []string{"user"},
								Effect:  effectv1.Effect_EFFECT_ALLOW,
							},
						},
					},
				},
			})

			principalPolicy := compilePolicy(t, &policyv1.Policy{
				ApiVersion: "api.cerbos.dev/v1",
				PolicyType: &policyv1.Policy_PrincipalPolicy{
					PrincipalPolicy: &policyv1.PrincipalPolicy{
						Principal: principalID,
						Version:   "default",
						Rules: []*policyv1.PrincipalRule{
							{
								Resource: tc.glob,
								Actions: []*policyv1.PrincipalRule_Action{
									{Action: action, Effect: effectv1.Effect_EFFECT_DENY},
								},
							},
						},
					},
				},
			})

			loader := staticLoader{sets: []*runtimev1.RunnablePolicySet{resourcePolicy, principalPolicy}}
			rt, err := ruletable.NewRuleTableFromLoader(t.Context(), loader)
			require.NoError(t, err)

			mgr, err := ruletable.NewRuleTableManager(rt, loader, schema.NewNopManager())
			require.NoError(t, err)

			conf := &evaluator.Conf{}
			conf.SetDefaults()
			params := evaluator.EvalParams{
				DefaultPolicyVersion: conf.DefaultPolicyVersion,
				DefaultScope:         conf.DefaultScope,
				NowFunc:              conditions.Now(),
			}
			principal := &enginev1.Principal{Id: principalID, Roles: []string{"user"}}

			t.Run("check", func(t *testing.T) {
				out, _, err := mgr.Check(t.Context(), tracer.Start(nil), params, &enginev1.CheckInput{
					RequestId: "1",
					Resource:  &enginev1.Resource{Kind: tc.kind, Id: "1"},
					Principal: principal,
					Actions:   []string{action},
				})
				require.NoError(t, err)
				require.Contains(t, out.Actions, action)
				require.Equal(t, effectv1.Effect_EFFECT_DENY, out.Actions[action].GetEffect())
				require.Equal(t, namer.PolicyKeyFromFQN(principalPolicy.Fqn), out.Actions[action].GetPolicy())
			})

			t.Run("plan", func(t *testing.T) {
				out, _, err := mgr.Plan(t.Context(), params, &enginev1.PlanResourcesInput{
					RequestId: "1",
					Actions:   []string{action},
					Principal: principal,
					Resource:  &enginev1.PlanResourcesInput_Resource{Kind: tc.kind},
				})
				require.NoError(t, err)
				require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, out.GetFilter().GetKind())
			})
		})
	}
}
