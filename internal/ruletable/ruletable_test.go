// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"bytes"
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
)

func TestRuleTableManager(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(t.Context())
	defer cancelFunc()

	memFsys := afero.NewMemMapFs()
	fsys := afero.NewIOFS(memFsys)

	idx, err := index.Build(ctx, fsys)
	require.NoError(t, err)

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	store.SubscriptionManager = storage.NewSubscriptionManager(ctx)

	schemaConf := schema.NewConf(schema.EnforcementNone)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(t, err)

	ruletableMgr, err := NewRuleTableManager(NewProtoRuletable(), compiler, store, schemaMgr)
	require.NoError(t, err)

	store.Subscribe(ruletableMgr)

	// add simple, valid policy and confirm an ALLOW request
	resourceFile := "resource_policies/rock.yaml"
	p := &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource: "rock",
				Version:  "default",
				Rules: []*policyv1.ResourceRule{
					{
						Actions: []string{"throw"},
						Roles:   []string{"user"},
						Effect:  effectv1.Effect_EFFECT_ALLOW,
					},
				},
			},
		},
	}

	addOrUpdatePolicy(t, resourceFile, p, memFsys, idx, store)

	action := "throw"
	input := &enginev1.CheckInput{
		RequestId: "1",
		Resource: &enginev1.Resource{
			Kind: "rock",
			Id:   "1",
		},
		Principal: &enginev1.Principal{
			Id:    "sam",
			Roles: []string{"user"},
		},
		Actions: []string{action},
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		outputs, err := ruletableMgr.RuleTable.Check(ctx, []*enginev1.CheckInput{input})
		require.NoError(t, err)

		require.Len(t, outputs, 1)
		require.Contains(t, outputs[0].Actions, action)
		require.Equal(t, outputs[0].Actions[action].GetEffect(), effectv1.Effect_EFFECT_ALLOW)
	}, 1*time.Second, 50*time.Millisecond)

	t.Run("maintain_valid_state_on_missing_derived_role", func(t *testing.T) {
		// Update policy so that it references a nonexistent derived role
		p := &policyv1.Policy{
			ApiVersion: "api.cerbos.dev/v1",
			PolicyType: &policyv1.Policy_ResourcePolicy{
				ResourcePolicy: &policyv1.ResourcePolicy{
					Resource:           "rock",
					Version:            "default",
					ImportDerivedRoles: []string{"special_roles"},
					Rules: []*policyv1.ResourceRule{
						{
							Actions:      []string{action},
							DerivedRoles: []string{"special_user"},
							Effect:       effectv1.Effect_EFFECT_ALLOW,
						},
					},
				},
			},
		}

		addOrUpdatePolicy(t, resourceFile, p, memFsys, idx, store)

		// Check request should still return ALLOW
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			outputs, err := ruletableMgr.RuleTable.Check(ctx, []*enginev1.CheckInput{input})
			require.NoError(t, err)

			require.Len(t, outputs, 1)
			require.Contains(t, outputs[0].Actions, action)
			require.Equal(t, outputs[0].Actions[action].GetEffect(), effectv1.Effect_EFFECT_ALLOW)
		}, 1*time.Second, 50*time.Millisecond)
	})

	t.Run("adding_missing_derived_role_re_enables_updates", func(t *testing.T) {
		derivedRoleFile := "derived_roles/special_roles.yaml"
		p := &policyv1.Policy{
			ApiVersion: "api.cerbos.dev/v1",
			PolicyType: &policyv1.Policy_DerivedRoles{
				DerivedRoles: &policyv1.DerivedRoles{
					Name: "special_roles",
					Definitions: []*policyv1.RoleDef{
						{
							Name:        "special_user",
							ParentRoles: []string{"user"},
							Condition: &policyv1.Condition{
								Condition: &policyv1.Condition_Match{
									Match: &policyv1.Match{
										Op: &policyv1.Match_Expr{
											Expr: "true == false",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		addOrUpdatePolicy(t, derivedRoleFile, p, memFsys, idx, store)

		// Check request should now return DENY
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			outputs, err := ruletableMgr.RuleTable.Check(ctx, []*enginev1.CheckInput{input})
			require.NoError(t, err)

			require.Len(t, outputs, 1)
			require.Contains(t, outputs[0].Actions, action)
			require.Equal(t, outputs[0].Actions[action].GetEffect(), effectv1.Effect_EFFECT_DENY)
		}, 1*time.Second, 50*time.Millisecond)
	})

	t.Run("updating_derived_role_affects_rule_table", func(t *testing.T) {
		derivedRoleFile := "derived_roles/special_roles.yaml"
		p := &policyv1.Policy{
			ApiVersion: "api.cerbos.dev/v1",
			PolicyType: &policyv1.Policy_DerivedRoles{
				DerivedRoles: &policyv1.DerivedRoles{
					Name: "special_roles",
					Definitions: []*policyv1.RoleDef{
						{
							Name:        "special_user",
							ParentRoles: []string{"user"},
							Condition: &policyv1.Condition{
								Condition: &policyv1.Condition_Match{
									Match: &policyv1.Match{
										Op: &policyv1.Match_Expr{
											Expr: "true == true", // <-- change
										},
									},
								},
							},
						},
					},
				},
			},
		}

		addOrUpdatePolicy(t, derivedRoleFile, p, memFsys, idx, store)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			outputs, err := ruletableMgr.RuleTable.Check(ctx, []*enginev1.CheckInput{input})
			require.NoError(t, err)

			require.Len(t, outputs, 1)
			require.Contains(t, outputs[0].Actions, action)
			require.Equal(t, outputs[0].Actions[action].GetEffect(), effectv1.Effect_EFFECT_ALLOW)
		}, 1*time.Second, 50*time.Millisecond)
	})
}

func addOrUpdatePolicy(t *testing.T, f string, p *policyv1.Policy, memFsys afero.Fs, idx index.Index, store *disk.Store) {
	t.Helper()

	var s bytes.Buffer
	require.NoError(t, policy.WritePolicy(&s, p))

	require.NoError(t, afero.WriteFile(memFsys, f, s.Bytes(), fs.ModeAppend))

	evt, err := idx.AddOrUpdate(index.Entry{File: f, Policy: policy.Wrap(p)})
	require.NoError(t, err)

	store.NotifySubscribers(evt)
}
