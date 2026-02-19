// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRedisIndex(t *testing.T) {
	test.SkipIfGHActions(t)

	mr := miniredis.RunT(t)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace := "test"

	_, err := index.GetExistingRedis(ctx, client, namespace)
	require.ErrorIs(t, err, index.ErrCacheMiss)

	writerIdx := index.NewRedis(client, namespace, time.Minute, time.Second)
	writerImpl := index.NewImpl(writerIdx)

	testRow := &runtimev1.RuleTable_RuleRow{
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
		Resource:   "document",
		Role:       "user",
		ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:     effectv1.Effect_EFFECT_ALLOW,
		Scope:      "alpha",
		Version:    "default",
		Params: &runtimev1.RuleTable_RuleRow_Params{
			OrderedVariables: []*runtimev1.Variable{},
			Constants:        map[string]*structpb.Value{},
		},
	}

	require.NoError(t, writerImpl.IndexRules(ctx, []*runtimev1.RuleTable_RuleRow{testRow}))
	require.NoError(t, writerImpl.IndexParentRoles(ctx, map[string]*runtimev1.RuleTable_RoleParentRoles{
		"alpha": {
			RoleParentRoles: map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles{
				"manager": {
					Roles: []string{"user"},
				},
			},
		},
	}))

	readerIdx, err := index.GetExistingRedis(ctx, client, namespace)
	require.NoError(t, err)
	require.NotNil(t, readerIdx)

	readerImpl := index.NewImpl(readerIdx)

	rows, err := readerImpl.GetRows(ctx, []string{"default"}, []string{"document"}, []string{"alpha"}, []string{"user"}, []string{"view"}, false)
	require.NoError(t, err)

	require.Len(t, rows, 1)

	roles, err := readerImpl.AddParentRoles(ctx, []string{"alpha"}, []string{"manager"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"manager", "user"}, roles)

	newRow := &runtimev1.RuleTable_RuleRow{
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
		Resource:   "document",
		ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:     effectv1.Effect_EFFECT_DENY,
		Scope:      "alpha",
		Version:    "default",
		Params: &runtimev1.RuleTable_RuleRow_Params{
			OrderedVariables: []*runtimev1.Variable{},
			Constants:        map[string]*structpb.Value{},
		},
	}

	require.ErrorIs(t, readerImpl.IndexRules(ctx, []*runtimev1.RuleTable_RuleRow{newRow}), index.ErrReadOnly)
	require.ErrorIs(t, readerImpl.IndexParentRoles(ctx, map[string]*runtimev1.RuleTable_RoleParentRoles{"alpha": {}}), index.ErrReadOnly)
}
