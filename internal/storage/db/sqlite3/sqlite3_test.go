// Copyright 2021 Zenauth Ltd.

package sqlite3_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/test"
)

func TestSQLite(t *testing.T) {
	store, err := sqlite3.New(context.Background(), &sqlite3.Conf{DSN: ":memory:?_fk=true"})
	require.NoError(t, err)

	rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
	pp := policy.Wrap(test.GenPrincipalPolicy(test.NoMod()))
	dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

	t.Run("addAndRetrieve", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()

		require.NoError(t, store.AddOrUpdate(ctx, rp, pp, dr))

		unitWithDeps, err := store.GetPolicyUnit(ctx, rp.ID)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(rp.Policy, unitWithDeps.Policy, protocmp.Transform()))
		require.Len(t, unitWithDeps.Dependencies, 1)
		require.Empty(t, cmp.Diff(dr.Policy, unitWithDeps.Dependencies[0].Policy, protocmp.Transform()))

		unitWithoutDeps, err := store.GetPolicyUnit(ctx, pp.ID)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(pp.Policy, unitWithoutDeps.Policy, protocmp.Transform()))
		require.Len(t, unitWithoutDeps.Dependencies, 0)
	})
}
