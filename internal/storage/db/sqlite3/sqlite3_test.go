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

func TestAddAndRetrieve(t *testing.T) {
	store, err := sqlite3.New(context.Background(), &sqlite3.Conf{DSN: ":memory:"})
	require.NoError(t, err)

	rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
	pp := policy.Wrap(test.GenPrincipalPolicy(test.NoMod()))
	dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFunc()

	require.NoError(t, store.AddOrUpdate(ctx, rp, pp, dr))

	unit, err := store.GetPolicyUnit(ctx, rp.ID)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(rp.Policy, unit.Policy, protocmp.Transform()))
	require.Len(t, unit.Dependencies, 1)
	require.Empty(t, cmp.Diff(dr.Policy, unit.Dependencies[0].Policy, protocmp.Transform()))
}
