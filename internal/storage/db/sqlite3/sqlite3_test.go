// Copyright 2021 Zenauth Ltd.

package sqlite3_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/db"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/test"
)

func TestSQLite(t *testing.T) {
	store, err := sqlite3.New(context.Background(), &sqlite3.Conf{DSN: ":memory:?_fk=true"})
	require.NoError(t, err)

	rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
	pp := policy.Wrap(test.GenPrincipalPolicy(test.NoMod()))
	dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))
	rpx := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("x", "x")))
	drx := policy.Wrap(test.GenDerivedRoles(test.PrefixAndSuffix("x", "x")))

	t.Run("addAndRetrieve", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()

		require.NoError(t, store.AddOrUpdate(ctx, rp, pp, dr, rpx, drx))

		t.Run("unit_with_deps", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rp.ID)
			require.NoError(t, err)
			require.Len(t, have, 1)
			require.Contains(t, have, rp.ID)

			haveRec := have[rp.ID]
			require.Equal(t, rp.ID, haveRec.ModID)
			require.Len(t, haveRec.Definitions, 2)

			require.Contains(t, haveRec.Definitions, rp.ID)
			require.Equal(t, rp.FQN, haveRec.Definitions[rp.ID].Fqn)

			require.Contains(t, haveRec.Definitions, dr.ID)
			require.Equal(t, dr.FQN, haveRec.Definitions[dr.ID].Fqn)
		})

		t.Run("unit_without_deps", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, pp.ID)
			require.NoError(t, err)
			require.Len(t, have, 1)
			require.Contains(t, have, pp.ID)

			haveRec := have[pp.ID]
			require.Equal(t, pp.ID, haveRec.ModID)
			require.Len(t, haveRec.Definitions, 1)

			require.Contains(t, haveRec.Definitions, pp.ID)
			require.Equal(t, pp.FQN, haveRec.Definitions[pp.ID].Fqn)
		})

		t.Run("multiple_units", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rp.ID, pp.ID)
			require.NoError(t, err)
			require.Len(t, have, 2)
			require.Contains(t, have, rp.ID)
			require.Contains(t, have, pp.ID)

			haveRP := have[rp.ID]
			require.Equal(t, rp.ID, haveRP.ModID)
			require.Len(t, haveRP.Definitions, 2)

			require.Contains(t, haveRP.Definitions, rp.ID)
			require.Equal(t, rp.FQN, haveRP.Definitions[rp.ID].Fqn)

			require.Contains(t, haveRP.Definitions, dr.ID)
			require.Equal(t, dr.FQN, haveRP.Definitions[dr.ID].Fqn)

			havePP := have[pp.ID]
			require.Equal(t, pp.ID, havePP.ModID)
			require.Len(t, havePP.Definitions, 1)

			require.Contains(t, havePP.Definitions, pp.ID)
			require.Equal(t, pp.FQN, havePP.Definitions[pp.ID].Fqn)
		})

		t.Run("non_existent_record", func(t *testing.T) {
			p := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("y", "y")))
			_, err := store.GetCompilationUnits(ctx, p.ID)
			require.ErrorIs(t, err, db.ErrNoResults)
		})
	})
}
