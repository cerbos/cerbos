// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"cmp"
	"os"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/private/compile"
	ruletablecompile "github.com/cerbos/cerbos/private/ruletable/compile"
)

func TestCompile(t *testing.T) {
	fsys := os.DirFS(test.PathToDir(t, "store"))

	ctx := t.Context()

	rt, err := ruletablecompile.Compile(ctx, fsys)
	require.NoError(t, err)
	require.NotEmpty(t, rt.GetRules())

	idx, err := compile.BuildIndex(ctx, fsys)
	require.NoError(t, err)

	mgr, err := internalcompile.NewManager(ctx, disk.NewFromIndexWithConf(idx, &disk.Conf{}))
	require.NoError(t, err)

	want := ruletable.NewProtoRuletable()
	require.NoError(t, ruletable.LoadPolicies(ctx, want, mgr))
	require.NoError(t, ruletable.LoadSchemas(ctx, want, idx))

	// The streaming path releases CheckedExprs
	conditions.WalkExprs(want, func(e *runtimev1.Expr) { e.Checked = nil })
	sortRules(want)
	sortRules(rt)

	require.Empty(t, gocmp.Diff(want, rt, protocmp.Transform()))
}

func sortRules(rt *runtimev1.RuleTable) {
	slices.SortFunc(rt.Rules, func(a, b *runtimev1.RuleTable_RuleRow) int {
		return cmp.Compare(util.HashPB(a, nil), util.HashPB(b, nil))
	})
}
