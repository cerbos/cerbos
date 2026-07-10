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
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
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

	sortRules(want)
	sortRules(rt)

	require.Empty(t, gocmp.Diff(want, rt, protocmp.Transform()))
}

func sortRules(rt *runtimev1.RuleTable) {
	slices.SortFunc(rt.Rules, func(a, b *runtimev1.RuleTable_RuleRow) int {
		return cmp.Compare(util.HashPB(a, nil), util.HashPB(b, nil))
	})
}
// TestStreamedWireCompatibility proves that a rule table serialized incrementally.
func TestStreamedWireCompatibility(t *testing.T) {
	const rulesFieldNumber = 1 // runtimev1.RuleTable.rules

	rt, err := ruletablecompile.Compile(t.Context(), os.DirFS(test.PathToDir(t, "store")))
	require.NoError(t, err)
	require.NotEmpty(t, rt.GetRules())
	rt.Manifest = &runtimev1.RuleTable_Manifest{BundleId: "WIRECHECK0000000"}

	conventional, err := rt.MarshalVT()
	require.NoError(t, err)

	var rowRecords []byte
	for _, row := range rt.Rules {
		rowBytes, err := row.MarshalVT()
		require.NoError(t, err)
		rowRecords = protowire.AppendTag(rowRecords, rulesFieldNumber, protowire.BytesType)
		rowRecords = protowire.AppendVarint(rowRecords, uint64(len(rowBytes)))
		rowRecords = append(rowRecords, rowBytes...)
	}

	rows := rt.Rules
	rt.Rules = nil
	remainder, err := rt.MarshalVT()
	require.NoError(t, err)
	rt.Rules = rows

	control := &runtimev1.RuleTable{}
	require.NoError(t, control.UnmarshalVT(conventional))

	streamed := map[string][]byte{
		"rowsFirst":      append(slices.Clone(rowRecords), remainder...),
		"remainderFirst": append(slices.Clone(remainder), rowRecords...),
	}
	for name, data := range streamed {
		t.Run(name, func(t *testing.T) {
			vt := &runtimev1.RuleTable{}
			require.NoError(t, vt.UnmarshalVT(data))
			require.Empty(t, gocmp.Diff(control, vt, protocmp.Transform()), "UnmarshalVT mismatch")

			std := &runtimev1.RuleTable{}
			require.NoError(t, proto.Unmarshal(data, std))
			require.Empty(t, gocmp.Diff(control, std, protocmp.Transform()), "proto.Unmarshal mismatch")
		})
	}
}
