// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func buildFullRuleTable(tb testing.TB) *RuleTable {
	tb.Helper()

	ctx := tb.(interface{ Context() context.Context }).Context()

	dir := test.PathToDir(tb, "store")
	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	protoRT := NewProtoRuletable()

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(tb, err)

	require.NoError(tb, LoadPolicies(ctx, protoRT, compiler))
	require.NoError(tb, LoadSchemas(ctx, protoRT, store))

	rt, err := NewRuleTable(protoRT)
	require.NoError(tb, err)

	return rt
}

func BenchmarkMarshal(b *testing.B) {
	rt := buildFullRuleTable(b)
	b.ResetTimer()
	for b.Loop() {
		if _, err := rt.idx.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	rt := buildFullRuleTable(b)
	data, err := rt.idx.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := index.Unmarshal(data); err != nil {
			b.Fatal(err)
		}
	}
}
