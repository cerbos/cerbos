// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
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

// TestMarshaledIndexCheck runs the full engine test suite against an evaluator
// whose index has been round-tripped through Marshal/Unmarshal.
func TestMarshaledIndexCheck(t *testing.T) {
	rt := buildFullRuleTable(t)

	// Round-trip the index through marshal/unmarshal.
	data, err := rt.idx.Marshal()
	require.NoError(t, err)

	restored, err := index.Unmarshal(data)
	require.NoError(t, err)

	rt.idx = restored

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	evalConf.Globals = map[string]any{"environment": "test"}

	eval, err := rt.Evaluator(evalConf, schema.NewConf(schema.EnforcementNone))
	require.NoError(t, err)

	testCases := test.LoadTestCases(t, "engine")
	testCases = append(testCases, test.LoadTestCases(t, "engine_strict_scope_search")...)

	for _, tcase := range testCases {
		t.Run(tcase.Name, func(t *testing.T) {
			tc := &privatev1.EngineTestCase{}
			require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(tcase.Input), tc))

			traceCollector := tracer.NewCollector()
			haveOutputs, err := eval.Check(t.Context(), tc.Inputs, evaluator.WithTraceSink(traceCollector))

			if tc.WantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			for i, have := range haveOutputs {
				slices.SortStableFunc(have.Outputs, func(a, b *enginev1.OutputEntry) int {
					if a.Src < b.Src {
						return -1
					} else if a.Src > b.Src {
						return 1
					}
					return 0
				})

				require.Empty(t, cmp.Diff(tc.WantOutputs[i],
					have,
					protocmp.Transform(),
					protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
				))
			}
		})
	}
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
