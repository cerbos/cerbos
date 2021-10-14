// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

// trick compiler into not converting benchmarks into nops.
var dummy int

func TestCheck(t *testing.T) {
	eng, cancelFunc := mkEngine(t, false)
	defer cancelFunc()

	testCases := test.LoadTestCases(t, "engine")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			buf := new(bytes.Buffer)

			haveOutputs, err := eng.Check(context.Background(), tc.Inputs, WithWriterTraceSink(buf))
			t.Logf("TRACE =>\n%s", buf.String())

			if tc.WantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			for i, have := range haveOutputs {
				require.Empty(t, cmp.Diff(tc.WantOutputs[i], have, protocmp.Transform(), protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles")))
			}
		})
	}
}

func readTestCase(tb testing.TB, data []byte) *privatev1.EngineTestCase {
	tb.Helper()

	tc := &privatev1.EngineTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func BenchmarkCheck(b *testing.B) {
	testCases := test.LoadTestCases(b, "engine")

	b.Run("noop_decision_logger", func(b *testing.B) {
		eng, cancelFunc := mkEngine(b, false)
		defer cancelFunc()

		runBenchmarks(b, eng, testCases)
	})

	b.Run("local_decision_logger", func(b *testing.B) {
		eng, cancelFunc := mkEngine(b, true)
		defer cancelFunc()

		runBenchmarks(b, eng, testCases)
	})
}

func runBenchmarks(b *testing.B, eng *Engine, testCases []test.Case) {
	b.Helper()

	for _, tcase := range testCases {
		tcase := tcase
		b.Run(tcase.Name, func(b *testing.B) {
			tc := readTestCase(b, tcase.Input)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				have, err := eng.Check(context.Background(), tc.Inputs)
				if tc.WantError {
					if err == nil {
						b.Errorf("Expected error but got none")
					}
				}

				dummy += len(have)
			}
		})
	}
}

func mkEngine(tb testing.TB, enableAuditLog bool) (*Engine, context.CancelFunc) {
	tb.Helper()

	dir := test.PathToDir(tb, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	compiler := compile.NewManager(ctx, store)

	var auditLog audit.Log
	if enableAuditLog {
		conf := &local.Conf{
			StoragePath: tb.TempDir(),
		}
		conf.SetDefaults()

		auditLog, err = local.NewLog(conf)
		require.NoError(tb, err)
	} else {
		auditLog = audit.NewNopLog()
	}

	eng, err := New(ctx, compiler, auditLog)
	require.NoError(tb, err)

	return eng, cancelFunc
}

func TestSatisfiesCondition(t *testing.T) {
	testCases := test.LoadTestCases(t, "cel_eval")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readCELTestCase(t, tcase.Input)
			cond, err := compile.Condition(&policyv1.Condition{Condition: &policyv1.Condition_Match{Match: tc.Condition}})
			require.NoError(t, err)

			buf := new(bytes.Buffer)
			tcr := newTracer(NewWriterTraceSink(buf))

			retVal, err := satisfiesCondition(tcr.beginTrace(conditionComponent), cond, nil, tc.Input)
			t.Logf("TRACE =>\n%s", buf.String())

			if tc.WantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.Want, retVal)
		})
	}
}

func readCELTestCase(t *testing.T, data []byte) *privatev1.CelTestCase {
	t.Helper()

	tc := &privatev1.CelTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
