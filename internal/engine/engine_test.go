package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	cerbosdevv1 "github.com/cerbos/cerbos/internal/genpb/cerbosdev/v1"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

// trick compiler into not converting benchmarks into nops.
var dummy int

func TestEngineCheckResourceBatch(t *testing.T) {
	eng, cancelFunc := mkEngine(t)
	defer cancelFunc()

	testCases := test.LoadTestCases(t, "engine")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)

			have, err := eng.CheckResourceBatch(context.Background(), tc.Input)
			if tc.WantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.WantResponse == nil {
				return
			}

			require.NotNil(t, have)

			// clear out timing data to make the comparison work
			if have.Meta != nil {
				have.Meta.EvaluationDuration = nil
			}

			require.Empty(t, cmp.Diff(tc.WantResponse, have, protocmp.Transform()))
		})
	}
}

func readTestCase(tb testing.TB, data []byte) *cerbosdevv1.EngineTestCase {
	tb.Helper()

	tc := &cerbosdevv1.EngineTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func BenchmarkCheckResourceBatch(b *testing.B) {
	eng, cancelFunc := mkEngine(b)
	defer cancelFunc()

	testCases := test.LoadTestCases(b, "engine")

	for _, tcase := range testCases {
		tcase := tcase
		b.Run(tcase.Name, func(b *testing.B) {
			tc := readTestCase(b, tcase.Input)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				have, err := eng.CheckResourceBatch(context.Background(), tc.Input)
				if tc.WantError {
					if err == nil {
						b.Errorf("Expected error but got none")
					}
				}

				if tc.WantResponse != nil {
					dummy += len(have.RequestId)
				}
			}
		})
	}
}

func mkEngine(tb testing.TB) (*Engine, context.CancelFunc) {
	tb.Helper()

	dir := test.PathToDir(tb, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewReadOnlyStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	eng, err := New(ctx, store)
	require.NoError(tb, err)

	return eng, cancelFunc
}
