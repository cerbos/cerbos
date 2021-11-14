// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"fmt"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

// trick compiler into not converting benchmarks into nops.
var dummy int

func TestCheck(t *testing.T) {
	eng, cancelFunc := mkEngine(t, param{schemaEnforcement: schema.EnforcementNone})
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
				require.Empty(t, cmp.Diff(tc.WantOutputs[i],
					have,
					protocmp.Transform(),
					protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
				))
			}
		})
	}
}

func TestSchemaValidation(t *testing.T) {
	for _, enforcement := range []string{"warn", "reject"} {
		enforcement := enforcement
		t.Run(fmt.Sprintf("enforcement=%s", enforcement), func(t *testing.T) {
			p := param{schemaEnforcement: schema.Enforcement(enforcement)}

			eng, cancelFunc := mkEngine(t, p)
			t.Cleanup(cancelFunc)

			testCases := test.LoadTestCases(t, filepath.Join("engine_schema_enforcement", enforcement))

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
						require.Empty(t, cmp.Diff(tc.WantOutputs[i],
							have,
							protocmp.Transform(),
							protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
							protocmp.SortRepeated(cmpValidationError),
						))
					}
				})
			}
		})
	}
}

func cmpValidationError(a, b *schemav1.ValidationError) bool {
	if a.Source == b.Source {
		return a.Path < b.Path
	}
	return a.Source < b.Source
}

func readTestCase(tb testing.TB, data []byte) *privatev1.EngineTestCase {
	tb.Helper()

	tc := &privatev1.EngineTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func BenchmarkCheck(b *testing.B) {
	testCases := test.LoadTestCases(b, "engine")

	for _, enableAuditLog := range []bool{false, true} {
		for _, schemaEnforcement := range []schema.Enforcement{schema.EnforcementNone, schema.EnforcementWarn, schema.EnforcementReject} {
			b.Run(fmt.Sprintf("auditLog=%t/schemaEnforcement=%s", enableAuditLog, schemaEnforcement), func(b *testing.B) {
				eng, cancelFunc := mkEngine(b, param{enableAuditLog: enableAuditLog, schemaEnforcement: schemaEnforcement})
				defer cancelFunc()

				runBenchmarks(b, eng, testCases)
			})
		}
	}
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

type param struct {
	enableAuditLog    bool
	schemaEnforcement schema.Enforcement
	subDir            string
}

func mkEngine(tb testing.TB, p param) (*Engine, context.CancelFunc) {
	if p.subDir == "" {
		p.subDir = "store"
	}
	dir := test.PathToDir(tb, p.subDir)

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	schemaConf := &schema.Conf{Enforcement: p.schemaEnforcement}
	schemaMgr := schema.NewWithConf(ctx, store, schemaConf)

	compiler := compile.NewManager(ctx, store, schemaMgr)

	var auditLog audit.Log
	if p.enableAuditLog {
		conf := &local.Conf{
			StoragePath: tb.TempDir(),
		}
		conf.SetDefaults()

		auditLog, err = local.NewLog(conf)
		require.NoError(tb, err)
	} else {
		auditLog = audit.NewNopLog()
	}

	eng, err := New(ctx, Components{CompileMgr: compiler, SchemaMgr: schemaMgr, AuditLog: auditLog})
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

func readQPTestSuite(t *testing.T, data []byte) *privatev1.QueryPlannerTestSuite {
	t.Helper()

	tc := &privatev1.QueryPlannerTestSuite{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func TestQueryPlan(t *testing.T) {
	eng, cancelFunc := mkEngine(t, param{subDir: "query_planner/policies"})
	defer cancelFunc()

	suites := test.LoadTestCases(t, "query_planner/suite")
	for _, suite := range suites {
		s := suite
		t.Run(s.Name, func(t *testing.T) {
			ts := readQPTestSuite(t, s.Input)
			for _, tt := range ts.Tests {
				t.Run(tt.Action, func(t *testing.T) {
					is := require.New(t)
					request := &requestv1.ResourcesQueryPlanRequest{
						RequestId:     "requestId",
						Action:        tt.Action,
						Principal:     ts.Principal,
						PolicyVersion: tt.PolicyVersion,
						ResourceKind:  tt.ResourceKind,
					}

					response, err := eng.ResourcesQueryPlan(context.Background(), request)
					is.NoError(err)
					is.NotNil(response)

					is.Empty(cmp.Diff(tt.Want, response.Filter, protocmp.Transform()))
					t.Log(response.FilterDebug)
				})
			}
		})
	}
}
