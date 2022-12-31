// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/printer"
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

			traceCollector := tracer.NewCollector()
			haveOutputs, err := eng.Check(context.Background(), tc.Inputs, WithTraceSink(traceCollector))

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

					haveOutputs, err := eng.Check(context.Background(), tc.Inputs, WithTraceSink(newTestTraceSink(t)))

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
	tb.Helper()

	if p.subDir == "" {
		p.subDir = "store"
	}
	dir := test.PathToDir(tb, p.subDir)

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	schemaConf := schema.NewConf(p.schemaEnforcement)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	compiler := compile.NewManagerFromDefaultConf(ctx, store, schemaMgr)

	var auditLog audit.Log
	if p.enableAuditLog {
		conf := &local.Conf{
			StoragePath: tb.TempDir(),
		}
		conf.SetDefaults()

		decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
		auditLog, err = local.NewLog(conf, decisionFilter)
		require.NoError(tb, err)
	} else {
		auditLog = audit.NewNopLog()
	}

	eng, err := New(ctx, Components{
		PolicyLoader:      compiler,
		SchemaMgr:         schemaMgr,
		AuditLog:          auditLog,
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})
	require.NoError(tb, err)

	return eng, cancelFunc
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

	auxData := &enginev1.AuxData{Jwt: make(map[string]*structpb.Value)}
	auxData.Jwt["customInt"] = structpb.NewNumberValue(42)

	suites := test.LoadTestCases(t, "query_planner/suite")
	for _, suite := range suites {
		s := suite
		t.Run(s.Name, func(t *testing.T) {
			ts := readQPTestSuite(t, s.Input)
			for _, tt := range ts.Tests {
				t.Run(fmt.Sprintf("%s/%s", tt.Resource.Kind, tt.Action), func(t *testing.T) {
					is := require.New(t)
					request := &enginev1.PlanResourcesInput{
						RequestId: "requestId",
						Action:    tt.Action,
						Principal: ts.Principal,
						Resource: &enginev1.PlanResourcesInput_Resource{
							Kind:          tt.Resource.Kind,
							Attr:          tt.Resource.Attr,
							PolicyVersion: tt.Resource.PolicyVersion,
						},
						IncludeMeta: true,
						AuxData:     auxData,
					}

					response, err := eng.PlanResources(context.Background(), request)
					if tt.WantErr {
						is.Error(err)
					} else {
						is.NoError(err)
						is.NotNil(response)
						is.Empty(cmp.Diff(tt.Want, response.Filter, protocmp.Transform()), "AST: %s", response.FilterDebug)
					}
				})
			}
		})
	}
}

type testTraceSink struct {
	t *testing.T
}

func newTestTraceSink(t *testing.T) *testTraceSink {
	t.Helper()
	return &testTraceSink{t: t}
}

func (*testTraceSink) Enabled() bool {
	return true
}

func (s *testTraceSink) AddTrace(trace *enginev1.Trace) {
	var stdout bytes.Buffer
	printer.New(&stdout, io.Discard).PrintTrace(trace)
	s.t.Logf("%s\n", stdout.String())
}
