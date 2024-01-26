// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
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
	mockAuditLog := &mockAuditLog{}
	eng, cancelFunc := mkEngine(t, param{auditLog: mockAuditLog, schemaEnforcement: schema.EnforcementNone})
	defer cancelFunc()

	testCases := test.LoadTestCases(t, "engine")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			mockAuditLog.clear()

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

			haveDecisionLogs := mockAuditLog.getDecisionLogs()
			require.Empty(t, cmp.Diff(tc.WantDecisionLogs,
				haveDecisionLogs,
				protocmp.Transform(),
				protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
				protocmp.IgnoreFields(&auditv1.DecisionLogEntry{}, "call_id", "timestamp", "peer"),
			))
		})
	}
}

func TestCheckWithLenientScopeSearch(t *testing.T) {
	mockAuditLog := &mockAuditLog{}
	eng, cancelFunc := mkEngine(t, param{auditLog: mockAuditLog, schemaEnforcement: schema.EnforcementNone, lenientScopeSearch: true})
	defer cancelFunc()

	testCases := test.LoadTestCases(t, "engine")
	testCases = append(testCases, test.LoadTestCases(t, "engine_lenient_scope_search")...)

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			mockAuditLog.clear()

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

			haveDecisionLogs := mockAuditLog.getDecisionLogs()
			require.Empty(t, cmp.Diff(tc.WantDecisionLogs,
				haveDecisionLogs,
				protocmp.Transform(),
				protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
				protocmp.IgnoreFields(&auditv1.DecisionLogEntry{}, "call_id", "timestamp", "peer"),
			))
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
	enableAuditLog     bool
	schemaEnforcement  schema.Enforcement
	subDir             string
	lenientScopeSearch bool
	auditLog           audit.Log
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
	switch {
	case p.auditLog != nil:
		auditLog = p.auditLog
	case p.enableAuditLog:
		conf := &local.Conf{
			StoragePath: tb.TempDir(),
		}
		conf.SetDefaults()

		decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
		auditLog, err = local.NewLog(conf, decisionFilter)
		require.NoError(tb, err)
	default:
		auditLog = audit.NewNopLog()
	}

	engineConf := &Conf{}
	engineConf.SetDefaults()
	engineConf.Globals = map[string]any{"environment": "test"}
	engineConf.LenientScopeSearch = p.lenientScopeSearch

	eng := NewFromConf(ctx, engineConf, Components{
		PolicyLoader:      compiler,
		SchemaMgr:         schemaMgr,
		AuditLog:          auditLog,
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})

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
	timestamp, err := time.Parse(time.RFC3339, "2024-01-16T10:18:27.395716+13:00")
	require.NoError(t, err)
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
					nowFnCallsCounter := 0
					nowFn := func() time.Time {
						nowFnCallsCounter++
						return timestamp
					}
					response, err := eng.PlanResources(context.Background(), request, WithNowFunc(nowFn))
					if tt.WantErr {
						is.Error(err)
					} else {
						is.NoError(err)
						is.NotNil(response)
						is.Empty(cmp.Diff(tt.Want, response.Filter, protocmp.Transform()), "AST: %s\n%s\n", response.FilterDebug, protojson.Format(response.Filter))
						is.Equal(1, nowFnCallsCounter, "time function should be called once")
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

var _ audit.Log = (*mockAuditLog)(nil)

type mockAuditLog struct {
	mu           sync.RWMutex
	decisionLogs []*auditv1.DecisionLogEntry
	errors       []error
}

func (m *mockAuditLog) WriteAccessLogEntry(_ context.Context, _ audit.AccessLogEntryMaker) error {
	return nil
}

func (m *mockAuditLog) WriteDecisionLogEntry(_ context.Context, entry audit.DecisionLogEntryMaker) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, err := entry()
	if err != nil {
		m.errors = append(m.errors, err)
		return err
	}

	m.decisionLogs = append(m.decisionLogs, e)
	return nil
}

func (m *mockAuditLog) Close() error {
	return nil
}

func (m *mockAuditLog) Enabled() bool {
	return true
}

func (m *mockAuditLog) Backend() string {
	return "mock"
}

func (m *mockAuditLog) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.decisionLogs = nil
}

func (m *mockAuditLog) getDecisionLogs() []*auditv1.DecisionLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	decisionLogs := slices.Clone(m.decisionLogs)
	return decisionLogs
}
