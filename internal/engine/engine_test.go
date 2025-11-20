// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/planner"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

// trick compiler into not converting benchmarks into nops.
var dummy int

func TestCheck(t *testing.T) {
	mockAuditLog := &mockAuditLog{}
	params := param{auditLog: mockAuditLog, schemaEnforcement: schema.EnforcementNone}

	eng, engCancelFunc := mkEngine(t, params)
	defer engCancelFunc()

	rt, rtCancelFunc := mkRuleTable(t, params)
	defer rtCancelFunc()

	evaluators := map[string]evaluator.Evaluator{
		"engine":    eng,
		"ruletable": rt,
	}

	testCases := test.LoadTestCases(t, "engine")

	for evalName, eval := range evaluators {
		t.Run(evalName, func(t *testing.T) {
			for _, tcase := range testCases {
				t.Run(tcase.Name, func(t *testing.T) {
					tc := readTestCase(t, tcase.Input)
					mockAuditLog.clear()

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

					haveDecisionLogs := mockAuditLog.getDecisionLogs()

					// ruletable calls do not return audit logs
					if evalName == "ruletable" {
						tc.WantDecisionLogs = nil
					}

					require.Empty(t, cmp.Diff(tc.WantDecisionLogs,
						haveDecisionLogs,
						protocmp.Transform(),
						protocmp.IgnoreEmptyMessages(),
						protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
						protocmp.SortRepeatedFields(&enginev1.Principal{}, "roles"),
						protocmp.IgnoreFields(&auditv1.DecisionLogEntry{}, "call_id", "timestamp", "peer"),
					))
				})
			}
		})
	}

	t.Run("deterministic_now", func(t *testing.T) {
		roles := []string{"user"}
		actions := []string{"a", "b", "c"}

		inputs := []*enginev1.CheckInput{
			{
				Principal: &enginev1.Principal{Id: "1", Roles: roles},
				Resource:  &enginev1.Resource{Kind: "output_now", Id: "1"},
				Actions:   actions,
			},
			{
				Principal: &enginev1.Principal{Id: "2", Roles: roles},
				Resource:  &enginev1.Resource{Kind: "output_now", Id: "1"},
				Actions:   actions,
			},
			{
				Principal: &enginev1.Principal{Id: "1", Roles: roles},
				Resource:  &enginev1.Resource{Kind: "output_now", Id: "2"},
				Actions:   actions,
			},
			{
				Principal: &enginev1.Principal{Id: "2", Roles: roles},
				Resource:  &enginev1.Resource{Kind: "output_now", Id: "2"},
				Actions:   actions,
			},
		}

		outputs, err := eng.Check(t.Context(), inputs)
		require.NoError(t, err)
		require.Len(t, outputs, len(inputs))

		uniqueNows := make(map[string]struct{})
		for _, output := range outputs {
			require.Len(t, output.Outputs, 3)
			for _, entry := range output.Outputs {
				uniqueNows[entry.Val.GetStringValue()] = struct{}{}
			}
		}
		require.Len(t, uniqueNows, 1)
	})
}

func TestCheckWithLenientScopeSearch(t *testing.T) {
	mockAuditLog := &mockAuditLog{}
	eng, cancelFunc := mkEngine(t, param{auditLog: mockAuditLog, schemaEnforcement: schema.EnforcementNone, lenientScopeSearch: true})
	defer cancelFunc()

	testCases := test.LoadTestCases(t, "engine")
	testCases = append(testCases, test.LoadTestCases(t, "engine_lenient_scope_search")...)

	for _, tcase := range testCases {
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			mockAuditLog.clear()

			traceCollector := tracer.NewCollector()
			haveOutputs, err := eng.Check(t.Context(), tc.Inputs, evaluator.WithTraceSink(traceCollector))

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
					protocmp.FilterField(&enginev1.CheckOutput{}, "outputs", cmpopts.SortSlices(func(x, y *enginev1.OutputEntry) bool {
						return x.Src < y.Src
					})),
				))
			}

			haveDecisionLogs := mockAuditLog.getDecisionLogs()
			require.Empty(t, cmp.Diff(tc.WantDecisionLogs,
				haveDecisionLogs,
				protocmp.Transform(),
				protocmp.IgnoreEmptyMessages(),
				protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
				protocmp.SortRepeatedFields(&enginev1.Principal{}, "roles"),
				protocmp.IgnoreFields(&auditv1.DecisionLogEntry{}, "call_id", "timestamp", "peer"),
			))
		})
	}
}

func TestSchemaValidation(t *testing.T) {
	for _, enforcement := range []string{"warn", "reject"} {
		t.Run(fmt.Sprintf("enforcement=%s", enforcement), func(t *testing.T) {
			p := param{schemaEnforcement: schema.Enforcement(enforcement)}

			eng, cancelFunc := mkEngine(t, p)
			t.Cleanup(cancelFunc)

			testCases := test.LoadTestCases(t, filepath.Join("engine_schema_enforcement", enforcement))

			for _, tcase := range testCases {
				t.Run(tcase.Name, func(t *testing.T) {
					tc := readTestCase(t, tcase.Input)

					haveOutputs, err := eng.Check(t.Context(), tc.Inputs, evaluator.WithTraceSink(newTestTraceSink(t)))

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
							protocmp.FilterField(&enginev1.CheckOutput{}, "outputs", cmpopts.SortSlices(func(x, y *enginev1.OutputEntry) bool {
								return x.Src < y.Src
							})),
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

	store := test.PathToDir(tb, "store")

	for _, entry := range tc.WantDecisionLogs {
		disk := entry.GetPolicySource().GetDisk()
		if disk != nil {
			disk.Directory = store
		}
	}

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

func runBenchmarks(b *testing.B, eng evaluator.Evaluator, testCases []test.Case) {
	b.Helper()

	for _, tcase := range testCases {
		b.Run(tcase.Name, func(b *testing.B) {
			tc := readTestCase(b, tcase.Input)

			b.ResetTimer()
			b.ReportAllocs()

			for b.Loop() {
				have, err := eng.Check(b.Context(), tc.Inputs)
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

func mkEngine(tb testing.TB, p param) (evaluator.Evaluator, context.CancelFunc) {
	tb.Helper()

	if p.subDir == "" {
		p.subDir = "store"
	}
	dir := test.PathToDir(tb, p.subDir)

	ctx, cancelFunc := context.WithCancel(tb.Context())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(tb, err)

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

	rt := ruletable.NewProtoRuletable()
	require.NoError(tb, ruletable.LoadPolicies(ctx, rt, compiler))

	schemaConf := schema.NewConf(p.schemaEnforcement)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, compiler, schemaMgr)
	require.NoError(tb, err)

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	evalConf.Globals = map[string]any{"environment": "test"}
	evalConf.LenientScopeSearch = p.lenientScopeSearch

	eng := NewFromConf(ctx, evalConf, Components{
		PolicyLoader:      compiler,
		RuleTableManager:  ruletableMgr,
		SchemaMgr:         schemaMgr,
		AuditLog:          auditLog,
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})

	return eng, cancelFunc
}

func mkRuleTable(tb testing.TB, p param) (evaluator.Evaluator, context.CancelFunc) {
	tb.Helper()

	if p.subDir == "" {
		p.subDir = "store"
	}
	dir := test.PathToDir(tb, p.subDir)

	ctx, cancelFunc := context.WithCancel(tb.Context())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	protoRT := ruletable.NewProtoRuletable()

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(tb, err)

	err = ruletable.LoadPolicies(ctx, protoRT, compiler)
	require.NoError(tb, err)

	err = ruletable.LoadSchemas(ctx, protoRT, store)
	require.NoError(tb, err)

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	evalConf.Globals = map[string]any{"environment": "test"}
	evalConf.LenientScopeSearch = p.lenientScopeSearch

	rt, err := ruletable.NewRuleTable(protoRT, evalConf, schema.NewConf(p.schemaEnforcement))
	require.NoError(tb, err)

	return rt.Evaluator(), cancelFunc
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
				actionName := tt.Action
				if tt.Actions != nil {
					actionName = strings.Join(tt.Actions, ", ")
				}
				t.Run(fmt.Sprintf("%s/%s", tt.Resource.Kind, actionName), func(t *testing.T) {
					is := require.New(t)
					request := &enginev1.PlanResourcesInput{
						RequestId: "requestId",
						Principal: ts.Principal,
						Resource: &enginev1.PlanResourcesInput_Resource{
							Kind:          tt.Resource.Kind,
							Attr:          tt.Resource.Attr,
							PolicyVersion: tt.Resource.PolicyVersion,
							Scope:         tt.Resource.Scope,
						},
						IncludeMeta: true,
						AuxData:     auxData,
					}
					if tt.Actions != nil {
						request.Actions = tt.Actions
					} else {
						request.Actions = []string{tt.Action} //nolint:staticcheck
					}
					response, err := eng.Plan(t.Context(), request, evaluator.WithNowFunc(func() time.Time { return timestamp }))
					if tt.WantErr {
						is.Error(err)
					} else {
						is.NoError(err)
						is.NotNil(response)
					}
					filter, filterDebug := response.Filter, response.FilterDebug
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(stabiliseFilter(tt.Want), stabiliseFilter(filter),
						protocmp.Transform(),
						protocmp.SortRepeatedFields(&enginev1.PlanResourcesFilter_Expression{}, "operands")),
						"AST: %s\n%s\n", filterDebug, protojson.Format(filter))
				})
			}
		})
	}
}

// Create a recursive function to normalize all expressions with commutative operators.
func stabiliseFilter(filter *enginev1.PlanResourcesFilter) *enginev1.PlanResourcesFilter {
	if filter == nil {
		return nil
	}

	result := &enginev1.PlanResourcesFilter{
		Kind: filter.Kind,
	}

	if filter.Condition != nil {
		result.Condition = stabiliseOperand(filter.Condition)
	}

	return result
}

func stabiliseOperand(operand *enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	if operand == nil {
		return nil
	}

	if n, ok := operand.Node.(*enginev1.PlanResourcesFilter_Expression_Operand_Expression); ok {
		result := &enginev1.PlanResourcesFilter_Expression_Operand{}
		expr := stabiliseExpression(n.Expression)
		result.Node = &enginev1.PlanResourcesFilter_Expression_Operand_Expression{
			Expression: expr,
		}
		return result
	}

	return operand
}

func isCommutativeOperator(op string) bool {
	switch op {
	case planner.And, planner.Or, planner.Equals, planner.NotEquals, planner.Add, planner.Mult:
		return true
	default:
		return false
	}
}

func stabiliseExpression(expr *enginev1.PlanResourcesFilter_Expression) *enginev1.PlanResourcesFilter_Expression {
	if expr == nil {
		return nil
	}

	result := &enginev1.PlanResourcesFilter_Expression{
		Operator: expr.Operator,
	}

	// Normalize all operands
	normalizedOperands := make([]*enginev1.PlanResourcesFilter_Expression_Operand, len(expr.Operands))
	for i, op := range expr.Operands {
		normalizedOperands[i] = stabiliseOperand(op)
	}

	// Ensure struct literals have deterministically ordered entries to avoid flaky comparisons
	if expr.Operator == planner.Struct {
		sort.Slice(normalizedOperands, func(i, j int) bool {
			return normalizedOperands[i].GetExpression().Operands[0].GetValue().GetStringValue() <
				normalizedOperands[j].GetExpression().Operands[0].GetValue().GetStringValue()
		})
	}

	// Sort operands if operator is commutative
	if isCommutativeOperator(expr.Operator) {
		sort.Slice(normalizedOperands, func(i, j int) bool {
			aJSON, _ := protojson.Marshal(normalizedOperands[i])
			bJSON, _ := protojson.Marshal(normalizedOperands[j])
			return bytes.Compare(aJSON, bJSON) < 0
		})
	}

	result.Operands = normalizedOperands
	return result
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
