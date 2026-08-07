// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
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
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/planner"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

// trick compiler into not converting benchmarks into nops.
var dummy int

func TestCheck(t *testing.T) {
	t.Parallel()

	mkEngine := mkEngineFactory(t, "store")
	mkRuleTable := mkRuleTableFactory(t, "store", false)
	mkRuleTableWithRoundTrippedIndex := mkRuleTableFactory(t, "store", true)

	for _, tcase := range test.LoadTestCases(t, "engine") {
		t.Run(tcase.Name, func(t *testing.T) {
			t.Parallel()

			tc := readTestCase(t, tcase.Input)

			testEngineConfigMatrix(t, tc.GetConfig(), func(t *testing.T, params param, mockAuditLog *mockAuditLog, wantSuccess bool) {
				t.Helper()

				t.Run("engine", func(t *testing.T) {
					testCheck(t, tc, mkEngine(t, params), wantSuccess)

					diff := cmp.Diff(tc.WantDecisionLogs, mockAuditLog.getDecisionLogs(),
						protocmp.Transform(),
						protocmp.IgnoreEmptyMessages(),
						protocmp.IgnoreFields(&auditv1.DecisionLogEntry{}, "call_id", "timestamp", "peer"),
						protocmp.SortRepeated(cmpOutputEntry),
						protocmp.SortRepeated(cmpValidationError),
						protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
						protocmp.SortRepeatedFields(&enginev1.Principal{}, "roles"),
					)

					if wantSuccess {
						require.Empty(t, diff, "Unexpected decision logs")
					} else {
						require.NotEmpty(t, diff, "Expected decision logs not to match")
					}
				})

				t.Run("ruletable", func(t *testing.T) {
					testCheck(t, tc, mkRuleTable(t, params), wantSuccess)

					t.Run("round-tripped index", func(t *testing.T) {
						testCheck(t, tc, mkRuleTableWithRoundTrippedIndex(t, params), wantSuccess)
					})
				})
			})
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

		outputs, err := mkEngine(t, param{}).Check(t.Context(), inputs)
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

func testEngineConfigMatrix(t *testing.T, config *privatev1.EngineConfig, test func(*testing.T, param, *mockAuditLog, bool)) {
	t.Helper()

	for _, lenientScopeSearch := range []bool{false, true} {
		t.Run(fmt.Sprintf("lenient_scope_search=%v", lenientScopeSearch), func(t *testing.T) {
			for _, schemaEnforcement := range []privatev1.EngineConfig_Enforcement{privatev1.EngineConfig_ENFORCEMENT_NONE, privatev1.EngineConfig_ENFORCEMENT_WARN, privatev1.EngineConfig_ENFORCEMENT_REJECT} {
				t.Run(fmt.Sprintf("schema_enforcement=%s", schemaEnforcement), func(t *testing.T) {
					for _, strictEvaluation := range []bool{false, true} {
						t.Run(fmt.Sprintf("strict_evaluation=%v", strictEvaluation), func(t *testing.T) {
							mockAuditLog := &mockAuditLog{}

							wantSuccess := slices.Contains(config.GetLenientScopeSearch(), lenientScopeSearch) &&
								slices.Contains(config.GetSchemaEnforcement(), schemaEnforcement) &&
								slices.Contains(config.GetStrictEvaluation(), strictEvaluation)

							test(t, param{
								auditLog:             mockAuditLog,
								defaultPolicyVersion: config.GetDefaultPolicyVersion(),
								defaultScope:         config.GetDefaultScope(),
								globals:              (&structpb.Struct{Fields: config.GetGlobals()}).AsMap(),
								lenientScopeSearch:   lenientScopeSearch,
								schemaEnforcement:    schemaEnforcementFromProto(schemaEnforcement),
								strictEvaluation:     strictEvaluation,
							}, mockAuditLog, wantSuccess)
						})
					}
				})
			}
		})
	}
}

func schemaEnforcementFromProto(enforcement privatev1.EngineConfig_Enforcement) schema.Enforcement {
	switch enforcement {
	case privatev1.EngineConfig_ENFORCEMENT_NONE:
		return schema.EnforcementNone
	case privatev1.EngineConfig_ENFORCEMENT_WARN:
		return schema.EnforcementWarn
	case privatev1.EngineConfig_ENFORCEMENT_REJECT:
		return schema.EnforcementReject
	default:
		panic("Unexpected schema enforcement value")
	}
}

func testCheck(t *testing.T, tc *privatev1.EngineTestCase, eval evaluator.Evaluator, wantSuccess bool) {
	t.Helper()

	haveOutputs, err := eval.Check(t.Context(), tc.Inputs)
	require.NoError(t, err)

	diff := cmp.Diff(tc.WantOutputs, haveOutputs,
		protocmp.Transform(),
		protocmp.SortRepeated(cmpOutputEntry),
		protocmp.SortRepeated(cmpValidationError),
		protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
	)

	if wantSuccess {
		require.Empty(t, diff, "Unexpected check outputs")
	} else {
		require.NotEmpty(t, diff, "Expected check outputs not to match")
	}
}

func cmpOutputEntry(a, b *enginev1.OutputEntry) bool {
	return a.Src < b.Src
}

func cmpValidationError(a, b *schemav1.ValidationError) bool {
	if a.Source == b.Source {
		return a.Path < b.Path
	}
	return a.Source < b.Source
}

func readTestCase(tb testing.TB, data []byte) *privatev1.EngineTestCase {
	tb.Helper()

	tc := test.Parse[privatev1.EngineTestCase](tb, data)

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
				eng := mkEngineFactory(b, "store")(b, param{enableAuditLog: enableAuditLog, schemaEnforcement: schemaEnforcement})
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
				have, _ := eng.Check(b.Context(), tc.Inputs)
				dummy += len(have)
			}
		})
	}
}

type param struct {
	enableAuditLog       bool
	schemaEnforcement    schema.Enforcement
	defaultPolicyVersion string
	defaultScope         string
	lenientScopeSearch   bool
	strictEvaluation     bool
	globals              map[string]any
	auditLog             audit.Log
}

func (p param) evalConf() *evaluator.Conf {
	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	if p.defaultPolicyVersion != "" {
		evalConf.DefaultPolicyVersion = p.defaultPolicyVersion
	}
	evalConf.DefaultScope = p.defaultScope
	evalConf.Globals = p.globals
	evalConf.LenientScopeSearch = p.lenientScopeSearch
	evalConf.StrictEvaluation = p.strictEvaluation
	return evalConf
}

func mkEngineFactory(tb testing.TB, storeDir string) func(testing.TB, param) evaluator.Evaluator {
	tb.Helper()
	ctx := tb.Context()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: test.PathToDir(tb, storeDir)})
	require.NoError(tb, err)

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(tb, err)

	ruleTable, err := ruletable.NewRuleTableFromLoader(ctx, compiler)
	require.NoError(tb, err)

	return func(tb testing.TB, p param) evaluator.Evaluator {
		tb.Helper()

		schemaConf := schema.NewConf(p.schemaEnforcement)
		schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

		ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, compiler, schemaMgr)
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

		eng := NewFromConf(ctx, p.evalConf(), Components{
			PolicyLoader:      compiler,
			RuleTableManager:  ruletableMgr,
			SchemaMgr:         schemaMgr,
			AuditLog:          auditLog,
			MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
		})

		return eng
	}
}

func mkRuleTableFactory(tb testing.TB, storeDir string, roundTripIndex bool) func(testing.TB, param) evaluator.Evaluator {
	tb.Helper()
	ctx := tb.Context()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: test.PathToDir(tb, storeDir)})
	require.NoError(tb, err)

	protoRT := ruletable.NewProtoRuletable()

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(tb, err)

	err = ruletable.LoadPolicies(ctx, protoRT, compiler)
	require.NoError(tb, err)

	err = ruletable.LoadSchemas(ctx, protoRT, store)
	require.NoError(tb, err)

	rt, err := ruletable.NewRuleTable(protoRT)
	require.NoError(tb, err)

	if roundTripIndex {
		rt.MarshalAndUnmarshalIndex(tb)
	}

	return func(tb testing.TB, p param) evaluator.Evaluator {
		tb.Helper()
		eval, err := rt.Evaluator(p.evalConf(), schema.NewConf(p.schemaEnforcement))
		require.NoError(tb, err)
		return eval
	}
}

func TestQueryPlan(t *testing.T) {
	t.Parallel()

	mkEngine := mkEngineFactory(t, "query_planner/policies")
	testCases := test.LoadTestCases(t, "query_planner/suite")

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			ts := test.Parse[privatev1.QueryPlannerTestSuite](t, tc.Input)

			testEngineConfigMatrix(t, ts.GetConfig(), func(t *testing.T, params param, _ *mockAuditLog, wantSuccess bool) {
				t.Helper()

				eng := mkEngine(t, params)

				for _, tt := range ts.Tests {
					actionName := tt.Action
					if tt.Actions != nil {
						actionName = strings.Join(tt.Actions, ", ")
					}

					t.Run(fmt.Sprintf("%s/%s", tt.Resource.Kind, actionName), func(t *testing.T) {
						request := &enginev1.PlanResourcesInput{
							RequestId: "requestId",
							Principal: ts.Principal,
							Resource: &enginev1.PlanResourcesInput_Resource{
								Kind:          tt.Resource.Kind,
								Attr:          tt.Resource.Attr,
								PolicyVersion: tt.Resource.PolicyVersion,
								Scope:         tt.Resource.Scope,
							},
							Actions:     tt.Actions,
							AuxData:     ts.AuxData,
							IncludeMeta: true,
						}

						if tt.Action != "" {
							request.Actions = []string{tt.Action}
						}

						var opts []evaluator.CheckOpt
						if ts.Now != nil {
							opts = append(opts, evaluator.WithNowFunc(func() time.Time { return ts.Now.AsTime() }))
						}

						response, err := eng.Plan(t.Context(), request, opts...)
						require.NoError(t, err)
						require.NotNil(t, response)

						diff := cmp.Diff(stabiliseFilter(tt.Want), stabiliseFilter(response.Filter),
							protocmp.Transform(),
							protocmp.SortRepeatedFields(&enginev1.PlanResourcesFilter_Expression{}, "operands"),
						)

						if wantSuccess {
							require.Empty(t, diff, protojson.Format(response))
						} else {
							require.NotEmpty(t, diff)
						}
					})
				}
			})
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

func (m *mockAuditLog) getDecisionLogs() []*auditv1.DecisionLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	decisionLogs := slices.Clone(m.decisionLogs)
	return decisionLogs
}
