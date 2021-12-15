// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
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
	eng, cancelFunc := mkEngine(t, false, "")
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
		eng, cancelFunc := mkEngine(b, false, "")
		defer cancelFunc()

		runBenchmarks(b, eng, testCases)
	})

	b.Run("local_decision_logger", func(b *testing.B) {
		eng, cancelFunc := mkEngine(b, true, "")
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

func mkEngine(tb testing.TB, enableAuditLog bool, subDir string) (*Engine, context.CancelFunc) {
	tb.Helper()

	if subDir == "" {
		subDir = "store"
	}
	dir := test.PathToDir(tb, subDir)

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

func readQPTestSuite(t *testing.T, data []byte) *privatev1.QueryPlannerTestSuite {
	t.Helper()

	tc := &privatev1.QueryPlannerTestSuite{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
func TestQueryPlan(t *testing.T) {
	eng, cancelFunc := mkEngine(t, false, "query_planner/policies")
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

					response, err := eng.List(context.Background(), request)
					is.NoError(err)
					is.NotNil(response)

					is.Empty(cmp.Diff(tt.Want, response.Filter, protocmp.Transform()))
				})
			}
		})
	}
}
func TestList(t *testing.T) {
	eng, cancelFunc := mkEngine(t, false, "")
	defer cancelFunc()

	request := &requestv1.ResourcesQueryPlanRequest{
		RequestId: "requestId",
		Action:    "approve",
		Principal: &enginev1.Principal{
			Id:            "maggie",
			PolicyVersion: "default",
			Roles:         []string{"employee", "manager"},
			Attr: map[string]*structpb.Value{
				"geography": {Kind: &structpb.Value_StringValue{StringValue: "US"}},
				"managed_geographies": {Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: []*structpb.Value{
							{Kind: &structpb.Value_StringValue{StringValue: "US"}},
							{Kind: &structpb.Value_StringValue{StringValue: "CA"}},
						},
					},
				}},
			},
		},
		PolicyVersion: "default",
		ResourceKind:  "list-resources:leave_request",
	}
	tests := []struct {
		name, action, want, yaml string
		input                    *requestv1.ResourcesQueryPlanRequest
	}{
		{
			name: "harry wants to view",
			input: &requestv1.ResourcesQueryPlanRequest{
				RequestId: "requestId",
				Action:    "view",
				Principal: &enginev1.Principal{
					Id:            "harry",
					PolicyVersion: "default",
					Roles:         []string{"employee"},
				},
				PolicyVersion: "default",
				ResourceKind:  "list-resources:leave_request",
			},
			want: `(R.attr.owner == "harry")`,
		},
		{
			name: "harry wants to view2",
			input: &requestv1.ResourcesQueryPlanRequest{
				RequestId: "requestId",
				Action:    "view2",
				Principal: &enginev1.Principal{
					Id:            "harry",
					PolicyVersion: "default",
					Roles:         []string{"user"},
				},
				PolicyVersion: "default",
				ResourceKind:  "list-resources:leave_request",
			},
			want: `(request.resource.attr.owner == "harry")`,
		},
		{
			name:   "maggie wants to approve 3: short-circuit test",
			action: "approve3",
			input:  request,
			want:   `(false)`,
			yaml:   "value: false",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := require.New(t)
			if tt.action != "" {
				tt.input.Action = tt.action
			}
			response, err := eng.List(context.Background(), tt.input)
			is.NoError(err)
			is.NotNil(response)
			is.Equal(tt.want, response.FilterDebug)
			if tt.yaml == "" {
				buf, err := protojson.Marshal(response.Filter)
				is.NoError(err)
				buf, err = yaml.JSONToYAML(buf)
				is.NoError(err)

				t.Fatalf("Please specify yaml to test response.Filter. Returned value:\n%s", string(buf))
			}
			expected := new(responsev1.ResourcesQueryPlanResponse_Expression_Operand)
			err = util.ReadJSONOrYAML(strings.NewReader(tt.yaml), expected)
			is.NoError(err)
			is.Empty(cmp.Diff(expected, response.Filter, protocmp.Transform()))
		})
	}
}
