// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package hub_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit/hub"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuditLogFilter(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	t.Run("Tokenise", func(t *testing.T) {
		tc := []struct {
			path    string
			wantErr error
		}{
			{
				".foo",
				errors.New("invalid first character: '.'"),
			},
			{
				"foo.",
				errors.New("invalid final character: '.'"),
			},
			{
				"foo..bar",
				errors.New("invalid empty token"),
			},
			{
				"foo[bar].baz",
				errors.New("invalid character following '[': b"),
			},
			{
				"foo['bar].baz",
				errors.New("invalid string not closed"),
			},
			{
				"foo[\"bar\"]",
				errors.New("invalid character following '[': \""),
			},
			{
				"foo'.baz",
				errors.New("unexpected character for accessor: '"),
			},
			{
				"foo].baz",
				errors.New("unexpected character for accessor: ]"),
			},
			{
				"'foo'.baz",
				errors.New("invalid first character: '"),
			},
			{
				"foo[1r]",
				errors.New("unexpected character in number: r"),
			},
		}

		for _, c := range tc {
			err := hub.Tokenize(&hub.Token{}, c.path)
			if c.wantErr != nil {
				require.Error(t, err, fmt.Sprintf("failed path: `%s`", c.path))
				require.Equal(t, c.wantErr.Error(), err.Error())
			} else {
				require.NoError(t, err, fmt.Sprintf("failed path: `%s`", c.path))
			}
		}
	})

	t.Run("Filter", func(t *testing.T) {
		now := time.Now()
		ts0 := timestamppb.New(now)
		ts1 := timestamppb.New(now.Add(1 * time.Second))
		ts2 := timestamppb.New(now.Add(3 * time.Second))

		maskConf := hub.MaskConf{
			Metadata: []string{"metadata_key_2"},
			Peer: []string{
				"address",
				"forwardedFor",
			},
			CheckResources: []string{
				"inputs[0].principal.id",
				"inputs[0].principal.attr.attr1",
				"inputs[*]['principal']['attr']['attr2']",
				"inputs[*].principal.attr.someMap.nestedAttr1",
				"inputs[*].principal.attr.oneKeyMap.nestedAttr1",
				"inputs[*].principal.attr.someMap.someSomeMap.nestedNestedAttr1",
				"inputs[*].principal.attr.someList[0]",
				"outputs",
			},
			PlanResources: []string{
				"['input']['principal']['attr']['someMap']['nestedAttr1']",
				"input.principal.attr.someList[1]",
				"output.filterDebug",
			},
		}

		logEntries := []*logsv1.IngestBatch_Entry{
			{
				Kind:      logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG,
				Timestamp: ts0,
				Entry: &logsv1.IngestBatch_Entry_AccessLogEntry{
					AccessLogEntry: &auditv1.AccessLogEntry{
						CallId:    "1",
						Timestamp: ts0,
						Peer: &auditv1.Peer{
							Address:      "1.1.1.1",
							UserAgent:    "Mozilla/5.0",
							ForwardedFor: "2.2.2.2",
						},
						Metadata: map[string]*auditv1.MetaValues{
							"metadata_key_1": {Values: []string{"1"}},
							"metadata_key_2": {Values: []string{"2"}},
							"metadata_key_3": {Values: []string{"3"}},
						},
						Method: "/cerbos.svc.v1.CerbosService/Check",
					},
				},
			},
			{
				Kind:      logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
				Timestamp: ts1,
				Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
					DecisionLogEntry: &auditv1.DecisionLogEntry{
						CallId:    "2",
						Timestamp: ts1,
						Peer: &auditv1.Peer{
							Address:   "1.1.1.1",
							UserAgent: "curl/7.68.0",
						},
						Metadata: map[string]*auditv1.MetaValues{
							"metadata_key_2": {Values: []string{"2"}},
						},
						Method: &auditv1.DecisionLogEntry_PlanResources_{
							PlanResources: &auditv1.DecisionLogEntry_PlanResources{
								Input: &enginev1.PlanResourcesInput{
									RequestId: "1",
									Action:    "a1",
									Principal: &enginev1.Principal{
										Id:    "test",
										Roles: []string{"a", "b"},
										Attr: map[string]*structpb.Value{
											"attr1": structpb.NewNumberValue(1),
											"attr2": structpb.NewNumberValue(2),
											"attr3": structpb.NewNumberValue(3),
											"someMap": structpb.NewStructValue(&structpb.Struct{
												Fields: map[string]*structpb.Value{
													"nestedAttr1": structpb.NewNumberValue(1),
													"nestedAttr2": structpb.NewNumberValue(2),
												},
											}),
											"someList": structpb.NewListValue(&structpb.ListValue{
												Values: []*structpb.Value{
													structpb.NewStringValue("index0"),
													structpb.NewStringValue("index1"),
												},
											}),
										},
									},
									Resource: &enginev1.PlanResourcesInput_Resource{
										Kind: "test:kind",
										Attr: map[string]*structpb.Value{},
									},
								},
								Output: &enginev1.PlanResourcesOutput{
									RequestId: "1",
									Action:    "a1",
									Kind:      "test:kind",
									Filter: &enginev1.PlanResourcesFilter{
										Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED,
									},
									FilterDebug: "debug string",
								},
								Error: "BOOM",
							},
						},
					},
				},
			},
			{
				Kind:      logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
				Timestamp: ts2,
				Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
					DecisionLogEntry: &auditv1.DecisionLogEntry{
						CallId:    "4",
						Timestamp: ts2,
						Peer: &auditv1.Peer{
							Address:   "1.1.1.1",
							UserAgent: "curl/7.68.0",
						},
						Metadata: map[string]*auditv1.MetaValues{
							"metadata_key_1": {Values: []string{"1"}},
						},
						Method: &auditv1.DecisionLogEntry_CheckResources_{
							CheckResources: &auditv1.DecisionLogEntry_CheckResources{
								Inputs: []*enginev1.CheckInput{
									{
										RequestId: "1",
										Resource: &enginev1.Resource{
											Kind: "test:kind",
											Id:   "test",
										},
										Principal: &enginev1.Principal{
											Id:    "test",
											Roles: []string{"a", "b"},
											Attr: map[string]*structpb.Value{
												"attr1": structpb.NewNumberValue(1),
												"attr2": structpb.NewNumberValue(2),
												"attr3": structpb.NewNumberValue(3),
												"someMap": structpb.NewStructValue(&structpb.Struct{
													Fields: map[string]*structpb.Value{
														"nestedAttr1": structpb.NewNumberValue(1),
														"nestedAttr2": structpb.NewNumberValue(2),
														"someSomeMap": structpb.NewStructValue(&structpb.Struct{
															Fields: map[string]*structpb.Value{
																"nestedNestedAttr1": structpb.NewNumberValue(1),
																"nestedNestedAttr2": structpb.NewNumberValue(1),
															},
														}),
													},
												}),
												"oneKeyMap": structpb.NewStructValue(&structpb.Struct{
													Fields: map[string]*structpb.Value{
														"nestedAttr1": structpb.NewNumberValue(1),
													},
												}),
												"someList": structpb.NewListValue(&structpb.ListValue{
													Values: []*structpb.Value{
														structpb.NewStringValue("index0"),
														structpb.NewStringValue("index1"),
													},
												}),
											},
										},
										Actions: []string{"a1", "a2"},
									},
									{
										RequestId: "2",
										Resource: &enginev1.Resource{
											Kind: "test:kind",
											Id:   "test",
										},
										Principal: &enginev1.Principal{
											Id:    "test",
											Roles: []string{"a", "b"},
											Attr: map[string]*structpb.Value{
												"attr1": structpb.NewNumberValue(1),
												"attr2": structpb.NewNumberValue(2),
												"attr3": structpb.NewNumberValue(3),
											},
										},
										Actions: []string{"a1", "a2"},
									},
								},
								Outputs: []*enginev1.CheckOutput{
									{
										RequestId:  "1",
										ResourceId: "test",
										Actions: map[string]*enginev1.CheckOutput_ActionEffect{
											"a1": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
											"a2": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
										},
									},
								},
								Error: "BOOM",
							},
						},
					},
				},
			},
		}

		masker, err := hub.NewAuditLogFilter(maskConf)
		require.NoError(t, err)

		wantRemoved := []string{
			"entries[0].access_log_entry.metadata.metadata_key_2",
			"entries[0].access_log_entry.peer.address",
			"entries[0].access_log_entry.peer.forwarded_for",

			"entries[1].decision_log_entry.metadata", // only one key existed and was removed
			"entries[1].decision_log_entry.peer.address",
			// we removed the first element by manipulating the slice, so the "changed" element is the removed, previously first one
			"entries[1].decision_log_entry.plan_resources.input.principal.attr.someList[-1]",
			"entries[1].decision_log_entry.plan_resources.input.principal.attr.someMap.nestedAttr1",
			"entries[1].decision_log_entry.plan_resources.output.filter_debug",

			"entries[2].decision_log_entry.check_resources.inputs[0].principal.attr.attr1",
			"entries[2].decision_log_entry.check_resources.inputs[0].principal.attr.attr2",
			"entries[2].decision_log_entry.check_resources.inputs[0].principal.attr.oneKeyMap", // sole key deletion results in entire map deletion
			// we removed the first element by manipulating the slice, so the "changed" element is the removed, previously first one
			"entries[2].decision_log_entry.check_resources.inputs[0].principal.attr.someList[-1]",
			"entries[2].decision_log_entry.check_resources.inputs[0].principal.attr.someMap.nestedAttr1",
			"entries[2].decision_log_entry.check_resources.inputs[0].principal.attr.someMap.someSomeMap.nestedNestedAttr1",
			"entries[2].decision_log_entry.check_resources.inputs[0].principal.id",
			"entries[2].decision_log_entry.check_resources.inputs[1].principal.attr.attr2",
			"entries[2].decision_log_entry.check_resources.outputs",
			"entries[2].decision_log_entry.peer.address",
		}

		ingestBatch := &logsv1.IngestBatch{
			Id:      "1",
			Entries: logEntries,
		}
		ingestBatchCopy := proto.Clone(ingestBatch).(*logsv1.IngestBatch)
		for _, entry := range ingestBatch.Entries {
			err = masker.Filter(entry)
			require.NoError(t, err)
		}

		require.Len(t, ingestBatch.Entries, len(logEntries))

		var r diffReporter
		cmp.Equal(ingestBatchCopy, ingestBatch, protocmp.Transform(), cmp.Reporter(&r))
		require.Equal(t, strings.Join(wantRemoved, "\n"), r.String())

		// `-1` only infers that an array item is missing. check the correct item is missing for each
		l := ingestBatch.Entries[1].GetDecisionLogEntry().GetPlanResources().Input.Principal.Attr["someList"].GetListValue().Values
		require.Len(t, l, 1)
		require.Equal(t, l[0].GetStringValue(), "index0") // we removed the second entry

		l = ingestBatch.Entries[2].GetDecisionLogEntry().GetCheckResources().Inputs[0].Principal.Attr["someList"].GetListValue().Values
		require.Len(t, l, 1)
		require.Equal(t, l[0].GetStringValue(), "index1")
	})

	t.Run("FilterWithWildcardTargets", func(t *testing.T) {
		now := time.Now()
		ts := timestamppb.New(now)

		maskConf := hub.MaskConf{
			Peer:           []string{"*"},
			Metadata:       []string{"*"},
			CheckResources: []string{"*"},
			PlanResources:  []string{"*"},
		}

		logEntry := &logsv1.IngestBatch_Entry{
			Kind:      logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
			Timestamp: ts,
			Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
				DecisionLogEntry: &auditv1.DecisionLogEntry{
					CallId:    "1",
					Timestamp: ts,
					Peer: &auditv1.Peer{
						Address:      "1.1.1.1",
						UserAgent:    "test-agent",
						ForwardedFor: "2.2.2.2",
					},
					Metadata: map[string]*auditv1.MetaValues{
						"test_key": {Values: []string{"test_value"}},
					},
					Method: &auditv1.DecisionLogEntry_CheckResources_{
						CheckResources: &auditv1.DecisionLogEntry_CheckResources{
							Inputs: []*enginev1.CheckInput{
								{
									RequestId: "check-1",
									Principal: &enginev1.Principal{
										Id: "test-principal",
										Attr: map[string]*structpb.Value{
											"test_attr": structpb.NewStringValue("test_value"),
										},
									},
									Resource: &enginev1.Resource{
										Kind: "test:kind",
										Id:   "test-resource",
										Attr: map[string]*structpb.Value{
											"test_attr": structpb.NewStringValue("test_value"),
										},
									},
									Actions: []string{"action1"},
								},
							},
							Outputs: []*enginev1.CheckOutput{
								{
									RequestId:  "check-1",
									ResourceId: "test-resource",
									Actions: map[string]*enginev1.CheckOutput_ActionEffect{
										"action1": {Effect: effectv1.Effect_EFFECT_ALLOW},
									},
								},
							},
						},
					},
				},
			},
		}

		planEntry := proto.Clone(logEntry).(*logsv1.IngestBatch_Entry)
		planEntry.GetDecisionLogEntry().Method = &auditv1.DecisionLogEntry_PlanResources_{
			PlanResources: &auditv1.DecisionLogEntry_PlanResources{
				Input: &enginev1.PlanResourcesInput{
					RequestId: "plan-1",
					Principal: &enginev1.Principal{
						Id: "test-principal",
						Attr: map[string]*structpb.Value{
							"test_attr": structpb.NewStringValue("test_value"),
						},
					},
					Resource: &enginev1.PlanResourcesInput_Resource{
						Kind: "test:kind",
						Attr: map[string]*structpb.Value{
							"test_attr": structpb.NewStringValue("test_value"),
						},
					},
					Action: "action1",
				},
				Output: &enginev1.PlanResourcesOutput{
					RequestId:   "plan-1",
					Action:      "action1",
					Kind:        "test:kind",
					FilterDebug: "debug info",
				},
			},
		}

		masker, err := hub.NewAuditLogFilter(maskConf)
		require.NoError(t, err)

		err = masker.Filter(logEntry)
		require.NoError(t, err)

		err = masker.Filter(planEntry)
		require.NoError(t, err)

		require.Empty(t, logEntry.GetDecisionLogEntry().Peer)
		require.Empty(t, logEntry.GetDecisionLogEntry().Metadata)
		require.Empty(t, logEntry.GetDecisionLogEntry().GetCheckResources())
		require.Empty(t, planEntry.GetDecisionLogEntry().GetPlanResources())
	})
}

type diffReporter struct {
	path  cmp.Path
	diffs []string
}

func (r *diffReporter) PushStep(ps cmp.PathStep) {
	r.path = append(r.path, ps)
}

func (r *diffReporter) Report(rs cmp.Result) {
	if !rs.Equal() {
		vx, vy := r.path.Last().Values()
		if vx.IsValid() && !vy.IsValid() {
			var b strings.Builder
			for _, step := range r.path {
				switch p := step.(type) {
				case cmp.MapIndex:
					k := fmt.Sprintf("%v", p.Key())
					switch k {
					case "list_value", "values", "string_value", "struct_value", "fields":
						continue
					}

					if b.Len() > 0 {
						b.WriteString(".")
					}

					b.WriteString(k)
				case cmp.SliceIndex:
					fmt.Fprintf(&b, "[%d]", p.Key())
				}
			}
			r.diffs = append(r.diffs, b.String())
		}
	}
}

func (r *diffReporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

func (r *diffReporter) String() string {
	return strings.Join(r.diffs, "\n")
}
