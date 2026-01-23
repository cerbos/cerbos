// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package file_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/file"
)

const numRecords = 100_000

func TestLog(t *testing.T) {
	t.Parallel()

	testLogger := func(t *testing.T, log *file.Log, outputs ...string) {
		t.Helper()

		startDate := time.Now()

		require.Equal(t, file.Backend, log.Backend())
		require.True(t, log.Enabled())

		ch := make(chan int, 100)
		g, ctx := errgroup.WithContext(t.Context())

		for range 10 {
			g.Go(func() error {
				for x := range ch {
					ts := startDate.Add(time.Duration(x) * time.Second)
					id, err := audit.NewIDForTime(ts)
					if err != nil {
						return err
					}

					if err := log.WriteAccessLogEntry(ctx, mkAccessLogEntry(t, id, x, ts)); err != nil {
						return err
					}

					if err := log.WriteDecisionLogEntry(ctx, mkDecisionLogEntry(t, id, x, ts)); err != nil {
						return err
					}
				}

				return nil
			})
		}

		g.Go(func() error {
			defer close(ch)

			for i := range numRecords {
				if err := ctx.Err(); err != nil {
					return err
				}

				ch <- i
			}

			return nil
		})

		require.NoError(t, g.Wait())

		for _, o := range outputs {
			stat, err := os.Stat(o)
			require.NoError(t, err, "Failed to stat %s", o)
			require.True(t, stat.Size() > 0, "Audit log %s is empty", o)
		}
	}

	t.Run("minimal", func(t *testing.T) {
		t.Parallel()

		decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
		output := filepath.Join(t.TempDir(), "audit_x.log")
		log, err := file.NewLog(&file.Conf{
			Path: output,
		}, decisionFilter)
		require.NoError(t, err)

		t.Cleanup(func() {
			log.Close()
		})

		testLogger(t, log, output)
	})

	t.Run("additional_outputs", func(t *testing.T) {
		t.Parallel()

		decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
		tempDir := t.TempDir()
		output1 := filepath.Join(tempDir, "audit_x.log")
		output2 := filepath.Join(tempDir, "audit_y.log")
		log, err := file.NewLog(&file.Conf{
			Path:            output1,
			AdditionalPaths: []string{output2},
		}, decisionFilter)
		require.NoError(t, err)

		t.Cleanup(func() {
			log.Close()
		})

		testLogger(t, log, output1, output2)
	})

	t.Run("log_rotation", func(t *testing.T) {
		t.Parallel()

		decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
		tempDir := t.TempDir()
		output1 := filepath.Join(tempDir, "audit_x.log")
		output2 := filepath.Join(tempDir, "audit_y.log")
		log, err := file.NewLog(&file.Conf{
			Path:            output1,
			AdditionalPaths: []string{output2},
			LogRotation:     &file.LogRotationConf{MaxFileSizeMB: 10, MaxFileAgeDays: 1, MaxFileCount: 2},
		}, decisionFilter)
		require.NoError(t, err)

		t.Cleanup(func() {
			log.Close()
		})

		testLogger(t, log, output1, output2)
	})

	t.Run("format", func(t *testing.T) {
		t.Parallel()

		decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
		outPath := filepath.Join(t.TempDir(), "audit.log")
		log, err := file.NewLog(&file.Conf{Path: outPath}, decisionFilter)
		require.NoError(t, err)
		t.Cleanup(func() {
			log.Close()
		})

		ts := time.Now()
		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)

		require.NoError(t, log.WriteAccessLogEntry(t.Context(), mkAccessLogEntry(t, id, 42, ts)))

		require.NoError(t, log.WriteDecisionLogEntry(t.Context(), mkDecisionLogEntry(t, id, 42, ts)))

		require.NoError(t, log.Close())

		outFile, err := os.Open(outPath)
		require.NoError(t, err)
		t.Cleanup(func() {
			outFile.Close()
		})

		decoder := json.NewDecoder(outFile)

		tsEncoded := ts.UTC().Format("2006-01-02T15:04:05.000000000")
		tsEncoded = strings.TrimSuffix(tsEncoded, "000")
		tsEncoded = strings.TrimSuffix(tsEncoded, "000")
		tsEncoded = strings.TrimSuffix(tsEncoded, ".000")
		tsEncoded += "Z"

		haveAccessLogEntry := make(map[string]any)
		require.NoError(t, decoder.Decode(&haveAccessLogEntry))
		require.Equal(t, map[string]any{
			"log.logger": "cerbos.audit",
			"log.kind":   "access",
			"callId":     string(id),
			"timestamp":  tsEncoded,
			"metadata": map[string]any{
				"Num": map[string]any{"values": []any{"42"}},
			},
			"method": "/cerbos.svc.v1.CerbosService/Check",
			"peer":   map[string]any{"address": "1.1.1.1"},
			"requestContext": map[string]any{
				"annotations": map[string]any{
					"cerbos.dev/foo": "bar",
				},
			},
		}, haveAccessLogEntry)

		haveDecisionLogEntry := make(map[string]any)
		require.NoError(t, decoder.Decode(&haveDecisionLogEntry))
		require.Equal(t, map[string]any{
			"log.logger": "cerbos.audit",
			"log.kind":   "decision",
			"callId":     string(id),
			"timestamp":  tsEncoded,
			"inputs": []any{
				map[string]any{
					"requestId": "42",
					"resource": map[string]any{
						"kind": "test:kind",
						"id":   "test",
						"attr": map[string]any{
							"top": []any{
								map[string]any{
									"hello":  "world",
									"bottom": []any{float64(1), nil, true},
								},
							},
						},
					},
					"principal": map[string]any{
						"id":    "test",
						"roles": []any{"a", "b"},
					},
					"actions": []any{"a1", "a2"},
				},
			},
			"outputs": []any{
				map[string]any{
					"requestId":  "42",
					"resourceId": "test",
					"actions": map[string]any{
						"a1": map[string]any{
							"effect": "EFFECT_ALLOW",
							"policy": "resource.test.v1",
						},
						"a2": map[string]any{
							"effect": "EFFECT_ALLOW",
							"policy": "resource.test.v1",
						},
					},
				},
			},
			"requestContext": map[string]any{
				"annotations": map[string]any{
					"cerbos.dev/foo": "bar",
				},
			},
		}, haveDecisionLogEntry)
	})
}

func mkAccessLogEntry(t *testing.T, id audit.ID, i int, ts time.Time) audit.AccessLogEntryMaker {
	t.Helper()

	return func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId:    string(id),
			Timestamp: timestamppb.New(ts),
			Peer: &auditv1.Peer{
				Address: "1.1.1.1",
			},
			Metadata: map[string]*auditv1.MetaValues{"Num": {Values: []string{strconv.Itoa(i)}}},
			Method:   "/cerbos.svc.v1.CerbosService/Check",
			RequestContext: &auditv1.RequestContext{
				Annotations: map[string]*structpb.Value{"cerbos.dev/foo": structpb.NewStringValue("bar")},
			},
		}, nil
	}
}

func mkDecisionLogEntry(t *testing.T, id audit.ID, i int, ts time.Time) audit.DecisionLogEntryMaker {
	t.Helper()

	return func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId:    string(id),
			Timestamp: timestamppb.New(ts),
			Inputs: []*enginev1.CheckInput{
				{
					RequestId: strconv.Itoa(i),
					Resource: &enginev1.Resource{
						Kind: "test:kind",
						Id:   "test",
						Attr: map[string]*structpb.Value{
							"top": structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{
									structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"hello": structpb.NewStringValue("world"),
											"bottom": structpb.NewListValue(&structpb.ListValue{
												Values: []*structpb.Value{
													structpb.NewNumberValue(1),
													structpb.NewNullValue(),
													structpb.NewBoolValue(true),
												},
											}),
										},
									}),
								},
							}),
						},
					},
					Principal: &enginev1.Principal{
						Id:    "test",
						Roles: []string{"a", "b"},
					},
					Actions: []string{"a1", "a2"},
				},
			},
			Outputs: []*enginev1.CheckOutput{
				{
					RequestId:  strconv.Itoa(i),
					ResourceId: "test",
					Actions: map[string]*enginev1.CheckOutput_ActionEffect{
						"a1": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
						"a2": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
					},
				},
			},
			RequestContext: &auditv1.RequestContext{
				Annotations: map[string]*structpb.Value{"cerbos.dev/foo": structpb.NewStringValue("bar")},
			},
		}, nil
	}
}
