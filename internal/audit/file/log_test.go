// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package file_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
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

		for i := 0; i < 10; i++ {
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

			for i := 0; i < numRecords; i++ {
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
		}, nil
	}
}
