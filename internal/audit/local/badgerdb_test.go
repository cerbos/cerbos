// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race
// +build !race

package local_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
)

const numRecords = 250_000

func TestBadgerLog(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conf := &local.Conf{
		StoragePath:     t.TempDir(),
		RetentionPeriod: 24 * time.Hour,
		Advanced: local.AdvancedConf{
			MaxBatchSize:  32,
			FlushInterval: 1 * time.Second,
		},
	}

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
	db, err := local.NewLog(conf, decisionFilter)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, local.Backend, db.Backend())
	require.True(t, db.Enabled())

	loadData(t, db, startDate)
	db.ForceWrite()

	t.Run("lastNAccessLogEntries", func(t *testing.T) {
		n := 100

		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		it := db.LastNAccessLogEntries(ctx, uint(n))

		counter := 0
		for {
			rec, err := it.Next()
			if err != nil {
				require.ErrorIs(t, err, audit.ErrIteratorClosed)
				break
			}

			require.Len(t, rec.Metadata, 1)
			require.Equal(t, strconv.Itoa(numRecords-counter-1), rec.Metadata["Num"].Values[0])

			counter++
		}

		require.Equal(t, n, counter)
	})

	t.Run("lastNDecisionLogEntries", func(t *testing.T) {
		n := 100

		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		it := db.LastNDecisionLogEntries(ctx, uint(n))

		counter := 0
		for {
			rec, err := it.Next()
			if err != nil {
				require.ErrorIs(t, err, audit.ErrIteratorClosed)
				break
			}

			haveEntry := rec.GetCheckResources()
			require.NotNil(t, haveEntry)
			require.Len(t, haveEntry.Inputs, 1)
			require.Equal(t, strconv.Itoa(numRecords-counter-1), haveEntry.Inputs[0].RequestId)

			counter++
		}

		require.Equal(t, n, counter)
	})

	t.Run("accessLogEntriesBetween", func(t *testing.T) {
		startTime := startDate.Add(100_000 * time.Second)
		endTime := startDate.Add(200_000 * time.Second)

		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		it := db.AccessLogEntriesBetween(ctx, startTime, endTime)

		counter := 0
		for {
			rec, err := it.Next()
			if err != nil {
				require.ErrorIs(t, err, audit.ErrIteratorClosed)
				break
			}

			haveReqTime := rec.Timestamp.AsTime()
			require.True(t, haveReqTime.Equal(startTime) || haveReqTime.After(startTime))
			require.True(t, haveReqTime.Equal(endTime) || haveReqTime.Before(endTime))

			counter++
		}

		require.Equal(t, 100_001, counter)
	})

	t.Run("decisionLogEntriesBetween", func(t *testing.T) {
		startTime := startDate.Add(100_000 * time.Second)
		endTime := startDate.Add(200_000 * time.Second)

		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		it := db.DecisionLogEntriesBetween(ctx, startTime, endTime)

		counter := 0
		for {
			rec, err := it.Next()
			if err != nil {
				require.ErrorIs(t, err, audit.ErrIteratorClosed)
				break
			}

			haveReqTime := rec.Timestamp.AsTime()
			require.True(t, haveReqTime.Equal(startTime) || haveReqTime.After(startTime))
			require.True(t, haveReqTime.Equal(endTime) || haveReqTime.Before(endTime))

			counter++
		}

		require.Equal(t, 100_001, counter)
	})

	t.Run("accessLogEntryByID", func(t *testing.T) {
		it := db.LastNAccessLogEntries(t.Context(), 1)
		wantRecord, err := it.Next()
		require.NoError(t, err)

		it = db.AccessLogEntryByID(t.Context(), audit.ID(wantRecord.CallId))
		haveRecord, err := it.Next()
		require.NoError(t, err)

		require.Empty(t, cmp.Diff(wantRecord, haveRecord, protocmp.Transform()))
	})

	t.Run("decisionLogEntryByID", func(t *testing.T) {
		it := db.LastNDecisionLogEntries(t.Context(), 1)
		wantRecord, err := it.Next()
		require.NoError(t, err)

		it = db.DecisionLogEntryByID(t.Context(), audit.ID(wantRecord.CallId))
		haveRecord, err := it.Next()
		require.NoError(t, err)

		require.Empty(t, cmp.Diff(wantRecord, haveRecord, protocmp.Transform()))
	})
}

func loadData(t *testing.T, db *local.Log, startDate time.Time) {
	t.Helper()

	ch := make(chan int, 100)
	g, ctx := errgroup.WithContext(t.Context())

	for i := 0; i < 100; i++ {
		g.Go(func() error {
			for x := range ch {
				ts := startDate.Add(time.Duration(x) * time.Second)
				id, err := audit.NewIDForTime(ts)
				if err != nil {
					return err
				}

				if err := db.WriteAccessLogEntry(ctx, mkAccessLogEntry(t, id, x, ts)); err != nil {
					return err
				}

				if err := db.WriteDecisionLogEntry(ctx, mkDecisionLogEntry(t, id, x, ts)); err != nil {
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
