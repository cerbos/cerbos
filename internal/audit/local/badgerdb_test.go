// Copyright 2021 Zenauth Ltd.

// +build !race

package local_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	auditv1 "github.com/cerbos/cerbos/internal/genpb/audit/v1"
	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
)

const numRecords = 250_000

var payload [2048]byte

func TestBadgerLog(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conf := &local.Conf{
		StoragePath:     t.TempDir(),
		RetentionPeriod: 24 * time.Hour,
		Advanced: &local.AdvancedConf{
			MaxPendingTransactions: 32,
			FlushInterval:          1 * time.Second,
		},
	}

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	db, err := local.NewLog(conf)
	require.NoError(t, err)

	loadData(t, db, startDate)
	db.Close()

	// re-open the db
	db, err = local.NewLog(conf)
	require.NoError(t, err)

	defer db.Close()

	t.Run("lastNAccessLogEntries", func(t *testing.T) {
		n := 100

		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		it := db.LastNAccessLogEntries(ctx, uint(n))

		counter := 0
		for {
			rec, err := it.Next()
			if err != nil {
				require.ErrorIs(t, err, audit.ErrIteratorClosed)
				break
			}

			require.Len(t, rec.Meta, 1)
			require.Equal(t, strconv.Itoa(numRecords-counter), rec.Meta[0].Value)

			counter++
		}

		require.Equal(t, n, counter)
	})

	t.Run("lastNDecisionLogEntries", func(t *testing.T) {
		n := 100

		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		it := db.LastNDecisionLogEntries(ctx, uint(n))

		counter := 0
		for {
			rec, err := it.Next()
			if err != nil {
				require.ErrorIs(t, err, audit.ErrIteratorClosed)
				break
			}

			require.Len(t, rec.Inputs, 1)
			require.Equal(t, strconv.Itoa(numRecords-counter), rec.Inputs[0].RequestId)

			counter++
		}

		require.Equal(t, n, counter)
	})

	t.Run("accessLogEntriesBetween", func(t *testing.T) {
		startTime := startDate.Add(100_000 * time.Second)
		endTime := startDate.Add(200_000 * time.Second)

		ctx, cancelFunc := context.WithCancel(context.Background())
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

		ctx, cancelFunc := context.WithCancel(context.Background())
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
}

func loadData(t *testing.T, db *local.Log, startDate time.Time) {
	t.Helper()

	for i := 1; i <= numRecords; i++ {
		ts := startDate.Add(time.Duration(i) * time.Second)
		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)
		require.NoError(t, db.WriteAccessLogEntry(context.Background(), mkAccessLogEntry(t, id, i, ts)))
		require.NoError(t, db.WriteDecisionLogEntry(context.Background(), mkDecisionLogEntry(t, id, i, ts)))
	}
}

func mkAccessLogEntry(t *testing.T, id audit.ID, i int, ts time.Time) audit.AccessLogEntryMaker {
	t.Helper()

	return func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId:    id[:],
			Timestamp: timestamppb.New(ts),
			Peer: &auditv1.Address{
				Type:    auditv1.Address_TYPE_IPV4,
				Address: "1.1.1.1",
			},
			Meta: []*auditv1.Metadata{
				{Key: "Num", Value: strconv.Itoa(i)},
			},
			Method:          "/svc.v1.CerbosService/Check",
			RequestPayload:  payload[:],
			ResponsePayload: payload[:],
		}, nil
	}
}

func mkDecisionLogEntry(t *testing.T, id audit.ID, i int, ts time.Time) audit.DecisionLogEntryMaker {
	t.Helper()

	return func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId:    id[:],
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
						"a1": {Effect: sharedv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
						"a2": {Effect: sharedv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
					},
				},
			},
		}, nil
	}
}
