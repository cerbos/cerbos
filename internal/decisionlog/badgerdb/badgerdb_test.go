// Copyright 2021 Zenauth Ltd.

// +build !race

package badgerdb_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cerbos/internal/decisionlog/badgerdb"
	decisionlogv1 "github.com/cerbos/cerbos/internal/genpb/decisionlog/v1"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	"github.com/cerbos/cerbos/internal/test"
)

const numRecords = 250_000

func TestBadgerDB(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conf := &badgerdb.Conf{
		StoragePath:     t.TempDir(),
		RetentionPeriod: 24 * time.Hour,
		Advanced: &badgerdb.AdvancedConf{
			MaxPendingTransactions: 32,
			FlushInterval:          1 * time.Second,
		},
	}

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	db, err := badgerdb.NewLog(conf)
	require.NoError(t, err)

	loadData(t, db, startDate)
	db.Close()

	// re-open the db
	db, err = badgerdb.NewLog(conf)
	require.NoError(t, err)

	defer db.Close()

	t.Run("listLastN", func(t *testing.T) {
		n := 100

		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		it, err := db.ListLastN(ctx, uint(n))
		require.NoError(t, err)

		counter := 0
		for rec := range it {
			require.NoError(t, rec.Err, "Unexpected error on record %d", counter)
			require.NotNil(t, rec.Decision, "Nil decision on record %d", counter)

			wantID := fmt.Sprintf("request_%07d", numRecords-counter)
			require.Equal(t, wantID, rec.Decision.RequestId, "Unexpected request ID on record %d", counter)

			counter++
		}

		require.Equal(t, n, counter)
	})

	t.Run("listBetweenTimestamps", func(t *testing.T) {
		startTime := startDate.Add(100_000 * time.Second)
		endTime := startDate.Add(200_000 * time.Second)

		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		it, err := db.ListBetweenTimestamps(ctx, startTime, endTime)
		require.NoError(t, err)

		counter := 0
		for rec := range it {
			require.NoError(t, rec.Err, "Unexpected error on record %d", counter)
			require.NotNil(t, rec.Decision, "Nil decision on record %d", counter)

			wantID := fmt.Sprintf("request_%07d", 100_000+counter)
			require.Equal(t, wantID, rec.Decision.RequestId, "Unexpected request ID on record %d", counter)

			haveReqTime := rec.Decision.RequestTime.AsTime()
			require.True(t, haveReqTime.Equal(startTime) || haveReqTime.After(startTime))
			require.True(t, haveReqTime.Equal(endTime) || haveReqTime.Before(endTime))

			counter++
		}

		require.Equal(t, 100_001, counter)
	})

	t.Run("listBetweenTimestamps_NoRecords", func(t *testing.T) {
		startTime := time.Now()
		endTime := time.Now().Add(24 * time.Hour)

		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		it, err := db.ListBetweenTimestamps(ctx, startTime, endTime)
		require.NoError(t, err)

		counter := 0
		for range it {
			counter++
		}

		require.Equal(t, 0, counter)
	})
}

func loadData(t *testing.T, db *badgerdb.Log, startDate time.Time) {
	t.Helper()

	for i := 1; i <= numRecords; i++ {
		rec := mkRecord(t, i, startDate.Add(time.Duration(i)*time.Second))
		require.NoError(t, db.Add(context.Background(), rec))
	}
}

func mkRecord(t *testing.T, i int, ts time.Time) *decisionlogv1.Decision {
	t.Helper()

	rp := test.GenResourcePolicy(test.NoMod())
	return &decisionlogv1.Decision{
		RequestTime: timestamppb.New(ts),
		RequestId:   fmt.Sprintf("request_%07d", i),
		Request: &decisionlogv1.RequestPayload{
			Payload: &decisionlogv1.RequestPayload_AddOrUpdatePolicy{
				AddOrUpdatePolicy: &requestv1.AddOrUpdatePolicyRequest{
					Policies: []*policyv1.Policy{rp},
				},
			},
		},
		Response: &decisionlogv1.ResponsePayload{
			Payload: &decisionlogv1.ResponsePayload_AddOrUpdatePolicy{
				AddOrUpdatePolicy: &responsev1.AddOrUpdatePolicyResponse{
					Success: &emptypb.Empty{},
				},
			},
		},
	}
}
