// Copyright 2021 Zenauth Ltd.

package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/audit"
	auditv1 "github.com/cerbos/cerbos/internal/genpb/audit/v1"
)

func TestNopLog(t *testing.T) {
	log := audit.NewNopLog()

	t.Run("writeAccessLogEntry", func(t *testing.T) {
		recordMakerCalled := false
		err := log.WriteAccessLogEntry(context.Background(), func() (*auditv1.AccessLogEntry, error) {
			recordMakerCalled = true
			return &auditv1.AccessLogEntry{}, nil
		})
		require.NoError(t, err)
		require.False(t, recordMakerCalled)
	})

	t.Run("writeDecisionLogEntry", func(t *testing.T) {
		recordMakerCalled := false
		err := log.WriteDecisionLogEntry(context.Background(), func() (*auditv1.DecisionLogEntry, error) {
			recordMakerCalled = true
			return &auditv1.DecisionLogEntry{}, nil
		})
		require.NoError(t, err)
		require.False(t, recordMakerCalled)
	})

	t.Run("lastNAccessLogEntries", func(t *testing.T) {
		it := log.LastNAccessLogEntries(context.Background(), 10)
		require.NotNil(t, it)

		rec, err := it.Next()
		require.Nil(t, rec)
		require.ErrorIs(t, err, audit.ErrIteratorClosed)
	})

	t.Run("lastNDecisionLogEntries", func(t *testing.T) {
		it := log.LastNDecisionLogEntries(context.Background(), 10)
		require.NotNil(t, it)

		rec, err := it.Next()
		require.Nil(t, rec)
		require.ErrorIs(t, err, audit.ErrIteratorClosed)
	})

	t.Run("accessLogEntriesBetween", func(t *testing.T) {
		it := log.AccessLogEntriesBetween(context.Background(), time.Now(), time.Now().Add(1*time.Hour))
		require.NotNil(t, it)

		rec, err := it.Next()
		require.Nil(t, rec)
		require.ErrorIs(t, err, audit.ErrIteratorClosed)
	})

	t.Run("decisionLogEntriesBetween", func(t *testing.T) {
		it := log.DecisionLogEntriesBetween(context.Background(), time.Now(), time.Now().Add(1*time.Hour))
		require.NotNil(t, it)

		rec, err := it.Next()
		require.Nil(t, rec)
		require.ErrorIs(t, err, audit.ErrIteratorClosed)
	})
}
