// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
)

func TestNopLog(t *testing.T) {
	log := audit.NewNopLog()

	t.Run("writeAccessLogEntry", func(t *testing.T) {
		recordMakerCalled := false
		err := log.WriteAccessLogEntry(t.Context(), func() (*auditv1.AccessLogEntry, error) {
			recordMakerCalled = true
			return &auditv1.AccessLogEntry{}, nil
		})
		require.NoError(t, err)
		require.False(t, recordMakerCalled)
	})

	t.Run("writeDecisionLogEntry", func(t *testing.T) {
		recordMakerCalled := false
		err := log.WriteDecisionLogEntry(t.Context(), func() (*auditv1.DecisionLogEntry, error) {
			recordMakerCalled = true
			return &auditv1.DecisionLogEntry{}, nil
		})
		require.NoError(t, err)
		require.False(t, recordMakerCalled)
	})

	t.Run("close", func(_ *testing.T) {
		log.Close()
	})
}
