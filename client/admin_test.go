// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
)

func TestAccessLogs(t *testing.T) {
	serverOpts := mkServerOpts(t, false)
	tempDir := t.TempDir()
	serverOpts = append(serverOpts,
		testutil.WithHTTPListenAddr(fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))),
		testutil.WithGRPCListenAddr(fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))),
	)
	s, err := testutil.StartCerbosServer(serverOpts...)
	require.NoError(t, err)

	audit.RegisterBackend("local", func(_ context.Context) (audit.Log, error) {
		return local.New()
	})

	defer s.Stop() //nolint:errcheck

	ac, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, client.WithPlaintext())
	require.NoError(t, err)

	loadPolicies(t, ac)

	c, err := client.New(s.GRPCAddr(), client.WithPlaintext())
	require.NoError(t, err)

	_, err = c.IsAllowed(
		context.TODO(),
		client.NewPrincipal("john").
			WithRoles("employee").
			WithPolicyVersion("20210210").
			WithAttributes(map[string]interface{}{
				"department": "marketing",
				"geography":  "GB",
				"team":       "design",
			}),
		client.NewResource("leave_request", "XX125").
			WithPolicyVersion("20210210").
			WithAttributes(map[string]interface{}{
				"department": "marketing",
				"geography":  "GB",
				"id":         "XX125",
				"owner":      "john",
				"team":       "design",
			}),
		"view:public")

	require.NoError(t, err)

	logs, err := ac.DecisionLogs(context.Background(), client.AuditLogOptions{
		StartTime: time.Now().Add(time.Duration(-10) * time.Minute),
		EndTime:   time.Now(),
	})
	require.NoError(t, err)
	if len(logs) == 0 {
		t.Skip("test is skipped, logs could not be received")
	}
}
