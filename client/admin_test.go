// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestCollectLogs(t *testing.T) {
	t.Run("access logs", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) {
			return &responsev1.ListAuditLogEntriesResponse{Entry: &responsev1.ListAuditLogEntriesResponse_AccessLogEntry{
				AccessLogEntry: &auditv1.AccessLogEntry{CallId: "test"},
			}}, nil
		}

		logs, err := collectLogs(receiver)
		require.NoError(t, err)

		log := <-logs
		require.Equal(t, "test", log.accessLog.CallId)
		require.Empty(t, logs)
	})

	t.Run("return io.EOF directly", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) {
			return nil, io.EOF
		}

		logs, err := collectLogs(receiver)
		require.NoError(t, err)
		require.Empty(t, logs)
	})

	t.Run("error from receiver", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) { return nil, errors.New("test-error") }

		logs, err := collectLogs(receiver)
		require.NoError(t, err)

		log := <-logs
		al, err := log.AccessLog()
		require.Nil(t, al)
		require.Error(t, err)
	})
}

func TestAuditLogs(t *testing.T) {
	t.Run("should fail on invalid log options", func(t *testing.T) {
		c := GrpcAdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AuditLogs(context.Background(), AuditLogOptions{
			Type: AccessLogs,
			Tail: 10000,
		})

		require.Error(t, err)
	})

	t.Run("should fail if log type is different", func(t *testing.T) {
		c := GrpcAdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AuditLogs(context.Background(), AuditLogOptions{
			Type: AuditLogType(100),
			Tail: 10000,
		})

		require.Error(t, err)
	})
}

func TestListPolicies(t *testing.T) {
	const (
		adminUsername = "cerbos"
		adminPassword = "cerbosAdmin"
		timeout       = 15 * time.Second
	)

	serverOpts := []testutil.ServerOpt{
		testutil.WithPolicyRepositoryDatabase("sqlite3", fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))),
		testutil.WithAdminAPI(adminUsername, adminPassword),
	}

	s, err := testutil.StartCerbosServer(serverOpts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Stop()
	})

	ac, err := NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, WithPlaintext(), WithConnectTimeout(timeout))
	require.NoError(t, err)

	ps := NewPolicySet()
	testdataDir := test.PathToDir(t, "store")
	err = filepath.WalkDir(testdataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		ps.AddPolicyFromFile(path)
		return ps.Err()
	})

	require.NoError(t, err)
	require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))

	t.Run("should get the list of policies for a specific kind", func(t *testing.T) {
		opts := make([]FilterOpt, 0)
		opts = append(opts, WithKind(DerivedRolesPolicyKind))

		policies, err := ac.ListPolicies(context.Background(), opts...)

		require.NoError(t, err)
		require.NotEmpty(t, policies)
		require.IsType(t, &policyv1.Policy_DerivedRoles{}, policies[0].PolicyType)
	})

	t.Run("should get the list of polices with the version given", func(t *testing.T) {
		opts := make([]FilterOpt, 0)
		opts = append(opts, WithVersion("20210210"), WithKind(PrincipalPolicyKind), WithKind(ResourcePolicyKind))

		policies, err := ac.ListPolicies(context.Background(), opts...)

		require.NoError(t, err)
		require.NotEmpty(t, policies)
		for _, pol := range policies {
			switch p := pol.PolicyType.(type) {
			case *policyv1.Policy_ResourcePolicy:
				require.Equal(t, "20210210", p.ResourcePolicy.Version)
			case *policyv1.Policy_PrincipalPolicy:
				require.Equal(t, "20210210", p.PrincipalPolicy.Version)
			default:
				require.Failf(t, "invalid policy", "type: %T", p)
			}
		}
	})

	t.Run("should get error when requesting incorrect type and id", func(t *testing.T) {
		opts := make([]FilterOpt, 0)
		opts = append(opts, WithResourceName("gibberish"))
		opts = append(opts, WithKind(PrincipalPolicyKind))

		_, err := ac.ListPolicies(context.Background(), opts...)

		require.Error(t, err)
	})

	t.Run("should filter down with id and matched type", func(t *testing.T) {
		opts := make([]FilterOpt, 0)
		opts = append(opts, WithResourceName("gibberish"))
		opts = append(opts, WithKind(ResourcePolicyKind))
		opts = append(opts, WithKind(PrincipalPolicyKind))

		policies, err := ac.ListPolicies(context.Background(), opts...)

		require.NoError(t, err)
		require.NotEmpty(t, policies)
		require.IsType(t, &policyv1.Policy_PrincipalPolicy{}, policies[0].PolicyType)
	})
}
