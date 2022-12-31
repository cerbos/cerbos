// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package testutil_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
)

var configYAML = `
server:
  httpListenAddr: 127.0.0.1:3592
  grpcListenAddr: 127.0.0.1:3593

storage:
  driver: sqlite3
  sqlite3:
    dsn: ":memory:"
`

func TestStartServer(t *testing.T) {
	certDir := test.PathToDir(t, "server")
	tlsCert := filepath.Join(certDir, "tls.crt")
	tlsKey := filepath.Join(certDir, "tls.key")

	policyDir := test.PathToDir(t, "store")
	tempDir := t.TempDir()

	check := func(s *testutil.ServerInfo) (bool, error) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancelFunc()
		return s.IsReady(ctx)
	}

	testCases := []struct {
		name string
		opt  testutil.ServerOpt
	}{
		{name: "None"},
		{name: "TLS", opt: testutil.WithTLSCertAndKey(tlsCert, tlsKey)},
		{name: "Policy Dir", opt: testutil.WithPolicyRepositoryDirectory(policyDir)},
		{name: "UDS gRPC", opt: testutil.WithGRPCListenAddr(fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")))},
		{name: "UDS HTTP", opt: testutil.WithHTTPListenAddr(fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")))},
		{name: "Admin API", opt: testutil.WithAdminAPI("test", "test")},
		{name: "Config Reader", opt: testutil.WithConfig(strings.NewReader(configYAML))},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s, err := testutil.StartCerbosServer(tc.opt)
			require.NoError(t, err)

			defer s.Stop() //nolint:errcheck

			var ready bool
			for i := 0; i < 5; i++ {
				ready, err = check(s)
				if ready {
					break
				}

				if i < 4 {
					sleepTime := time.Duration(100*(i+1)) * time.Millisecond
					time.Sleep(sleepTime)
				}
			}

			require.NoError(t, err)
			require.True(t, ready)
		})
	}
}
