// Copyright 2021 Zenauth Ltd.

package testutil_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
)

func TestStartServerInvalidOptions(t *testing.T) {
	testCases := []struct {
		name string
		opts []testutil.ServerOpt
	}{
		{
			name: "Empty TLS cert",
			opts: []testutil.ServerOpt{testutil.WithTLSCertAndKey("", "test.key")},
		},
		{
			name: "Empty TLS key",
			opts: []testutil.ServerOpt{testutil.WithTLSCertAndKey("test.crt", "")},
		},
		{
			name: "Unsupported database driver",
			opts: []testutil.ServerOpt{testutil.WithPolicyRepositoryDatabase("cockroachdb", "dsn")},
		},
		{
			name: "Both repository dir and database specified",
			opts: []testutil.ServerOpt{
				testutil.WithPolicyRepositoryDatabase("sqlite3", ":memory:"),
				testutil.WithPolicyRepositoryDirectory("/tmp"),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s, err := testutil.StartCerbosServer(tc.opts...)
			require.Error(t, err)
			require.Nil(t, s)
		})
	}
}

func TestStartServer(t *testing.T) {
	certDir := test.PathToDir(t, "server")
	tlsCert := filepath.Join(certDir, "tls.crt")
	tlsKey := filepath.Join(certDir, "tls.key")

	policyDir := test.PathToDir(t, "store")

	s, err := testutil.StartCerbosServer(testutil.WithPolicyRepositoryDirectory(policyDir), testutil.WithTLSCertAndKey(tlsCert, tlsKey))
	require.NoError(t, err)

	defer s.Stop()

	check := func() (bool, error) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancelFunc()
		return s.IsReady(ctx)
	}

	var ready bool
	for i := 0; i < 5; i++ {
		ready, err = check()
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
}
