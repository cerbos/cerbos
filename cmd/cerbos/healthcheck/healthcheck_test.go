// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"path/filepath"
	"testing"

	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/stretchr/testify/require"
)

func TestBuildFromServerConf(t *testing.T) {
	testdataDir := test.PathToDir(t, "server")
	certPath := filepath.Join(testdataDir, "tls.crt")
	keyPath := filepath.Join(testdataDir, "tls.key")

	testCases := []struct {
		name     string
		cmd      *Cmd
		conf     *server.Conf
		wantAddr string
		wantErr  bool
	}{
		{
			name: "grpc/tls/secure",
			cmd:  &Cmd{Kind: "grpc"},
			conf: &server.Conf{
				HTTPListenAddr: ":3592",
				GRPCListenAddr: ":3593",
				TLS: &server.TLSConf{
					Cert: certPath,
					Key:  keyPath,
				},
			},
			wantAddr: ":3593",
		},
		{
			name: "grpc/tls/insecure",
			cmd:  &Cmd{Kind: "grpc", Insecure: true},
			conf: &server.Conf{
				HTTPListenAddr: ":3592",
				GRPCListenAddr: ":3593",
				TLS: &server.TLSConf{
					Cert: certPath,
					Key:  keyPath,
				},
			},
			wantAddr: ":3593",
		},
		{
			name: "grpc/no-tls",
			cmd:  &Cmd{Kind: "grpc"},
			conf: &server.Conf{
				HTTPListenAddr: ":3592",
				GRPCListenAddr: ":3593",
			},
			wantAddr: ":3593",
		},
		{
			name: "http/tls/secure",
			cmd:  &Cmd{Kind: "http"},
			conf: &server.Conf{
				HTTPListenAddr: ":3592",
				GRPCListenAddr: ":3593",
				TLS: &server.TLSConf{
					Cert: certPath,
					Key:  keyPath,
				},
			},
			wantAddr: "https://127.0.0.1:3592/_cerbos/health",
		},
		{
			name: "http/tls/insecure",
			cmd:  &Cmd{Kind: "http", Insecure: true},
			conf: &server.Conf{
				HTTPListenAddr: ":3592",
				GRPCListenAddr: ":3593",
				TLS: &server.TLSConf{
					Cert: certPath,
					Key:  keyPath,
				},
			},
			wantAddr: "https://127.0.0.1:3592/_cerbos/health",
		},
		{
			name: "http/no-tls",
			cmd:  &Cmd{Kind: "http"},
			conf: &server.Conf{
				HTTPListenAddr: ":3592",
				GRPCListenAddr: ":3593",
			},
			wantAddr: "http://127.0.0.1:3592/_cerbos/health",
		},
		{
			name: "http/specific-host",
			cmd:  &Cmd{Kind: "http"},
			conf: &server.Conf{
				HTTPListenAddr: "10.0.1.5:3592",
				GRPCListenAddr: ":3593",
			},
			wantAddr: "http://10.0.1.5:3592/_cerbos/health",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := tc.cmd.doBuildCheckFromConf(tc.conf)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.cmd.Kind == httpKind {
				hc, ok := have.(httpCheck)
				require.True(t, ok)
				require.Equal(t, tc.wantAddr, hc.url)
				if tc.conf.TLS != nil {
					require.NotNil(t, hc.tlsConf)
					require.Equal(t, tc.cmd.Insecure, hc.tlsConf.InsecureSkipVerify)
				}
				return
			}

			gc, ok := have.(grpcCheck)
			require.True(t, ok)
			require.Equal(t, tc.wantAddr, gc.addr)
			if tc.conf.TLS != nil {
				require.NotNil(t, gc.tlsConf)
				require.Equal(t, tc.cmd.Insecure, gc.tlsConf.InsecureSkipVerify)
			}
		})
	}
}

func TestBuildManual(t *testing.T) {
	testdataDir := test.PathToDir(t, "server")
	certPath := filepath.Join(testdataDir, "tls.crt")

	testCases := []struct {
		name     string
		cmd      *Cmd
		wantTLS  bool
		wantAddr string
		wantErr  bool
	}{
		{
			name:     "grpc/tls/secure",
			cmd:      &Cmd{Kind: "grpc"},
			wantTLS:  true,
			wantAddr: "127.0.0.1:3593",
		},
		{
			name:     "grpc/tls/insecure",
			cmd:      &Cmd{Kind: "grpc", Insecure: true, HostPort: "10.0.1.5:3593", CACert: certPath},
			wantTLS:  true,
			wantAddr: "10.0.1.5:3593",
		},
		{
			name:     "grpc/no-tls",
			cmd:      &Cmd{Kind: "grpc", HostPort: "10.0.1.5:3593", NoTLS: true},
			wantAddr: "10.0.1.5:3593",
		},
		{
			name:     "http/tls/secure",
			cmd:      &Cmd{Kind: "http"},
			wantTLS:  true,
			wantAddr: "https://127.0.0.1:3592/_cerbos/health",
		},
		{
			name:     "http/tls/insecure",
			cmd:      &Cmd{Kind: "http", Insecure: true, HostPort: "10.0.1.5:3592"},
			wantTLS:  true,
			wantAddr: "https://10.0.1.5:3592/_cerbos/health",
		},
		{
			name:     "http/no-tls",
			cmd:      &Cmd{Kind: "http", NoTLS: true},
			wantAddr: "http://127.0.0.1:3592/_cerbos/health",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := tc.cmd.doBuildCheckManual()
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.cmd.Kind == httpKind {
				hc, ok := have.(httpCheck)
				require.True(t, ok)
				require.Equal(t, tc.wantAddr, hc.url)
				if tc.wantTLS {
					require.NotNil(t, hc.tlsConf)
					require.Equal(t, tc.cmd.Insecure, hc.tlsConf.InsecureSkipVerify)
				}
				return
			}

			gc, ok := have.(grpcCheck)
			require.True(t, ok)
			require.Equal(t, tc.wantAddr, gc.addr)
			if tc.wantTLS {
				require.NotNil(t, gc.tlsConf)
				require.Equal(t, tc.cmd.Insecure, gc.tlsConf.InsecureSkipVerify)
			}
		})
	}
}
