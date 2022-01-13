// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestServer(t *testing.T) {
	dir := test.PathToDir(t, "store")
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	auditLog := audit.NewNopLog()
	auxData := auxdata.NewFromConf(ctx, &auxdata.Conf{JWT: &auxdata.JWTConf{
		KeySets: []auxdata.JWTKeySet{
			{
				ID:    "cerbos",
				Local: &auxdata.LocalSource{File: filepath.Join(test.PathToDir(t, "auxdata"), "verify_key.jwk")},
			},
		},
	}})

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	schemaMgr := schema.NewWithConf(ctx, store, &schema.Conf{Enforcement: schema.EnforcementReject})

	eng, err := engine.New(ctx, engine.Components{
		CompileMgr: compile.NewManager(ctx, store, schemaMgr),
		SchemaMgr:  schemaMgr,
		AuditLog:   auditLog,
	})
	require.NoError(t, err)

	param := Param{AuditLog: auditLog, AuxData: auxData, Store: store, Engine: eng}

	tr := LoadTestCases(t, "checks", "playground", "plan_resources")

	t.Run("with_tls", func(t *testing.T) {
		testdataDir := test.PathToDir(t, "server")

		t.Run("tcp", func(t *testing.T) {
			conf := &Conf{
				HTTPListenAddr: getFreeListenAddr(t),
				GRPCListenAddr: getFreeListenAddr(t),
				TLS: &TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				},
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, param)

			tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

			t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("grpc_over_http", tr.RunGRPCTests(conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("http", tr.RunHTTPTests(fmt.Sprintf("https://%s", conf.HTTPListenAddr), nil))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &Conf{
				HTTPListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
				TLS: &TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				},
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, param)

			tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

			t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("grpc_over_http", tr.RunGRPCTests(conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
		})
	})

	t.Run("without_tls", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {
			conf := &Conf{
				HTTPListenAddr:    getFreeListenAddr(t),
				GRPCListenAddr:    getFreeListenAddr(t),
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, param)

			t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			t.Run("h2c", tr.RunGRPCTests(conf.HTTPListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			t.Run("http", tr.RunHTTPTests(fmt.Sprintf("http://%s", conf.HTTPListenAddr), nil))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &Conf{
				HTTPListenAddr:    fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr:    fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, param)

			t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
		})
	})
}

func TestAdminService(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	auditLog := audit.NewNopLog()
	auxData := auxdata.NewFromConf(ctx, &auxdata.Conf{JWT: &auxdata.JWTConf{
		KeySets: []auxdata.JWTKeySet{
			{
				ID:    "cerbos",
				Local: &auxdata.LocalSource{File: filepath.Join(test.PathToDir(t, "auxdata"), "verify_key.jwk")},
			},
		},
	}})

	store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))})
	require.NoError(t, err)

	schemaMgr := schema.NewWithConf(ctx, store, &schema.Conf{Enforcement: schema.EnforcementReject})

	eng, err := engine.New(ctx, engine.Components{
		CompileMgr: compile.NewManager(ctx, store, schemaMgr),
		SchemaMgr:  schemaMgr,
		AuditLog:   auditLog,
	})
	require.NoError(t, err)

	testdataDir := test.PathToDir(t, "server")
	conf := &Conf{
		HTTPListenAddr: getFreeListenAddr(t),
		GRPCListenAddr: getFreeListenAddr(t),
		TLS: &TLSConf{
			Cert: filepath.Join(testdataDir, "tls.crt"),
			Key:  filepath.Join(testdataDir, "tls.key"),
		},
		AdminAPI: AdminAPIConf{
			Enabled: true,
			AdminCredentials: &AdminCredentialsConf{
				Username:     "cerbos",
				PasswordHash: base64.StdEncoding.EncodeToString([]byte("$2y$10$yOdMOoQq6g7s.ogYRBDG3e2JyJFCyncpOEmkEyV.mNGKNyg68uPZS")),
			},
		},
	}

	startServer(ctx, conf, Param{Store: store, Engine: eng, AuditLog: auditLog, AuxData: auxData})

	tr := LoadTestCases(t, "admin", "checks")
	creds := &AuthCreds{Username: "cerbos", Password: "cerbosAdmin"}

	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
	t.Run("http", tr.RunHTTPTests(fmt.Sprintf("https://%s", conf.HTTPListenAddr), creds))
}

func getFreeListenAddr(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "Failed to create listener")

	addr := lis.Addr().String()
	lis.Close()

	return addr
}

func startServer(ctx context.Context, conf *Conf, param Param) {
	s := NewServer(conf)
	go func() {
		if err := s.Start(ctx, param); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
}
