// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
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
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/bundle"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

type testParam struct {
	store        storage.Store
	policyLoader engine.PolicyLoader
	schemaMgr    schema.Manager
}

type testParamGen func(*testing.T) testParam

func TestServer(t *testing.T) {
	t.Run("store=disk", func(t *testing.T) {
		tpg := func(t *testing.T) testParam {
			t.Helper()
			ctx, cancelFunc := context.WithCancel(context.Background())
			t.Cleanup(cancelFunc)

			dir := test.PathToDir(t, "store")
			store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
			require.NoError(t, err)

			schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
			policyLoader := compile.NewManagerFromDefaultConf(ctx, store, schemaMgr)

			tp := testParam{
				store:        store,
				policyLoader: policyLoader,
				schemaMgr:    schemaMgr,
			}
			return tp
		}

		t.Run("api", apiTests(tpg))
	})

	t.Run("store=bundle_local", func(t *testing.T) {
		tpg := func(t *testing.T) testParam {
			t.Helper()
			ctx, cancelFunc := context.WithCancel(context.Background())
			t.Cleanup(cancelFunc)

			dir := test.PathToDir(t, "bundle")

			keyBytes, err := os.ReadFile(filepath.Join(dir, "secret_key.txt"))
			require.NoError(t, err, "Failed to read secret key")

			conf := &bundle.Conf{
				Credentials: bundle.CredentialsConf{SecretKey: string(bytes.TrimSpace(keyBytes))},
				Local: &bundle.LocalSourceConf{
					BundlePath: filepath.Join(dir, "bundle.crbp"),
					TempDir:    t.TempDir(),
				},
			}
			store, err := bundle.NewStore(ctx, conf)
			require.NoError(t, err)

			schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
			tp := testParam{
				store:        store,
				policyLoader: store,
				schemaMgr:    schemaMgr,
			}
			return tp
		}

		t.Run("api", apiTests(tpg))
	})
}

func apiTests(tpg testParamGen) func(*testing.T) {
	return func(t *testing.T) {
		tr := LoadTestCases(t, "checks", "playground", "plan_resources")

		t.Run("with_tls", func(t *testing.T) {
			testdataDir := test.PathToDir(t, "server")

			t.Run("tcp", func(t *testing.T) {
				conf := defaultConf()
				conf.HTTPListenAddr = getFreeListenAddr(t)
				conf.GRPCListenAddr = getFreeListenAddr(t)
				conf.TLS = &TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				}

				startServer(t, conf, tpg)

				tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

				t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
				t.Run("grpc_over_http", tr.RunGRPCTests(conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
				t.Run("http", tr.RunHTTPTests(fmt.Sprintf("https://%s", conf.HTTPListenAddr), nil))
			})

			t.Run("uds", func(t *testing.T) {
				tempDir := t.TempDir()

				conf := defaultConf()
				conf.HTTPListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))
				conf.GRPCListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))
				conf.TLS = &TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				}

				startServer(t, conf, tpg)

				tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

				t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
				t.Run("grpc_over_http", tr.RunGRPCTests(conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			})
		})

		t.Run("without_tls", func(t *testing.T) {
			t.Run("tcp", func(t *testing.T) {
				conf := defaultConf()
				conf.HTTPListenAddr = getFreeListenAddr(t)
				conf.GRPCListenAddr = getFreeListenAddr(t)

				startServer(t, conf, tpg)

				t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
				t.Run("h2c", tr.RunGRPCTests(conf.HTTPListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
				t.Run("http", tr.RunHTTPTests(fmt.Sprintf("http://%s", conf.HTTPListenAddr), nil))
			})

			t.Run("uds", func(t *testing.T) {
				tempDir := t.TempDir()

				conf := defaultConf()
				conf.HTTPListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))
				conf.GRPCListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))

				startServer(t, conf, tpg)

				t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			})
		})
	}
}

func TestAdminService(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()

		ctx, cancelFunc := context.WithCancel(context.Background())
		t.Cleanup(cancelFunc)

		store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))})
		require.NoError(t, err)

		schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
		policyLoader := compile.NewManagerFromDefaultConf(ctx, store, schemaMgr)

		tp := testParam{
			store:        store,
			policyLoader: policyLoader,
			schemaMgr:    schemaMgr,
		}
		return tp
	}

	testdataDir := test.PathToDir(t, "server")
	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.TLS = &TLSConf{
		Cert: filepath.Join(testdataDir, "tls.crt"),
		Key:  filepath.Join(testdataDir, "tls.key"),
	}
	conf.AdminAPI = AdminAPIConf{
		Enabled: true,
		AdminCredentials: &AdminCredentialsConf{
			Username:     "cerbos",
			PasswordHash: base64.StdEncoding.EncodeToString([]byte("$2y$10$yOdMOoQq6g7s.ogYRBDG3e2JyJFCyncpOEmkEyV.mNGKNyg68uPZS")),
		},
	}

	startServer(t, conf, tpg)

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

func startServer(t *testing.T, conf *Conf, tpg testParamGen) {
	t.Helper()

	tp := tpg(t)

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	auditLog := audit.NewNopLog()
	auxData := auxdata.NewFromConf(ctx, &auxdata.Conf{JWT: &auxdata.JWTConf{
		KeySets: []auxdata.JWTKeySet{
			{
				ID:    "cerbos",
				Local: &auxdata.LocalSource{File: filepath.Join(test.PathToDir(t, "auxdata"), "verify_key.jwk")},
			},
		},
	}})

	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader:      tp.policyLoader,
		SchemaMgr:         tp.schemaMgr,
		AuditLog:          auditLog,
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})
	require.NoError(t, err, "Failed to create engine")

	param := Param{AuditLog: auditLog, AuxData: auxData, Store: tp.store, Engine: eng}

	s := NewServer(conf)
	go func() {
		if err := s.Start(ctx, param); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
}

func defaultConf() *Conf {
	conf := &Conf{}
	conf.SetDefaults()

	conf.RequestLimits = RequestLimitsConf{
		MaxActionsPerResource:  5,
		MaxResourcesPerRequest: 5,
	}
	conf.PlaygroundEnabled = true

	return conf
}
