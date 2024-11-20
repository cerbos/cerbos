// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/engine/ruletable"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	hubstore "github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cloud-api/bundle"
)

// NOTE(saml) this is the max allowable path length on macOS, which appears to be the shortest of common platforms (at 104).
const udsMaxSocketPathLength = 104

type testParam struct {
	store        storage.Store
	policyLoader policyloader.PolicyLoader
	schemaMgr    schema.Manager
	ruletable    *ruletable.RuleTable
}

type testParamGen func(*testing.T) testParam

func TestServer(t *testing.T) {
	logging.InitLogging(context.Background(), "ERROR")

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

			rt := ruletable.NewRuleTable().WithPolicyLoader(policyLoader)

			rps, err := policyLoader.GetAll(ctx)
			require.NoError(t, err, "Failed to get all policies")

			err = rt.LoadPolicies(rps)
			require.NoError(t, err, "Failed to load policies into rule table")

			tp := testParam{
				store:        store,
				policyLoader: policyLoader,
				schemaMgr:    schemaMgr,
				ruletable:    rt,
			}
			return tp
		}

		t.Run("api", apiTests(tpg))
	})

	t.Run("store=bundle_local", func(t *testing.T) {
		tpg := func(version bundle.Version) func(t *testing.T) testParam {
			return func(t *testing.T) testParam {
				t.Helper()
				ctx, cancelFunc := context.WithCancel(context.Background())
				t.Cleanup(cancelFunc)

				dir := test.PathToDir(t, filepath.Join("bundle", fmt.Sprintf("v%d", version)))

				conf := &hubstore.Conf{
					BundleVersion: version,
					CacheSize:     1024,
					Local: &hubstore.LocalSourceConf{
						BundlePath: filepath.Join(dir, "bundle.crbp"),
						TempDir:    t.TempDir(),
					},
				}

				switch version {
				case bundle.Version1:
					keyBytes, err := os.ReadFile(filepath.Join(dir, "secret_key.txt"))
					require.NoError(t, err, "Failed to read secret key")

					conf.Credentials = &hub.CredentialsConf{WorkspaceSecret: string(bytes.TrimSpace(keyBytes))}
				case bundle.Version2:
					keyBytes, err := os.ReadFile(filepath.Join(dir, "encryption_key.txt"))
					require.NoError(t, err, "Failed to read encryption key")

					conf.Local.EncryptionKey = string(keyBytes)
				default:
				}

				store, err := hubstore.NewStore(ctx, conf)
				require.NoError(t, err)

				rt := ruletable.NewRuleTable().WithPolicyLoader(store)

				rps, err := store.GetAll(ctx)
				require.NoError(t, err, "Failed to get all policies")

				err = rt.LoadPolicies(rps)
				require.NoError(t, err, "Failed to load policies into rule table")

				schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
				tp := testParam{
					store:        store,
					policyLoader: store,
					schemaMgr:    schemaMgr,
					ruletable:    rt,
				}
				return tp
			}
		}

		t.Run("api", func(t *testing.T) {
			t.Run("bundlev1", apiTests(tpg(bundle.Version1)))
			t.Run("bundlev2", apiTests(tpg(bundle.Version2)))
		})
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
				tempDir := createTempDirForUDS(t)

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
				tempDir := createTempDirForUDS(t)

				conf := defaultConf()
				conf.HTTPListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))
				conf.GRPCListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))

				startServer(t, conf, tpg)

				t.Run("grpc", tr.RunGRPCTests(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			})
		})
	}
}

// createTempDirForUDS is used to generate a temporary directory with a pathname length below a defined limit.
// This is to prevent the randomly generated directory path length exceeding platform limits (104-108, platform specific).
func createTempDirForUDS(t *testing.T) string {
	t.Helper()

	osTempDir := os.TempDir()
	leafDirNameLen := 10
	// We fail early if the generated path is guaranteed to exceed the hard path length limit.
	// The `10` below accounts for the length of the string: `grpc.sock` (9), plus a single delimiter: `/`.
	if len(osTempDir)+leafDirNameLen+10 >= udsMaxSocketPathLength {
		t.Fatal("unable to create temp directory for UDS: socket path name length will exceed limit")
	}

	maxAttempts := 5
	for i := 0; i < maxAttempts; i++ {
		s, err := generateRandomString(leafDirNameLen)
		require.NoError(t, err, "failed to generate random string for UDS directory path")

		tmpPath := filepath.Join(osTempDir, s)
		if _, err := os.Stat(tmpPath); os.IsNotExist(err) {
			err = os.Mkdir(tmpPath, 0o700)
			require.NoError(t, err, "failed to create temp dir for UDS")

			t.Cleanup(func() {
				os.RemoveAll(tmpPath)
			})

			return tmpPath
		}
	}
	t.Fatal("unable to create temp directory for UDS")

	return ""
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, (length+1)/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	hash := hex.EncodeToString(bytes)[:length]
	return hash, nil
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
		RuleTable:         tp.ruletable,
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
