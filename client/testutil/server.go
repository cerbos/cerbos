// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package testutil provides testing utilities such as functions to start a Cerbos server and tear it down.
package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/postgres"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	minConnectTimeout = 10 * time.Second
	maxRetries        = 3
	retryTimeout      = 2 * time.Second
)

type ServerOpt func(*serverOpt)

// WithHTTPListenAddr sets the listener address for HTTP. Default is to find a random, unused port.
func WithHTTPListenAddr(httpListenAddr string) ServerOpt {
	return func(so *serverOpt) {
		so.serverConf.HTTPListenAddr = httpListenAddr
	}
}

// WithGRPCListenAddr sets the listener address for gRPC. Default is to find a random, unused port.
func WithGRPCListenAddr(grpcListenAddr string) ServerOpt {
	return func(so *serverOpt) {
		so.serverConf.GRPCListenAddr = grpcListenAddr
	}
}

// WithTLSCertAndKey sets the TLS certificate and key to use. Defaults to no TLS.
func WithTLSCertAndKey(cert, key string) ServerOpt {
	return func(so *serverOpt) {
		if so.serverConf.TLS == nil {
			so.serverConf.TLS = &server.TLSConf{}
		}
		so.serverConf.TLS.Cert = cert
		so.serverConf.TLS.Key = key
	}
}

// WithTLSCACert sets the TLS CA certicate to use. Defaults to none.
func WithTLSCACert(caCert string) ServerOpt {
	return func(so *serverOpt) {
		if so.serverConf.TLS == nil {
			so.serverConf.TLS = &server.TLSConf{}
		}
		so.serverConf.TLS.CACert = caCert
	}
}

// WithAdminAPI enables the AdminAPI with the given username and password. Defaults to disabled.
func WithAdminAPI(username, password string) ServerOpt {
	return func(so *serverOpt) {
		hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			panic(fmt.Errorf("failed to generate hash for password: %w", err))
		}

		so.serverConf.AdminAPI.Enabled = true
		so.serverConf.AdminAPI.AdminCredentials = &server.AdminCredentialsConf{
			Username:     username,
			PasswordHash: base64.StdEncoding.EncodeToString(hashBytes),
		}
	}
}

// WithPolicyRepositoryDirectory sets the directory to use as the policy repository. Defaults to none.
// Cannot be used together with WithPolicyRepositoryDatabase.
func WithPolicyRepositoryDirectory(dir string) ServerOpt {
	return func(so *serverOpt) {
		so.policyRepoDir = dir
	}
}

// WithPolicyRepositoryDatabase sets the database to use as the policy repository. Defaults to SQLite3 in-memory database.
// Cannot be used together with WithPolicyRepositoryDirectory. Currently only 'sqlite3' is supported.
func WithPolicyRepositoryDatabase(driver, connStr string) ServerOpt {
	return func(so *serverOpt) {
		so.policyRepoDBDriver = driver
		so.policyRepoDBConnStr = connStr
	}
}

// WithDefaultPolicyVersion sets the default policy version to use when none is specified. Default to the "default".
func WithDefaultPolicyVersion(version string) ServerOpt {
	return func(so *serverOpt) {
		so.defaultPolicyVersion = version
	}
}

// WithPlaygroundAPI enables the Playground API. Defaults to disabled.
func WithPlaygroundAPI() ServerOpt {
	return func(so *serverOpt) {
		so.serverConf.PlaygroundEnabled = true
	}
}

type serverOpt struct {
	serverConf           *server.Conf
	defaultPolicyVersion string
	policyRepoDir        string
	policyRepoDBDriver   string
	policyRepoDBConnStr  string
}

func (so *serverOpt) setDefaultsAndValidate() error {
	if so.serverConf.HTTPListenAddr == "" {
		addr, err := util.GetFreeListenAddr()
		if err != nil {
			return fmt.Errorf("failed to find free listen address: %w", err)
		}
		so.serverConf.HTTPListenAddr = addr
	}

	if so.serverConf.GRPCListenAddr == "" {
		addr, err := util.GetFreeListenAddr()
		if err != nil {
			return fmt.Errorf("failed to find free listen address: %w", err)
		}
		so.serverConf.GRPCListenAddr = addr
	}

	if so.serverConf.TLS != nil {
		if so.serverConf.TLS.Cert == "" || so.serverConf.TLS.Key == "" {
			return errors.New("invalid TLS configuration: both TLS certificate and key must be specified")
		}
	}

	if so.policyRepoDir != "" && so.policyRepoDBConnStr != "" {
		return errors.New("only one of PolicyRepositoryDirectory or PolicyRepositoryDatabase is allowed")
	}

	// if none is specified, default to in-mem db.
	if so.policyRepoDir == "" && so.policyRepoDBConnStr == "" {
		so.policyRepoDBDriver = "sqlite3"
		so.policyRepoDBConnStr = ":memory:"
	}

	return nil
}

func (so *serverOpt) mkGRPCConn(ctx context.Context) (grpc.ClientConnInterface, error) {
	dialOpts := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: minConnectTimeout}),
		grpc.WithChainStreamInterceptor(
			grpc_retry.StreamClientInterceptor(
				grpc_retry.WithMax(maxRetries),
				grpc_retry.WithPerRetryTimeout(retryTimeout),
			),
		),
		grpc.WithChainUnaryInterceptor(
			grpc_retry.UnaryClientInterceptor(
				grpc_retry.WithMax(maxRetries),
				grpc_retry.WithPerRetryTimeout(retryTimeout),
			),
		),
	}

	//nolint:nestif
	if conf := so.serverConf.TLS; conf != nil {
		certificate, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate and key: %w", err)
		}

		tlsConfig := util.DefaultTLSConfig()
		tlsConfig.Certificates = []tls.Certificate{certificate}
		tlsConfig.InsecureSkipVerify = true

		if conf.CACert != "" {
			certPool := x509.NewCertPool()
			bs, err := os.ReadFile(conf.CACert)
			if err != nil {
				return nil, fmt.Errorf("failed to load CA certificate: %w", err)
			}

			ok := certPool.AppendCertsFromPEM(bs)
			if !ok {
				return nil, errors.New("failed to append certificates to the pool")
			}

			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			tlsConfig.ClientCAs = certPool
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(local.NewCredentials()))
	}

	return grpc.DialContext(ctx, so.serverConf.GRPCListenAddr, dialOpts...)
}

// StartCerbosServer starts a new Cerbos server that can be used for testing a client integration locally with test data.
// If no options are passed, the server will be started with the http and gRPC endpoints available on a random free port
// and the storage backend configured to use an in-memory database. Use the methods on the returned ServerInfo object to
// find the listening addresses and stop the server when tests are done.
func StartCerbosServer(opts ...ServerOpt) (*ServerInfo, error) {
	sopt := &serverOpt{serverConf: &server.Conf{}}
	for _, o := range opts {
		if o != nil {
			o(sopt)
		}
	}

	if err := sopt.setDefaultsAndValidate(); err != nil {
		return nil, err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	g, _ := errgroup.WithContext(ctx)
	if err := startServer(ctx, g, sopt); err != nil {
		cancelFunc()
		return nil, err
	}

	return &ServerInfo{sopt: sopt, g: g, cancelFunc: cancelFunc}, nil
}

func startServer(ctx context.Context, g *errgroup.Group, sopt *serverOpt) (err error) {
	var store storage.Store
	if sopt.policyRepoDir != "" {
		store, err = disk.NewStore(ctx, &disk.Conf{Directory: sopt.policyRepoDir})
	} else {
		switch sopt.policyRepoDBDriver {
		case sqlite3.DriverName:
			store, err = sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: sopt.policyRepoDBConnStr})
		case postgres.DriverName:
			store, err = postgres.NewStore(ctx, &postgres.Conf{URL: sopt.policyRepoDBConnStr})
		default:
			err = fmt.Errorf("unknown database driver: %s", sopt.policyRepoDBDriver)
		}
	}

	if err != nil {
		return err
	}

	auditLog := audit.NewNopLog()
	auxData := auxdata.NewWithoutVerification(ctx)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), auditLog)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	s := server.NewServer(sopt.serverConf)
	g.Go(func() error {
		return s.Start(ctx, server.Param{Store: store, Engine: eng, AuditLog: auditLog, AuxData: auxData})
	})
	runtime.Gosched()

	return nil
}

type ServerInfo struct {
	sopt       *serverOpt
	g          *errgroup.Group
	cancelFunc context.CancelFunc
}

// Stop the running server.
func (s *ServerInfo) Stop() error {
	s.cancelFunc()
	return s.g.Wait()
}

// HTTPAddr returns the HTTP listen address of the running server.
func (s *ServerInfo) HTTPAddr() string {
	return s.sopt.serverConf.HTTPListenAddr
}

// GRPCAddr returns the GRPC listen address of the running server.
func (s *ServerInfo) GRPCAddr() string {
	return s.sopt.serverConf.GRPCListenAddr
}

// IsReady returns true if the server health check is successful.
func (s *ServerInfo) IsReady(ctx context.Context) (bool, error) {
	conn, err := s.sopt.mkGRPCConn(ctx)
	if err != nil {
		return false, err
	}

	hc := healthpb.NewHealthClient(conn)
	resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: svcv1.CerbosService_ServiceDesc.ServiceName})
	if err != nil {
		return false, err
	}

	switch resp.Status {
	case healthpb.HealthCheckResponse_SERVING, healthpb.HealthCheckResponse_UNKNOWN:
		return true, nil
	default:
		return false, nil
	}
}
