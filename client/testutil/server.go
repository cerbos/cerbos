// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package testutil provides testing utilities such as functions to start a Cerbos server and tear it down.
// Deprecated: Use github.com/cerbos/cerbos-sdk-go/testutil instead.
package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"helm.sh/helm/v3/pkg/strvals"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	minConnectTimeout = 10 * time.Second
	maxRetries        = 3
	retryTimeout      = 2 * time.Second
)

type ServerOpt func(*serverOpt)

// WithConfig sets the source to read Cerbos configuration data.
func WithConfig(src io.Reader) ServerOpt {
	return func(so *serverOpt) {
		so.configSrc = src
	}
}

// WithConfigKeyValue sets the given config key to the provided value.
func WithConfigKeyValue(key, value string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride(key, value)
	}
}

// WithHTTPListenAddr sets the listener address for HTTP. Default is to find a random, unused port.
func WithHTTPListenAddr(httpListenAddr string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("server.httpListenAddr", httpListenAddr)
	}
}

// WithGRPCListenAddr sets the listener address for gRPC. Default is to find a random, unused port.
func WithGRPCListenAddr(grpcListenAddr string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("server.grpcListenAddr", grpcListenAddr)
	}
}

// WithTLSCertAndKey sets the TLS certificate and key to use. Defaults to no TLS.
func WithTLSCertAndKey(cert, key string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("server.tls.cert", cert)
		so.addOverride("server.tls.key", key)
	}
}

// WithTLSCACert sets the TLS CA certicate to use. Defaults to none.
func WithTLSCACert(caCert string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("server.tls.caCert", caCert)
	}
}

// WithAdminAPI enables the AdminAPI with the given username and password. Defaults to disabled.
func WithAdminAPI(username, password string) ServerOpt {
	return func(so *serverOpt) {
		hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			panic(fmt.Errorf("failed to generate hash for password: %w", err))
		}

		so.addOverride("server.adminAPI.enabled", "true")
		so.addOverride("server.adminAPI.adminCredentials.username", username)
		so.addOverride("server.adminAPI.adminCredentials.passwordHash", base64.StdEncoding.EncodeToString(hashBytes))
	}
}

// WithPolicyRepositoryDirectory sets the directory to use as the policy repository. Defaults to none.
// Cannot be used together with WithPolicyRepositorySQLite3.
func WithPolicyRepositoryDirectory(dir string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("storage.driver", "disk")
		so.addOverride("storage.disk.directory", dir)
	}
}

// WithPolicyRepositorySQLite3 sets the policy repository to the given SQLite3 database.
// Cannot be used together with WithPolicyRepositoryDirectory.
func WithPolicyRepositorySQLite3(dsn string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("storage.driver", sqlite3.DriverName)
		so.addOverride("storage.sqlite3.dsn", dsn)
	}
}

// WithDefaultPolicyVersion sets the default policy version to use when none is specified. Default to the "default".
func WithDefaultPolicyVersion(version string) ServerOpt {
	return func(so *serverOpt) {
		so.addOverride("engine.defaultPolicyVersion", version)
	}
}

type serverOpt struct {
	configSrc io.Reader
	overrides map[string]string
}

func (so *serverOpt) addOverride(key, value string) {
	if so.overrides == nil {
		so.overrides = make(map[string]string)
	}
	so.overrides[key] = value
}

func (so *serverOpt) toConfigWrapper() (*config.Wrapper, error) {
	confOverrides := map[string]any{}

	if so.configSrc == nil {
		defaults := map[string]string{
			"auxData.jwt.disableVerification": "true",
			"storage.driver":                  sqlite3.DriverName,
			"storage.sqlite3.dsn":             "file:cerbos.db?mode=memory&_fk=true",
		}

		httpAddr, err := util.GetFreeListenAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to find free listen address: %w", err)
		}
		defaults["server.httpListenAddr"] = httpAddr

		grpcAddr, err := util.GetFreeListenAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to find free listen address: %w", err)
		}
		defaults["server.grpcListenAddr"] = grpcAddr

		for k, v := range defaults {
			if err := strvals.ParseInto(fmt.Sprintf("%s=%s", k, v), confOverrides); err != nil {
				return nil, fmt.Errorf("failed to parse default config [%s=%s]: %w", k, v, err)
			}
		}
	}

	for k, v := range so.overrides {
		if err := strvals.ParseInto(fmt.Sprintf("%s=%s", k, v), confOverrides); err != nil {
			return nil, fmt.Errorf("failed to parse config override [%s=%s]: %w", k, v, err)
		}
	}

	if so.configSrc != nil {
		return config.WrapperFromReader(so.configSrc, confOverrides)
	}

	return config.WrapperFromMap(confOverrides)
}

// StartCerbosServer starts a new Cerbos server that can be used for testing a client integration locally with test data.
// If no options are passed, the server will be started with the http and gRPC endpoints available on a random free port
// and the storage backend configured to use an in-memory database. Use the methods on the returned ServerInfo object to
// find the listening addresses and stop the server when tests are done.
func StartCerbosServer(opts ...ServerOpt) (*ServerInfo, error) {
	sopt := &serverOpt{}
	for _, o := range opts {
		if o != nil {
			o(sopt)
		}
	}

	conf, err := sopt.toConfigWrapper()
	if err != nil {
		return nil, err
	}

	return startServer(conf)
}

func startServer(conf *config.Wrapper) (*ServerInfo, error) {
	ctx, cancelFunc := context.WithCancel(context.Background())

	sb := &serverBldr{ctx: ctx, conf: conf}
	sb.mkStore().mkAuditLog().mkAuxData().mkSchemaMgr().mkPolicyLoader().mkEngine().mkServer()
	if sb.err != nil {
		cancelFunc()
		return nil, sb.err
	}

	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		return sb.server.Start(ctx, server.Param{Store: sb.store, Engine: sb.engine, AuditLog: sb.auditLog, AuxData: sb.auxData})
	})
	runtime.Gosched()

	return &ServerInfo{conf: sb.serverConf, g: g, cancelFunc: cancelFunc}, nil
}

type serverBldr struct {
	ctx               context.Context
	conf              *config.Wrapper
	store             storage.Store
	auditLog          audit.Log
	auxData           *auxdata.AuxData
	schemaMgr         schema.Manager
	policyLoader      engine.PolicyLoader
	engine            *engine.Engine
	serverConf        *server.Conf
	server            *server.Server
	err               error
	metadataExtractor audit.MetadataExtractor
}

func (sb *serverBldr) mkStore() *serverBldr {
	if sb.err != nil {
		return sb
	}

	sb.store, sb.err = storage.NewFromConf(sb.ctx, sb.conf)
	return sb
}

func (sb *serverBldr) mkAuditLog() *serverBldr {
	if sb.err != nil {
		return sb
	}

	sb.auditLog, sb.err = audit.NewLogFromConf(sb.ctx, sb.conf)
	if sb.err == nil {
		auditConf := new(audit.Conf)
		if err := sb.conf.GetSection(auditConf); err != nil {
			sb.err = fmt.Errorf("failed to load audit configuration: %w", err)
			return sb
		}

		sb.metadataExtractor = audit.NewMetadataExtractorFromConf(auditConf)
	}
	return sb
}

func (sb *serverBldr) mkAuxData() *serverBldr {
	if sb.err != nil {
		return sb
	}

	adConf := new(auxdata.Conf)
	if err := sb.conf.GetSection(adConf); err != nil {
		sb.err = fmt.Errorf("failed to load auxData configuration: %w", err)
		return sb
	}

	sb.auxData = auxdata.NewFromConf(sb.ctx, adConf)
	return sb
}

func (sb *serverBldr) mkSchemaMgr() *serverBldr {
	if sb.err != nil {
		return sb
	}

	schemaConf := new(schema.Conf)
	if err := sb.conf.GetSection(schemaConf); err != nil {
		sb.err = fmt.Errorf("failed to load schema configuration: %w", err)
		return sb
	}

	sb.schemaMgr = schema.NewFromConf(sb.ctx, sb.store, schemaConf)
	return sb
}

func (sb *serverBldr) mkPolicyLoader() *serverBldr {
	if sb.err != nil {
		return sb
	}

	if bs, ok := sb.store.(storage.BinaryStore); ok {
		sb.policyLoader = bs
		return sb
	}

	if ss, ok := sb.store.(storage.SourceStore); ok {
		compileConf := new(compile.Conf)
		if err := sb.conf.GetSection(compileConf); err != nil {
			sb.err = fmt.Errorf("failed to load compile configuration: %w", err)
			return sb
		}

		sb.policyLoader = compile.NewManagerFromConf(sb.ctx, compileConf, ss, sb.schemaMgr)
		return sb
	}

	sb.err = server.ErrInvalidStore
	return sb
}

func (sb *serverBldr) mkEngine() *serverBldr {
	if sb.err != nil {
		return sb
	}

	engineConf := new(engine.Conf)
	if err := sb.conf.GetSection(engineConf); err != nil {
		sb.err = fmt.Errorf("failed to load engine configuration: %w", err)
		return sb
	}

	sb.engine = engine.NewFromConf(sb.ctx, engineConf, engine.Components{
		PolicyLoader:      sb.policyLoader,
		SchemaMgr:         sb.schemaMgr,
		AuditLog:          sb.auditLog,
		MetadataExtractor: sb.metadataExtractor,
	})

	return sb
}

func (sb *serverBldr) mkServer() *serverBldr {
	if sb.err != nil {
		return sb
	}

	sb.serverConf = new(server.Conf)
	if err := sb.conf.GetSection(sb.serverConf); err != nil {
		sb.err = fmt.Errorf("failed to load server configuration: %w", err)
		return sb
	}

	sb.server = server.NewServer(sb.serverConf)
	return sb
}

type ServerInfo struct {
	conf       *server.Conf
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
	return s.conf.HTTPListenAddr
}

// GRPCAddr returns the GRPC listen address of the running server.
func (s *ServerInfo) GRPCAddr() string {
	return s.conf.GRPCListenAddr
}

// IsReady returns true if the server health check is successful.
func (s *ServerInfo) IsReady(ctx context.Context) (bool, error) {
	conn, err := mkGRPCConn(ctx, s.conf)
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

func mkGRPCConn(ctx context.Context, serverConf *server.Conf) (grpc.ClientConnInterface, error) {
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
	if conf := serverConf.TLS; conf != nil {
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

	return grpc.DialContext(ctx, serverConf.GRPCListenAddr, dialOpts...)
}
