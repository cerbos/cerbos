// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/certinel/fswatcher"
	"github.com/gorilla/mux"
	grpc_logging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	grpc_validator "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	reuseport "github.com/kavu/go_reuseport"
	"github.com/sourcegraph/conc/pool"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/admin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/metadata"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/telemetry"
	"github.com/cerbos/cerbos/internal/validator"

	// Import the default grpc encoding to ensure that it gets replaced by VT.
	_ "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/encoding/protojson"

	// Import to register the Badger audit log backend.
	_ "github.com/cerbos/cerbos/internal/audit/local"
	// Import to register the file audit log backend.
	_ "github.com/cerbos/cerbos/internal/audit/file"
	// Import to register the kafka audit log backend.
	_ "github.com/cerbos/cerbos/internal/audit/kafka"
	// Import to register the hub audit log backend.
	_ "github.com/cerbos/cerbos/internal/audit/hub"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	internalSchema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"

	// Import blob to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/storage/overlay"

	// Import hub to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/hub"
	// Import mysql to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/mysql"
	// Import postgres to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/postgres"
	// Import sqlite3 to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	// Import sqlserver to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/sqlserver"
	// Import disk to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/disk"
	// Import git to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/git"
	"github.com/cerbos/cerbos/internal/svc"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/schema"
)

const (
	defaultTimeout           = 30 * time.Second
	metricsReportingInterval = 15 * time.Second
	minGRPCConnectTimeout    = 20 * time.Second

	adminEndpoint      = "/admin"
	apiEndpoint        = "/api"
	healthEndpoint     = "/_cerbos/health"
	metricsEndpoint    = "/_cerbos/metrics"
	playgroundEndpoint = "/api/playground"
	schemaEndpoint     = "/schema/swagger.json"
)

var ErrInvalidStore = errors.New("store does not implement either SourceStore or BinaryStore interfaces")

func Start(ctx context.Context) error {
	// get configuration
	conf, err := GetConf()
	if err != nil {
		return fmt.Errorf("failed to load server configuration: %w", err)
	}

	// create audit log
	auditLog, err := audit.NewLog(ctx)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	mdExtractor, err := audit.NewMetadataExtractor()
	if err != nil {
		return fmt.Errorf("failed to create metadata extractor: %w", err)
	}

	// create store
	store, err := storage.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}

	// create schema manager
	schemaMgr, err := internalSchema.New(ctx, store)
	if err != nil {
		return fmt.Errorf("failed to create schema manager: %w", err)
	}

	var policyLoader engine.PolicyLoader
	switch st := store.(type) {
	// Overlay needs to take precedence over BinaryStore in this type switch,
	// as our overlay store implements BinaryStore also
	case overlay.Overlay:
		// create wrapped policy loader
		pl, err := st.GetOverlayPolicyLoader(ctx, schemaMgr)
		if err != nil {
			return fmt.Errorf("failed to create overlay policy loader: %w", err)
		}
		policyLoader = pl
	case storage.BinaryStore:
		policyLoader = st
	case storage.SourceStore:
		// create compile manager
		compileMgr, err := compile.NewManager(ctx, st, schemaMgr)
		if err != nil {
			return fmt.Errorf("failed to create compile manager: %w", err)
		}
		policyLoader = compileMgr
	default:
		return ErrInvalidStore
	}

	// create engine
	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader:      policyLoader,
		SchemaMgr:         schemaMgr,
		AuditLog:          auditLog,
		MetadataExtractor: mdExtractor,
	})
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// initialize aux data
	auxData, err := auxdata.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize auxData handler: %w", err)
	}

	s := NewServer(conf)

	telemetry.Start(ctx, store)
	defer telemetry.Stop()

	return s.Start(ctx, Param{AuditLog: auditLog, AuxData: auxData, Engine: eng, Store: store})
}

type Param struct {
	AuditLog audit.Log
	AuxData  *auxdata.AuxData
	Engine   *engine.Engine
	Store    storage.Store
}

type Server struct {
	conf       *Conf
	cancelFunc context.CancelFunc
	pool       *pool.ContextPool
	health     *health.Server
	tlsConfig  *tls.Config
}

func NewServer(conf *Conf) *Server {
	return &Server{
		conf:   conf,
		health: health.NewServer(),
	}
}

func (s *Server) Start(ctx context.Context, param Param) error {
	ctx, cancelFunc := context.WithCancel(ctx)
	s.pool = pool.New().WithContext(ctx).WithCancelOnError().WithFirstError()
	s.cancelFunc = cancelFunc

	defer s.cancelFunc()

	log := zap.L().Named("server")
	if err := s.initializeTLSConfig(log); err != nil {
		log.Error("Failed to initialize TLS configuration", zap.Error(err))
	}

	// It would be nice to have a single port to serve both gRPC and HTTP. Unfortunately, cmux
	// can't deal effectively with both gRPC and HTTP/2 when TLS is enabled (see https://github.com/soheilhy/cmux/issues/68).
	// Another potential issue with single-port gRPC and HTTP/2 is when a proxy like Envoy is in front of the server it
	// would have a connection pool per port and would end up sending HTTP/2 traffic to gRPC and vice-versa.
	// This is why we have two dedicated ports for HTTP and gRPC traffic. However, if gRPC traffic is sent to the HTTP port, it
	// will still be handled correctly.

	grpcL, err := s.createListener(s.conf.GRPCListenAddr)
	if err != nil {
		log.Error("Failed to create gRPC listener", zap.Error(err))
		return err
	}

	httpL, err := s.createListener(s.conf.HTTPListenAddr)
	if err != nil {
		log.Error("Failed to create HTTP listener", zap.Error(err))
		return err
	}

	// start servers
	grpcServer, err := s.startGRPCServer(grpcL, param)
	if err != nil {
		log.Error("Failed to start GRPC server", zap.Error(err))
		return err
	}

	httpServer, err := s.startHTTPServer(ctx, httpL, grpcServer)
	if err != nil {
		log.Error("Failed to start HTTP server", zap.Error(err))
		return err
	}

	s.pool.Go(func(ctx context.Context) error {
		<-ctx.Done()
		log.Info("Shutting down")

		// mark this service as NOT_SERVING in the gRPC health check.
		s.health.Shutdown()

		log.Debug("Shutting down gRPC server")
		grpcServer.GracefulStop()

		log.Debug("Shutting down HTTP server")
		shutdownCtx, cancelFunc := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancelFunc()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Error("Failed to cleanly shutdown HTTP server", zap.Error(err))
		}

		return nil
	})

	if err := s.pool.Wait(); err != nil {
		log.Error("Stopping server due to error", zap.Error(err))
		return err
	}

	log.Debug("Shutting down the audit log")
	if err := param.AuditLog.Close(); err != nil {
		log.Error("Failed to cleanly close audit log", zap.Error(err))
	}

	if closer, ok := param.Store.(io.Closer); ok {
		log.Debug("Shutting down store")
		if err := closer.Close(); err != nil {
			log.Error("Store didn't shutdown correctly", zap.Error(err))
		}
	}

	log.Info("Shutdown complete")
	return nil
}

func (s *Server) initializeTLSConfig(log *zap.Logger) error {
	if s.conf.TLS == nil || (s.conf.TLS.Cert == "" || s.conf.TLS.Key == "") {
		return nil
	}
	conf := s.conf.TLS

	certinel, err := fswatcher.New(conf.Cert, conf.Key)
	if err != nil {
		return fmt.Errorf("failed to load certificate and key: %w", err)
	}

	s.pool.Go(func(ctx context.Context) (outErr error) {
		log.Info("Starting certificate watcher")
		if err := certinel.Start(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Error("Stopping certificate watcher due to error", zap.Error(err))
				return err
			}
		}

		log.Info("Stopping certificate watcher")
		return nil
	})

	s.tlsConfig = util.DefaultTLSConfig()
	s.tlsConfig.GetCertificate = certinel.GetCertificate

	if conf.CACert != "" {
		if _, err := os.Stat(conf.CACert); err != nil {
			//nolint:nilerr
			return nil
		}

		certPool := x509.NewCertPool()
		bs, err := os.ReadFile(conf.CACert)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}

		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return errors.New("failed to append certificates to the pool")
		}

		s.tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		s.tlsConfig.ClientCAs = certPool
	}

	return nil
}

func (s *Server) createListener(listenAddr string) (net.Listener, error) {
	l, err := s.parseAndOpen(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener at '%s': %w", listenAddr, err)
	}

	if s.tlsConfig != nil {
		l = tls.NewListener(l, s.tlsConfig)
	}

	return l, nil
}

func (s *Server) startGRPCServer(l net.Listener, param Param) (*grpc.Server, error) {
	log := zap.L().Named("grpc")
	server, err := s.mkGRPCServer(log, param.AuditLog)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC server: %w", err)
	}

	healthpb.RegisterHealthServer(server, s.health)
	reflection.Register(server)

	reqLimits := svc.RequestLimits{
		MaxActionsPerResource:  s.conf.RequestLimits.MaxActionsPerResource,
		MaxResourcesPerRequest: s.conf.RequestLimits.MaxResourcesPerRequest,
	}

	cerbosSvc := svc.NewCerbosService(param.Engine, param.AuxData, reqLimits)
	svcv1.RegisterCerbosServiceServer(server, cerbosSvc)
	s.health.SetServingStatus(svcv1.CerbosService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	if s.conf.AdminAPI.Enabled {
		log.Info("Starting admin service")
		creds := s.conf.AdminAPI.AdminCredentials

		adminUser, adminPasswdHash, err := creds.usernameAndPasswordHash()
		if err != nil {
			log.Error("Failed to get admin API credentials", zap.Error(err))
			return nil, err
		}

		go checkForUnsafeAdminCredentials(log, adminPasswdHash)

		svcv1.RegisterCerbosAdminServiceServer(server, svc.NewCerbosAdminService(param.Store, param.AuditLog, adminUser, adminPasswdHash))
		s.health.SetServingStatus(svcv1.CerbosAdminService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	}

	if s.conf.PlaygroundEnabled {
		log.Info("Starting playground service")
		svcv1.RegisterCerbosPlaygroundServiceServer(server, svc.NewCerbosPlaygroundService(reqLimits))
		s.health.SetServingStatus(svcv1.CerbosPlaygroundService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	}

	s.pool.Go(func(_ context.Context) error {
		log.Info(fmt.Sprintf("Starting gRPC server at %s", s.conf.GRPCListenAddr))

		cleanup, err := admin.Register(server)
		if err != nil {
			log.Error("Failed to register gRPC admin interfaces", zap.Error(err))
			return err
		}
		defer cleanup()

		if err := server.Serve(l); err != nil {
			log.Error("gRPC server failed", zap.Error(err))
			return err
		}

		log.Info("gRPC server stopped")
		return nil
	})

	return server, nil
}

func checkForUnsafeAdminCredentials(log *zap.Logger, passwordHash []byte) {
	unsafe, err := adminCredentialsAreUnsafe(passwordHash)
	if err != nil {
		log.Error("Failed to check admin API credentials", zap.Error(err))
	} else if unsafe {
		log.Warn("[INSECURE CONFIG] Admin API uses default credentials which are unsafe for production use. Please change the credentials by updating the configuration file.")
	}
}

func (s *Server) mkGRPCServer(log *zap.Logger, auditLog audit.Log) (*grpc.Server, error) {
	telemetryInt := telemetry.Intercept()

	auditInterceptor, err := audit.NewUnaryInterceptor(auditLog, accessLogExclude)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit unary interceptor: %w", err)
	}

	opts := []grpc.ServerOption{
		grpc.ChainStreamInterceptor(
			grpc_recovery.StreamServerInterceptor(),
			telemetryInt.StreamServerInterceptor(),
			grpc_validator.StreamServerInterceptor(validator.Validator),
			grpc_logging.StreamServerInterceptor(RequestLogger(log, "Handled request")),
			grpc_logging.StreamServerInterceptor(PayloadLogger(s.conf), grpc_logging.WithLogOnEvents(grpc_logging.PayloadReceived, grpc_logging.PayloadSent)),
		),
		grpc.ChainUnaryInterceptor(
			grpc_recovery.UnaryServerInterceptor(),
			telemetryInt.UnaryServerInterceptor(),
			grpc_validator.UnaryServerInterceptor(validator.Validator),
			RequestMetadataUnaryServerInterceptor,
			auditInterceptor,
			grpc_logging.UnaryServerInterceptor(RequestLogger(log, "Handled request")),
			grpc_logging.UnaryServerInterceptor(PayloadLogger(s.conf), grpc_logging.WithLogOnEvents(grpc_logging.PayloadReceived, grpc_logging.PayloadSent)),
			cerbosVersionUnaryServerInterceptor,
		),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: s.conf.Advanced.GRPC.MaxConnectionAge}),
		grpc.MaxConcurrentStreams(s.conf.Advanced.GRPC.MaxConcurrentStreams),
		grpc.ConnectionTimeout(s.conf.Advanced.GRPC.ConnectionTimeout),
		grpc.MaxRecvMsgSize(int(s.conf.Advanced.GRPC.MaxRecvMsgSizeBytes)),
		grpc.UnknownServiceHandler(handleUnknownServices),
	}

	return grpc.NewServer(opts...), nil
}

func (s *Server) startHTTPServer(ctx context.Context, l net.Listener, grpcSrv *grpc.Server) (*http.Server, error) {
	log := zap.S().Named("http")

	grpcConn, err := s.mkGRPCConn()
	if err != nil {
		return nil, err
	}

	gwmux := runtime.NewServeMux(
		runtime.WithForwardResponseOption(customHTTPResponseCode),
		runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher),
		runtime.WithMarshalerOption("application/json+pretty", &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{Indent: "  "},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}),
		runtime.WithMetadata(setPeerMetadata),
		runtime.WithRoutingErrorHandler(handleRoutingError),
		runtime.WithHealthEndpointAt(healthpb.NewHealthClient(grpcConn), healthEndpoint),
	)

	if err := svcv1.RegisterCerbosServiceHandler(ctx, gwmux, grpcConn); err != nil {
		log.Errorw("Failed to register Cerbos HTTP service", "error", err)
		return nil, fmt.Errorf("failed to register Cerbos HTTP service: %w", err)
	}

	if s.conf.AdminAPI.Enabled {
		if err := svcv1.RegisterCerbosAdminServiceHandler(ctx, gwmux, grpcConn); err != nil {
			log.Errorw("Failed to register Cerbos admin HTTP service", "error", err)
			return nil, fmt.Errorf("failed to register Cerbos admin HTTP service: %w", err)
		}
	}

	if s.conf.PlaygroundEnabled {
		if err := svcv1.RegisterCerbosPlaygroundServiceHandler(ctx, gwmux, grpcConn); err != nil {
			log.Errorw("Continuing without playground due to registration error", "error", err)
		}
	}

	cerbosMux := mux.NewRouter()
	// handle gRPC requests that come over http
	cerbosMux.MatcherFunc(func(r *http.Request, _ *mux.RouteMatch) bool {
		return r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc")
	}).Handler(tracing.HTTPHandler(grpcSrv, "grpc"))

	cerbosMux.PathPrefix(adminEndpoint).Handler(tracing.HTTPHandler(prettyJSON(gwmux), adminEndpoint))
	cerbosMux.PathPrefix(apiEndpoint).Handler(tracing.HTTPHandler(prettyJSON(gwmux), apiEndpoint))
	cerbosMux.Path(healthEndpoint).Handler(prettyJSON(gwmux))
	cerbosMux.Path(schemaEndpoint).HandlerFunc(schema.ServeSvcSwagger)

	if s.conf.MetricsEnabled {
		h, err := metrics.NewHandler()
		if err != nil {
			return nil, fmt.Errorf("failed to create Prometheus handler: %w", err)
		}
		cerbosMux.Path(metricsEndpoint).Handler(h)
	}

	if s.conf.APIExplorerEnabled {
		cerbosMux.HandleFunc("/", schema.ServeUI)
	}

	httpHandler := withCORS(s.conf, cerbosMux)

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           h2c.NewHandler(httpHandler, &http2.Server{}),
		ReadHeaderTimeout: s.conf.Advanced.HTTP.ReadHeaderTimeout,
		ReadTimeout:       s.conf.Advanced.HTTP.ReadTimeout,
		WriteTimeout:      s.conf.Advanced.HTTP.WriteTimeout,
		IdleTimeout:       s.conf.Advanced.HTTP.IdleTimeout,
	}

	s.pool.Go(func(_ context.Context) error {
		log.Infof("Starting HTTP server at %s", s.conf.HTTPListenAddr)
		err := h.Serve(l)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorw("HTTP server failed", "error", err)
			return err
		}

		log.Info("HTTP server stopped")
		return nil
	})

	return h, nil
}

func defaultGRPCDialOpts() []grpc.DialOption {
	// see https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md
	return []grpc.DialOption{
		grpc.WithUserAgent("grpc-gateway"),
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: minGRPCConnectTimeout}),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
}

func (s *Server) mkGRPCConn() (*grpc.ClientConn, error) {
	opts := defaultGRPCDialOpts()

	if s.tlsConfig != nil {
		tlsConf := s.tlsConfig.Clone()
		tlsConf.InsecureSkipVerify = true // we are connecting as localhost which would differ from what the cert is issued for.
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(local.NewCredentials()))
	}

	grpcConn, err := util.EagerGRPCClient(s.conf.GRPCListenAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, nil
}

// inspired by https://github.com/ghostunnel/ghostunnel/blob/6e58c75c8762fe371c1134e89dd55033a6d577a4/socket/net.go#L100
func (s *Server) parseAndOpen(listenAddr string) (net.Listener, error) {
	network, addr, err := util.ParseListenAddress(listenAddr)
	if err != nil {
		return nil, err
	}

	//nolint:nestif
	if network == "unix" {
		if err := os.RemoveAll(addr); err != nil {
			return nil, err
		}

		listener, err := net.Listen(network, addr)
		if err != nil {
			return nil, err
		}

		if s.conf.UDSFileMode != defaultUDSFileMode {
			fileMode := toUDSFileMode(s.conf.UDSFileMode)
			if err := os.Chmod(addr, fileMode); err != nil {
				return nil, fmt.Errorf("failed to change file mode of %q to %O: %w", addr, fileMode, err)
			}
		}

		//nolint:forcetypeassert
		listener.(*net.UnixListener).SetUnlinkOnClose(true)
		return listener, nil
	}

	return reuseport.NewReusablePortListener(network, addr)
}

//nolint:gomnd
func toUDSFileMode(modeStr string) os.FileMode {
	m, err := strconv.ParseInt(modeStr, 0, 32)
	if err != nil || m <= 0 {
		return 0o766
	}

	// Ignore everything but the last 9 bits which hold the user, group and world perms.
	return os.FileMode(m & 0o777)
}

func incomingHeaderMatcher(key string) (string, bool) {
	switch textproto.CanonicalMIMEHeaderKey(key) {
	// The gateway sets its own user agent, so we need to alias it
	case "User-Agent":
		return "Grpcgateway-User-Agent", true

	case
		// The request sent by the gateway will have a different content length
		"Content-Length",

		// Reserved for aliasing the incoming User-Agent header
		"Grpcgateway-User-Agent",

		// Translated to X-Forwarded-Host by the gateway
		"Host",

		// Connection-specific headers must be removed when translating HTTP/1.x to HTTP/2 (https://httpwg.org/specs/rfc9113.html#ConnectionSpecific)
		"Connection",
		"Keep-Alive",
		"Proxy-Connection",
		"Transfer-Encoding",
		"Upgrade":
		return "", false

	default:
		return key, true
	}
}

func setPeerMetadata(_ context.Context, req *http.Request) metadata.MD {
	return metadata.Pairs(audit.HTTPRemoteAddrKey, req.RemoteAddr)
}
