// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"contrib.go.opencensus.io/exporter/prometheus"
	"github.com/gorilla/mux"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_validator "github.com/grpc-ecosystem/go-grpc-middleware/validator"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	reuseport "github.com/kavu/go_reuseport"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/zpages"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/admin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"

	// Import the default grpc encoding to ensure that it gets replaced by VT.
	_ "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"

	// Import to register the Badger audit log backend.
	_ "github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"

	// Import cloud to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/blob"

	// Import mysql to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/mysql"

	// Import postgres to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/postgres"

	// Import sqlite3 to register the storage driver.
	_ "github.com/cerbos/cerbos/internal/storage/db/sqlite3"

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
	maxConnectionAge         = 10 * time.Minute
	metricsReportingInterval = 15 * time.Second
	minGRPCConnectTimeout    = 20 * time.Second

	adminEndpoint      = "/admin"
	apiEndpoint        = "/api"
	healthEndpoint     = "/_cerbos/health"
	metricsEndpoint    = "/_cerbos/metrics"
	playgroundEndpoint = "/api/playground"
	schemaEndpoint     = "/schema/swagger.json"
	zpagesEndpoint     = "/_cerbos/debug"
)

func Start(ctx context.Context, zpagesEnabled bool) error {
	// get configuration
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// create audit log
	auditLog, err := audit.NewLog(ctx)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	// create store
	store, err := storage.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}

	// create engine
	eng, err := engine.New(ctx, compile.NewManager(ctx, store), auditLog)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// initialize aux data
	auxData, err := auxdata.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize auxData handler: %w", err)
	}

	s := NewServer(conf)
	return s.Start(ctx, Param{AuditLog: auditLog, AuxData: auxData, Engine: eng, Store: store, ZPagesEnabled: zpagesEnabled})
}

type Param struct {
	AuditLog      audit.Log
	AuxData       *auxdata.AuxData
	Engine        *engine.Engine
	Store         storage.Store
	ZPagesEnabled bool
}

type Server struct {
	conf       *Conf
	cancelFunc context.CancelFunc
	group      *errgroup.Group
	health     *health.Server
	ocExporter *prometheus.Exporter
}

func NewServer(conf *Conf) *Server {
	ctx, cancelFunc := context.WithCancel(context.Background())

	group, _ := errgroup.WithContext(ctx)

	return &Server{
		conf:       conf,
		cancelFunc: cancelFunc,
		group:      group,
		health:     health.NewServer(),
	}
}

func (s *Server) Start(ctx context.Context, param Param) error {
	defer s.cancelFunc()

	log := zap.L().Named("server")

	if s.conf.MetricsEnabled {
		ocExporter, err := initOCPromExporter()
		if err != nil {
			log.Error("Failed to initialize Prometheus exporter", zap.Error(err))
			return err
		}

		s.ocExporter = ocExporter
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

	httpServer, err := s.startHTTPServer(ctx, httpL, grpcServer, param.ZPagesEnabled)
	if err != nil {
		log.Error("Failed to start HTTP server", zap.Error(err))
		return err
	}

	s.group.Go(func() error {
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

		log.Debug("Shutting down the audit log")
		param.AuditLog.Close()

		log.Info("Shutdown complete")
		return nil
	})

	err = s.group.Wait()
	if err != nil {
		log.Error("Stopping server due to error", zap.Error(err))
		return err
	}

	return nil
}

func (s *Server) createListener(listenAddr string) (net.Listener, error) {
	l, err := parseAndOpen(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener at '%s': %w", listenAddr, err)
	}

	tlsConf, err := s.getTLSConfig()
	if err != nil {
		return nil, err
	}

	if tlsConf != nil {
		l = tls.NewListener(l, tlsConf)
	}

	return l, nil
}

func (s *Server) getTLSConfig() (*tls.Config, error) {
	if s.conf.TLS == nil || (s.conf.TLS.Cert == "" || s.conf.TLS.Key == "") {
		return nil, nil
	}
	// TODO (cell) Configure TLS with reloadable certificates

	conf := s.conf.TLS

	certificate, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	tlsConfig := util.DefaultTLSConfig()
	tlsConfig.Certificates = []tls.Certificate{certificate}

	if conf.CACert != "" {
		if _, err := os.Stat(conf.CACert); err != nil {
			return tlsConfig, nil //nolint:nilerr
		}

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

	return tlsConfig, nil
}

func (s *Server) startGRPCServer(l net.Listener, param Param) (*grpc.Server, error) {
	log := zap.L().Named("grpc")
	server := s.mkGRPCServer(log, param.AuditLog)

	healthpb.RegisterHealthServer(server, s.health)
	reflection.Register(server)

	cerbosSvc := svc.NewCerbosService(param.Engine, param.AuxData)
	svcv1.RegisterCerbosServiceServer(server, cerbosSvc)
	s.health.SetServingStatus(svcv1.CerbosService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	if s.conf.AdminAPI.Enabled {
		log.Info("Starting admin service")
		creds := s.conf.AdminAPI.AdminCredentials
		if creds.isUnsafe() {
			log.Warn("[SECURITY RISK] Admin API uses default credentials which are unsafe for production use. Please change the credentials by updating the configuration file.")
		}

		adminUser, adminPasswdHash, err := creds.usernameAndPasswordHash()
		if err != nil {
			log.Error("Failed to get admin API credentials", zap.Error(err))
			return nil, err
		}

		svcv1.RegisterCerbosAdminServiceServer(server, svc.NewCerbosAdminService(param.Store, param.AuditLog, adminUser, adminPasswdHash))
		s.health.SetServingStatus(svcv1.CerbosAdminService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	}

	if s.conf.PlaygroundEnabled {
		log.Info("Starting playground service")
		svcv1.RegisterCerbosPlaygroundServiceServer(server, svc.NewCerbosPlaygroundService())
		s.health.SetServingStatus(svcv1.CerbosPlaygroundService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	}

	s.group.Go(func() error {
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

func (s *Server) mkGRPCServer(log *zap.Logger, auditLog audit.Log) *grpc.Server {
	payloadLog := zap.L().Named("payload")

	opts := []grpc.ServerOption{
		grpc.ChainStreamInterceptor(
			grpc_recovery.StreamServerInterceptor(),
			grpc_validator.StreamServerInterceptor(),
			grpc_ctxtags.StreamServerInterceptor(grpc_ctxtags.WithFieldExtractorForInitialReq(svc.ExtractRequestFields)),
			grpc_zap.StreamServerInterceptor(log,
				grpc_zap.WithDecider(loggingDecider),
				grpc_zap.WithMessageProducer(messageProducer),
			),
			grpc_zap.PayloadStreamServerInterceptor(payloadLog, payloadLoggingDecider(s.conf)),
		),
		grpc.ChainUnaryInterceptor(
			grpc_recovery.UnaryServerInterceptor(),
			grpc_validator.UnaryServerInterceptor(),
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(svc.ExtractRequestFields)),
			XForwardedHostUnaryServerInterceptor,
			grpc_zap.UnaryServerInterceptor(log,
				grpc_zap.WithDecider(loggingDecider),
				grpc_zap.WithMessageProducer(messageProducer),
			),
			grpc_zap.PayloadUnaryServerInterceptor(payloadLog, payloadLoggingDecider(s.conf)),
			audit.NewUnaryInterceptor(auditLog, accessLogExclude),
		),
		grpc.StatsHandler(&ocgrpc.ServerHandler{}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: maxConnectionAge}),
		grpc.UnknownServiceHandler(handleUnknownServices),
	}

	return grpc.NewServer(opts...)
}

func (s *Server) startHTTPServer(ctx context.Context, l net.Listener, grpcSrv *grpc.Server, zpagesEnabled bool) (*http.Server, error) {
	log := zap.S().Named("http")

	gwmux := runtime.NewServeMux(
		runtime.WithForwardResponseOption(customHTTPResponseCode),
		runtime.WithMarshalerOption("application/json+pretty", &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{Indent: "  "},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: true},
		}),
		runtime.WithRoutingErrorHandler(handleRoutingError),
	)

	grpcConn, err := s.mkGRPCConn(ctx)
	if err != nil {
		return nil, err
	}

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
	}).Handler(tracing.HTTPHandler(grpcSrv))

	cerbosMux.PathPrefix(adminEndpoint).Handler(tracing.HTTPHandler(prettyJSON(gwmux)))
	cerbosMux.PathPrefix(apiEndpoint).Handler(tracing.HTTPHandler(prettyJSON(gwmux)))
	cerbosMux.Path(schemaEndpoint).HandlerFunc(schema.ServeSvcSwagger)
	cerbosMux.Path(healthEndpoint).HandlerFunc(s.handleHTTPHealthCheck(grpcConn))

	if s.conf.MetricsEnabled && s.ocExporter != nil {
		cerbosMux.Path(metricsEndpoint).Handler(s.ocExporter)
	}

	if zpagesEnabled {
		hm := http.NewServeMux()
		zpages.Handle(hm, zpagesEndpoint)

		cerbosMux.PathPrefix(zpagesEndpoint).Handler(hm)
	}

	cerbosMux.HandleFunc("/", schema.ServeUI)

	httpHandler := withCORS(s.conf, cerbosMux)

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           h2c.NewHandler(httpHandler, &http2.Server{}),
		ReadHeaderTimeout: defaultTimeout,
		ReadTimeout:       defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	s.group.Go(func() error {
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
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: minGRPCConnectTimeout}),
		grpc.WithStatsHandler(&ocgrpc.ClientHandler{}),
	}
}

func (s *Server) handleHTTPHealthCheck(conn grpc.ClientConnInterface) http.HandlerFunc {
	healthClient := healthpb.NewHealthClient(conn)
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := healthClient.Check(r.Context(), &healthpb.HealthCheckRequest{})
		if err != nil {
			statusCode := runtime.HTTPStatusFromCode(status.Code(err))
			http.Error(w, "HealthCheck failure", statusCode)
			return
		}

		switch resp.Status {
		case healthpb.HealthCheckResponse_SERVING, healthpb.HealthCheckResponse_UNKNOWN:
			fmt.Fprintln(w, resp.Status.String())
		default:
			http.Error(w, resp.Status.String(), http.StatusServiceUnavailable)
		}
	}
}

func (s *Server) mkGRPCConn(ctx context.Context) (*grpc.ClientConn, error) {
	opts := defaultGRPCDialOpts()

	tlsConf, err := s.getTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	if tlsConf != nil {
		tlsConf.InsecureSkipVerify = true // we are connecting as localhost which would differ from what the cert is issued for.
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(local.NewCredentials()))
	}

	grpcConn, err := grpc.DialContext(ctx, s.conf.GRPCListenAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, nil
}

// inspired by https://github.com/ghostunnel/ghostunnel/blob/6e58c75c8762fe371c1134e89dd55033a6d577a4/socket/net.go#L100
func parseAndOpen(listenAddr string) (net.Listener, error) {
	network, addr, err := util.ParseListenAddress(listenAddr)
	if err != nil {
		return nil, err
	}

	if network == "unix" {
		if err := os.RemoveAll(addr); err != nil {
			return nil, err
		}

		listener, err := net.Listen(network, addr)
		if err != nil {
			return nil, err
		}

		listener.(*net.UnixListener).SetUnlinkOnClose(true)
		return listener, nil
	}

	return reuseport.NewReusablePortListener(network, addr)
}

func initOCPromExporter() (*prometheus.Exporter, error) {
	if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
		return nil, fmt.Errorf("failed to register gRPC server views: %w", err)
	}

	if err := view.Register(ochttp.DefaultServerViews...); err != nil {
		return nil, fmt.Errorf("failed to register HTTP server views: %w", err)
	}

	if err := view.Register(metrics.DefaultCerbosViews...); err != nil {
		return nil, fmt.Errorf("failed to register Cerbos views: %w", err)
	}

	registry, ok := prom.DefaultRegisterer.(*prom.Registry)
	if !ok {
		registry = nil
	}

	exporter, err := prometheus.NewExporter(prometheus.Options{Registry: registry})
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	view.RegisterExporter(exporter)
	view.SetReportingPeriod(metricsReportingInterval)

	return exporter, nil
}
