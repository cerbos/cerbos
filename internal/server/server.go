// Copyright 2021 Zenauth Ltd.

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
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/admin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/svc"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/schema"
)

const (
	defaultTimeout           = 30 * time.Second
	maxConnectionAge         = 10 * time.Minute
	metricsReportingInterval = 15 * time.Second
	minGRPCConnectTimeout    = 20 * time.Second

	apiEndpoint     = "/api"
	healthEndpoint  = "/_cerbos/health"
	metricsEndpoint = "/_cerbos/metrics"
	schemaEndpoint  = "/schema/swagger.json"
	zpagesEndpoint  = "/_cerbos/debug"
)

func Start(ctx context.Context, zpagesEnabled bool) error {
	// create Cerbos service
	cerbosSvc, err := createCerbosService(ctx)
	if err != nil {
		return err
	}

	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return err
	}

	s := NewServer(conf)
	return s.Start(ctx, cerbosSvc, zpagesEnabled)
}

func createCerbosService(ctx context.Context) (*svc.CerbosService, error) {
	// create store
	store, err := storage.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// create engine
	eng, err := engine.New(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	return svc.NewCerbosService(eng), nil
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

func (s *Server) Start(ctx context.Context, cerbosSvc *svc.CerbosService, zpagesEnabled bool) error {
	defer s.cancelFunc()

	log := zap.S().Named("server")

	if s.conf.MetricsEnabled {
		ocExporter, err := initOCPromExporter()
		if err != nil {
			log.Errorw("Failed to initialize Prometheus exporter", "error", err)
			return err
		}

		s.ocExporter = ocExporter
	}

	// It would be nice to have a single port to serve both gRPC and HTTP from. Unfortunately, cmux
	// can't deal effectively with both gRPC and HTTP/2 when TLS is enabled (see https://github.com/soheilhy/cmux/issues/68).
	// One way to handle that would be to use the `ServeHTTP` method of gRPC to serve gRPC from the HTTP server.
	// However, when TLS is disabled, that won't work either because Go's HTTP/2 server does not support h2c (plaintext).
	// Another potential issue with single-port gRPC and HTTP/2 is when a proxy like Envoy is in front of the server, it
	// would have a connection pool per port and would end up sending HTTP/2 traffic to gRPC and vice-versa.
	// So, we have two dedicated ports for HTTP and gRPC traffic. However, if TLS is enabled, you can send gRPC to the
	// HTTP port as well and it would work. I think that's an acceptable compromise given that we expect TLS to be
	// enabled in all production settings.

	// create listeners
	grpcL, err := s.createListener(s.conf.GRPCListenAddr)
	if err != nil {
		log.Errorw("Failed to create gRPC listener", "error", err)
		return err
	}

	httpL, err := s.createListener(s.conf.HTTPListenAddr)
	if err != nil {
		log.Errorw("Failed to create HTTP listener", "error", err)
		return err
	}

	grpcServer := s.startGRPCServer(cerbosSvc, grpcL)

	httpServer, err := s.startHTTPServer(ctx, httpL, grpcServer, zpagesEnabled)
	if err != nil {
		log.Errorw("Failed to start HTTP server", "error", err)
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
			log.Errorw("Failed to cleanly shutdown HTTP server", "error", err)
		}

		log.Info("Shutdown complete")
		return ctx.Err()
	})

	err = s.group.Wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}

		log.Errorw("Stopping server due to error", "error", err)
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

func (s *Server) startGRPCServer(cerbosSvc *svc.CerbosService, l net.Listener) *grpc.Server {
	log := zap.L().Named("grpc")
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
		),
		grpc.StatsHandler(&ocgrpc.ServerHandler{}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: maxConnectionAge}),
	}

	server := grpc.NewServer(opts...)
	svcv1.RegisterCerbosServiceServer(server, cerbosSvc)
	healthpb.RegisterHealthServer(server, s.health)
	reflection.Register(server)

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

	return server
}

func (s *Server) startHTTPServer(ctx context.Context, l net.Listener, grpcSrv *grpc.Server, zpagesEnabled bool) (*http.Server, error) { //nolint:revive
	log := zap.S().Named("http")

	gwmux := runtime.NewServeMux(runtime.WithMarshalerOption("application/json+pretty", &runtime.JSONPb{
		MarshalOptions:   protojson.MarshalOptions{Indent: "  "},
		UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: true},
	}))

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

	if err := svcv1.RegisterCerbosServiceHandler(ctx, gwmux, grpcConn); err != nil {
		log.Errorw("Failed to register gRPC gateway", "error", err)
		return nil, fmt.Errorf("failed to register gRPC service: %w", err)
	}

	cerbosMux := mux.NewRouter()
	// handle gRPC requests that come over http
	cerbosMux.MatcherFunc(func(r *http.Request, _ *mux.RouteMatch) bool {
		return r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc")
	}).Handler(&ochttp.Handler{Handler: grpcSrv})

	cerbosMux.PathPrefix(apiEndpoint).Handler(&ochttp.Handler{Handler: prettyJSON(gwmux)})
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

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           cerbosMux,
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

// inspired by https://github.com/ghostunnel/ghostunnel/blob/6e58c75c8762fe371c1134e89dd55033a6d577a4/socket/net.go#L100
func parseAndOpen(listenAddr string) (net.Listener, error) {
	network, addr, err := util.ParseListenAddress(listenAddr)
	if err != nil {
		return nil, err
	}

	if network == "unix" {
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
