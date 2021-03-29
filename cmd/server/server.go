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
	"os/signal"
	"strings"
	"time"

	"github.com/ghostunnel/ghostunnel/socket"
	"github.com/google/gops/agent"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_validator "github.com/grpc-ecosystem/go-grpc-middleware/validator"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/soheilhy/cmux"
	"github.com/spf13/cobra"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/channelz/service"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/cerbos/cerbos/pkg/config"
	"github.com/cerbos/cerbos/pkg/engine"
	svcv1 "github.com/cerbos/cerbos/pkg/generated/svc/v1"
	"github.com/cerbos/cerbos/pkg/logging"
	"github.com/cerbos/cerbos/pkg/storage"
	"github.com/cerbos/cerbos/pkg/svc"
)

type serverArgs struct {
	configFile      string
	logLevel        string
	debugListenAddr string
}

var args = serverArgs{}

const defaultTimeout = 30 * time.Second

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Start server",
		RunE:         doRun,
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&args.configFile, "config", "", "Path to config file")
	cmd.Flags().StringVar(&args.logLevel, "log-level", "INFO", "Log level")
	cmd.Flags().StringVar(&args.debugListenAddr, "debug-listen-addr", "", "Address to start the gops listener")

	_ = cmd.MarkFlagFilename("config")
	_ = cmd.MarkFlagRequired("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	logging.InitLogging(args.logLevel)

	log := zap.S().Named("server")

	undo, err := maxprocs.Set(maxprocs.Logger(log.Infof))
	defer undo()

	if err != nil {
		log.Warnw("Failed to adjust GOMAXPROCS", "error", err)
	}

	if args.debugListenAddr != "" {
		startDebugListener(args.debugListenAddr)
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	// load configuration
	if err := config.Load(args.configFile); err != nil {
		return err
	}

	// create Cerbos service
	cerbosSvc, err := createCerbosService(ctx)
	if err != nil {
		return err
	}

	conf, err := getServerConf()
	if err != nil {
		return err
	}

	s := newServer(conf)
	return s.start(ctx, cerbosSvc)
}

func startDebugListener(listenAddr string) {
	log := zap.S().Named("debug")
	log.Infof("Starting debug listener at %s", args.debugListenAddr)

	err := agent.Listen(agent.Options{
		Addr:                   listenAddr,
		ShutdownCleanup:        true,
		ReuseSocketAddrAndPort: true,
	})
	if err != nil {
		log.Errorw("Failed to start debug agent", "error", err)
	}
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

type server struct {
	conf       Conf
	cancelFunc context.CancelFunc
	group      *errgroup.Group
	health     *health.Server
}

func newServer(conf Conf) *server {
	ctx, cancelFunc := context.WithCancel(context.Background())

	group, _ := errgroup.WithContext(ctx)

	return &server{
		conf:       conf,
		cancelFunc: cancelFunc,
		group:      group,
		health:     health.NewServer(),
	}
}

func (s *server) start(ctx context.Context, cerbosSvc *svc.CerbosService) error {
	defer s.cancelFunc()

	log := zap.S().Named("server")

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

	httpServer, err := s.startHTTPServer(ctx, httpL, grpcServer)
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

func (s *server) createListener(listenAddr string) (net.Listener, error) {
	l, err := socket.ParseAndOpen(listenAddr)
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

func (s *server) getTLSConfig() (*tls.Config, error) {
	if s.conf.TLS == nil || (s.conf.TLS.Cert == "" || s.conf.TLS.Key == "") {
		return nil, nil
	}

	conf := s.conf.TLS

	certificate, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	tlsConfig := defaultTLSConfig()
	tlsConfig.Certificates = []tls.Certificate{certificate}

	if conf.CACert != "" {
		// TODO (cell) Configure TLS with reloadable certificates
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

func defaultTLSConfig() *tls.Config {
	// See https://wiki.mozilla.org/Security/Server_Side_TLS
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2"},
	}
}

func (s *server) startGRPCServer(cerbosSvc *svc.CerbosService, l net.Listener) *grpc.Server {
	log := zap.L().Named("grpc")
	// grpc_zap.ReplaceGrpcLoggerV2(log)
	// TODO (cell) log payload

	opts := []grpc.ServerOption{
		grpc.ChainStreamInterceptor(
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_zap.StreamServerInterceptor(log),
			grpc_validator.StreamServerInterceptor(),
		),
		grpc.ChainUnaryInterceptor(
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(svc.ExtractRequestFields)),
			grpc_zap.UnaryServerInterceptor(log),
			grpc_validator.UnaryServerInterceptor(),
		),
	}

	server := grpc.NewServer(opts...)
	svcv1.RegisterCerbosServiceServer(server, cerbosSvc)
	healthpb.RegisterHealthServer(server, s.health)

	reflection.Register(server)
	service.RegisterChannelzServiceToServer(server)

	s.group.Go(func() error {
		log.Info(fmt.Sprintf("Starting gRPC server at %s", s.conf.GRPCListenAddr))
		err := server.Serve(l)
		if err != nil && !(errors.Is(err, cmux.ErrListenerClosed) || errors.Is(err, cmux.ErrServerClosed)) {
			log.Error("gRPC server failed", zap.Error(err))
			return err
		}

		log.Info("gRPC server stopped")
		return nil
	})

	return server
}

func (s *server) startHTTPServer(ctx context.Context, l net.Listener, grpcSrv *grpc.Server) (*http.Server, error) {
	log := zap.S().Named("http")

	gwmux := runtime.NewServeMux()

	// see https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md
	opts := []grpc.DialOption{
		grpc.WithContextDialer(dialFunc),
		grpc.WithConnectParams(grpc.ConnectParams{
			MinConnectTimeout: 20 * time.Second, //nolint:gomnd
		}),
	}

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

	mux := http.NewServeMux()
	mux.Handle("/", gwmux)
	mux.HandleFunc("/status", s.handleHTTPHealthCheck(grpcConn))

	handler := grpcHandler(grpcSrv, mux)

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           handler,
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

func dialFunc(ctx context.Context, address string) (net.Conn, error) {
	network, addr, _, err := socket.ParseAddress(address)
	if err != nil {
		return nil, err
	}

	dialer := new(net.Dialer)
	return dialer.DialContext(ctx, network, addr)
}

func grpcHandler(grpcSvc *grpc.Server, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcSvc.ServeHTTP(w, r)
		} else {
			handler.ServeHTTP(w, r)
		}
	})
}

func (s *server) handleHTTPHealthCheck(conn grpc.ClientConnInterface) http.HandlerFunc {
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
