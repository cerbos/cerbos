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

	"github.com/google/gops/agent"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_validator "github.com/grpc-ecosystem/go-grpc-middleware/validator"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/soheilhy/cmux"
	"github.com/spf13/cobra"
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

	if args.debugListenAddr != "" {
		startDebugListener(args.debugListenAddr)
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	// load configuration
	if err := config.Load(args.configFile); err != nil {
		return err
	}

	conf, err := getServerConf()
	if err != nil {
		return err
	}

	s := newServer(conf)
	return s.start(ctx)
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

func (s *server) start(ctx context.Context) error {
	defer s.cancelFunc()

	log := zap.S().Named("server")

	// cmux can't deal with both grpc and HTTP/2 (see https://github.com/soheilhy/cmux/issues/68)
	// Therefore, we have to have two different modes for when TLS is enabled and when it's not
	// TLS Enabled: Use HTTP server to serve gRPC too
	// TLS Disabled: Use cmux to mux the connections (can't reuse first method because gRPC gateway fails to connect)
	// TODO (cell) Find a better way to handle this

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

	// create service
	cerbosSvc, err := createCerbosService(ctx)
	if err != nil {
		log.Errorw("Failed to create Cerbos service", "error", err)
		return err
	}

	grpcServer := s.startGRPCServer(cerbosSvc, grpcL)

	httpServer, err := s.startHTTPServer(ctx, httpL, grpcServer)
	if err != nil {
		log.Errorw("Failed to start HTTP server", "error", err)
		return err
	}

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

	return nil
}

func (s *server) createListener(listenAddr string) (net.Listener, error) {
	l, err := net.Listen("tcp", listenAddr)
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
	if s.conf.TLS == nil {
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
	// See https://blog.cloudflare.com/exposing-go-on-the-internet/
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"h2"},
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

func (s *server) startGRPCServer(cerbosSvc *svc.CerbosService, l net.Listener) *grpc.Server {
	log := zap.L().Named("grpc")
	//	grpc_zap.ReplaceGrpcLoggerV2WithVerbosity(log, -3)
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

	opts := []grpc.DialOption{grpc.WithTransportCredentials(local.NewCredentials())}

	tlsConf, err := s.getTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	if tlsConf != nil {
		tlsConf.InsecureSkipVerify = true
		opts = []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))}
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
		}

		log.Info("HTTP server stopped")
		return err
	})

	return h, nil
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
