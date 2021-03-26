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
	"time"

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
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/cerbos/cerbos/pkg/config"
	"github.com/cerbos/cerbos/pkg/engine"
	svcv1 "github.com/cerbos/cerbos/pkg/generated/svc/v1"
	"github.com/cerbos/cerbos/pkg/storage"
	"github.com/cerbos/cerbos/pkg/svc"
	"github.com/cerbos/cerbos/pkg/util"
)

type serverArgs struct {
	configFile string
	logLevel   string
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

	_ = cmd.MarkFlagFilename("config")
	_ = cmd.MarkFlagRequired("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	util.InitLogging(args.logLevel)

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

	// create listeners
	grpcL, httpL, err := s.createListeners()
	if err != nil {
		log.Errorw("Failed to start listener", "error", err)
		return err
	}

	// create service
	cerbosSvc, err := createCerbosService(ctx)
	if err != nil {
		log.Errorw("Failed to create Cerbos service", "error", err)
		return err
	}

	grpcServer := s.startGRPCServer(cerbosSvc, grpcL)

	httpServer, err := s.startHTTPServer(ctx, httpL)
	if err != nil {
		log.Errorw("Failed to start HTTP server", "error", err)
		return err
	}

	<-ctx.Done()

	// mark this service as NOT_SERVING in the gRPC health check.
	s.health.Shutdown()

	log.Info("Shutting down HTTP server")
	shutdownCtx, cancelFunc := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancelFunc()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Errorw("Failed to cleanly shutdown HTTP server", "error", err)
	}

	log.Info("Shutting down gRPC server")
	grpcServer.GracefulStop()

	log.Info("Shutdown complete")

	return nil
}

func (s *server) createListeners() (grpcL, httpL net.Listener, err error) {
	l, err := net.Listen("tcp", s.conf.ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create listener at '%s': %w", s.conf.ListenAddr, err)
	}

	if s.conf.TLS != nil {
		tlsConf, err := getTLSConfig(s.conf.TLS)
		if err != nil {
			return nil, nil, err
		}

		l = tls.NewListener(l, tlsConf)
	}

	connMux := cmux.New(l)
	grpcL = connMux.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
	httpL = connMux.Match(cmux.HTTP1Fast())

	s.group.Go(func() error {
		log := zap.S().Named("server")
		log.Infof("Starting listener on %s", s.conf.ListenAddr)

		err := connMux.Serve()
		if !errors.Is(err, net.ErrClosed) {
			log.Errorw("Listener failed", "error", err)
			return err
		}

		return err
	})

	return grpcL, httpL, nil
}

func getTLSConfig(conf *TLSConf) (*tls.Config, error) {
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
			grpc_ctxtags.UnaryServerInterceptor(),
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
		log.Info("Starting gRPC server")

		err := server.Serve(l)
		if err != nil && !(errors.Is(err, cmux.ErrListenerClosed) || errors.Is(err, cmux.ErrServerClosed)) {
			log.Error("gRPC server failed", zap.Error(err))
			return err
		}

		return nil
	})

	return server
}

func (s *server) startHTTPServer(ctx context.Context, l net.Listener) (*http.Server, error) {
	log := zap.S().Named("http")

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(local.NewCredentials())}
	if err := svcv1.RegisterCerbosServiceHandlerFromEndpoint(ctx, mux, s.conf.ListenAddr, opts); err != nil {
		log.Errorw("Failed to register gRPC gateway", "error", err)
		return nil, fmt.Errorf("failed to register gRPC service: %w", err)
	}

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           mux,
		ReadHeaderTimeout: defaultTimeout,
		ReadTimeout:       defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	s.group.Go(func() error {
		log.Info("Starting HTTP server")
		err := h.Serve(l)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorw("HTTP server failed", "error", err)
		}

		return err
	})

	return h, nil
}
