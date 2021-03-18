package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/charithe/menshen/pkg/config"
	"github.com/charithe/menshen/pkg/engine"
	"github.com/charithe/menshen/pkg/server"
	"github.com/charithe/menshen/pkg/storage"
	"github.com/charithe/menshen/pkg/util"
)

type serverArgs struct {
	configFile string
	listenAddr string
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
	cmd.Flags().StringVar(&args.listenAddr, "listenAddr", "", "Server listen address")
	cmd.Flags().StringVar(&args.logLevel, "loglevel", "INFO", "Log level")

	_ = cmd.MarkFlagFilename("config")
	_ = cmd.MarkFlagRequired("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	util.InitLogging(args.logLevel)
	log := zap.S().Named("http.server")

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	// load configuration
	if err := config.Load(args.configFile); err != nil {
		log.Errorw("Failed to load configuration", "error", err)

		return err
	}

	conf, err := getServerConf(args.listenAddr)
	if err != nil {
		return err
	}

	// create store
	store, err := storage.New(ctx)
	if err != nil {
		log.Errorw("Failed to create store", "error", err)
		return fmt.Errorf("failed to create store: %w", err)
	}

	// create engine
	eng, err := engine.New(ctx, store)
	if err != nil {
		log.Errorw("Failed to create engine", "error", err)
		return fmt.Errorf("failed to create engine: %w", err)
	}

	srv := server.New(eng, store)

	return startHTTPServer(ctx, srv, conf, log)
}

func startHTTPServer(ctx context.Context, srv *server.Server, conf Conf, log *zap.SugaredLogger) error {
	// TODO (cell) Configure TLS with reloadable certificates
	// TODO (cell) gRPC on the same port

	h := &http.Server{
		Addr:              conf.ListenAddr,
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: defaultTimeout,
		ReadTimeout:       defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	errChan := make(chan error, 1)
	go func() {
		log.Infof("Starting HTTP server on %s", conf.ListenAddr)
		if err := h.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("http server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		log.Errorw("Stopping due to error", "error", err)
		return err
	case <-ctx.Done():
		log.Info("Shutting down")
		shutdownCtx, cancelFunc := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancelFunc()

		return h.Shutdown(shutdownCtx)
	}
}
