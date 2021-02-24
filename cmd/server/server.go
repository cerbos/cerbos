package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/charithe/menshen/pkg/config"
	"github.com/charithe/menshen/pkg/server"
	"github.com/charithe/menshen/pkg/storage"
	"github.com/charithe/menshen/pkg/util"
)

type serverArgs struct {
	logLevel   string
	configFile string
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

	cmd.Flags().StringVar(&args.logLevel, "loglevel", "INFO", "Log level")
	cmd.Flags().StringVar(&args.configFile, "config", "", "Path to config file")

	cmd.MarkFlagFilename("config")
	cmd.MarkFlagRequired("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	util.InitLogging(args.logLevel)
	log := zap.S().Named("http.server")

	if err := config.Init(args.configFile); err != nil {
		log.Errorw("Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load config file %s: %w", args.configFile, err)
	}

	conf := config.Get()

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	store, err := storage.New(ctx, conf.Storage)
	if err != nil {
		log.Errorw("Failed to create store", "error", err)
		return fmt.Errorf("failed to create store: %w", err)
	}

	server, err := server.New(store)
	if err != nil {
		log.Errorw("Failed to initialize server", "error", err)
		return fmt.Errorf("failed to create http server; %w", err)
	}

	// TODO (cell) Configure TLS

	h := &http.Server{
		Addr:              conf.Server.ListenAddr,
		ErrorLog:          zap.NewStdLog(zap.L().Named("http.error")),
		Handler:           server.Handler(),
		ReadHeaderTimeout: defaultTimeout,
		ReadTimeout:       defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	errChan := make(chan error, 1)
	go func() {
		log.Infof("Starting HTTP server on %s", conf.Server.ListenAddr)
		if err := h.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
