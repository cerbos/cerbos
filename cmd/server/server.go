package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/server"
	"github.com/charithe/menshen/pkg/util"
)

type serverArgs struct {
	logLevel   string
	listenAddr string
	policyDir  string
}

var args = serverArgs{}

const defaultTimeout = 30 * time.Second

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start server",
		RunE:  doRun,
	}

	cmd.Flags().StringVar(&args.logLevel, "log-level", "INFO", "Log level")
	cmd.Flags().StringVar(&args.listenAddr, "listen-addr", ":9999", "Listen address")
	cmd.Flags().StringVar(&args.policyDir, "policy-dir", "", "Path to the directory containing policies")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	util.InitLogging(args.logLevel)

	checker, err := policy.NewChecker(args.policyDir)
	if err != nil {
		return err
	}

	return startHTTPServer(server.New(checker))
}

func startHTTPServer(s *server.Server) error {
	h := &http.Server{
		Addr:              args.listenAddr,
		ErrorLog:          zap.NewStdLog(zap.L().Named("httperr")),
		Handler:           s.Handler(),
		ReadHeaderTimeout: defaultTimeout,
		ReadTimeout:       defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	log := zap.S().Named("http.server")

	go func() {
		log.Infof("Starting HTTP server on %s", args.listenAddr)
		if err := h.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server", "error", err)
		}
	}()

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt)
	<-shutdownChan

	log.Info("Shutting down")
	ctx, cancelFunc := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancelFunc()

	return h.Shutdown(ctx)
}
