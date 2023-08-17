// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package run

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/go-cmd/cmd"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/server"
)

const (
	help = `
Launches a command within the context of a Cerbos PDP. The policies are loaded by default from a directory named "policies" in the current working directory. The launched application can access Cerbos endpoints using the values from CERBOS_HTTP or CERBOS_GRPC environment variables.

If a file named ".cerbos.yaml" exists in the current working directory, it will be used as the configuration file for the PDP. You can override the config file and/or other configuration options using the flags described below.

Examples:

# Launch Go tests within a Cerbos context

cerbos run -- go test ./...

# Start Cerbos with a custom configuration file and run Python tests within the context

cerbos run --config=myconf.yaml -- python -m unittest

# Silence Cerbos log output

cerbos run --log-level=error -- curl -I http://127.0.0.1:3592/_cerbos/health
	`

	confDefault = `
server:
  httpListenAddr: "127.0.0.1:3592"
  grpcListenAddr: "127.0.0.1:3593"
storage:
  driver: "disk"
  disk:
    directory: %q
    watchForChanges: true
`

	requestTimeout = 100 * time.Millisecond
	retryInterval  = 141 * time.Millisecond
)

type Cmd struct {
	LogLevel string         `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
	Config   string         `help:"Path to config file" type:"existingfile" placeholder:".cerbos.yaml"`
	Set      []string       `help:"Config overrides" placeholder:"server.adminAPI.enabled=true"`
	Command  []string       `help:"Command to run" arg:"" passthrough:"" required:""`
	Timeout  time.Duration  `help:"Cerbos startup timeout" default:"30s"`
	wg       sync.WaitGroup `kong:"-"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	notifyCtx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	logging.InitLogging(notifyCtx, c.LogLevel)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.S().Named("run")

	undo, _ := maxprocs.Set(maxprocs.Logger(log.Infof))
	defer undo()

	if err := c.loadConfig(); err != nil {
		log.Errorw("Failed to load configuration", "error", err)
		return err
	}

	pdp, err := c.startPDP(notifyCtx)
	if err != nil {
		log.Errorw("Failed to start the PDP", "error", err)
		return err
	}

	command := c.prepCommand(pdp, k.Stdout, k.Stderr)
	statusChan := command.Start()

	cleanup := func() {
		if cerr := command.Stop(); cerr != nil && !errors.Is(cerr, cmd.ErrNotStarted) {
			log.Errorw("Error stopping command", "error", cerr)
		}

		pdp.stopFn()
		c.wg.Wait()
	}

	select {
	case err := <-pdp.errors:
		log.Errorw("Cerbos PDP error", "error", err)
		cleanup()

		return err
	case status := <-statusChan:
		if status.Error != nil {
			log.Errorw("Command execution error", "error", err)
			cleanup()

			return err
		}

		if status.Complete {
			log.Infof("Command finished with status %d", status.Exit)
		}

		cleanup()

		if status.Exit != 0 {
			stopFunc()
			undo()
			k.Exit(status.Exit)
		}
	case <-notifyCtx.Done():
		log.Info("Terminated by signal")
		cleanup()
	}

	return nil
}

func (c *Cmd) loadConfig() error {
	// load any config overrides
	confOverrides := map[string]any{}
	for _, override := range c.Set {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}

	// load configuration
	//nolint:nestif
	if c.Config != "" {
		if err := config.Load(c.Config, confOverrides); err != nil {
			return fmt.Errorf("failed to load configuration from %s: %w", c.Config, err)
		}
	} else if fd, err := os.Stat(".cerbos.yaml"); err == nil && !fd.IsDir() {
		if err := config.Load(".cerbos.yaml", confOverrides); err != nil {
			return fmt.Errorf("failed to load configuration from .cerbos.yaml: %w", err)
		}
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to determine current working directory: %w", err)
		}

		policyDir := filepath.Join(wd, "policies")
		if _, err := os.Stat(policyDir); err != nil && errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(policyDir, 0o744); err != nil { //nolint:gomnd
				return fmt.Errorf("unable to create policies directory: %w", err)
			}
		}

		confYAML := fmt.Sprintf(confDefault, policyDir)
		if err := config.LoadReader(strings.NewReader(confYAML), confOverrides); err != nil {
			return fmt.Errorf("failed to load default Cerbos configuration: %w", err)
		}
	}

	return nil
}

func (c *Cmd) startPDP(ctx context.Context) (*pdpInstance, error) {
	var conf server.Conf
	if err := config.GetSection(&conf); err != nil {
		return nil, fmt.Errorf("failed to obtain server config; %w", err)
	}

	protocol := "http"
	if conf.TLS != nil && conf.TLS.Cert != "" && conf.TLS.Key != "" {
		protocol = "https"
	}

	instance := &pdpInstance{
		httpAddr: fmt.Sprintf("%s://%s", protocol, conf.HTTPListenAddr),
		grpcAddr: conf.GRPCListenAddr,
		errors:   make(chan error, 1),
	}

	serverCtx, stopFn := context.WithCancel(context.Background())
	instance.stopFn = stopFn

	c.goroutine(func() {
		instance.errors <- server.Start(serverCtx, false)
		close(instance.errors)
	})

	waitCtx, cancelFn := context.WithTimeout(ctx, c.Timeout)
	defer cancelFn()
	if err := instance.waitForReady(waitCtx); err != nil {
		return nil, fmt.Errorf("error starting Cerbos PDP: %w", err)
	}

	return instance, nil
}

func (c *Cmd) prepCommand(pdp *pdpInstance, stdout, stderr io.Writer) *cmd.Cmd {
	httpAddr := fmt.Sprintf("CERBOS_HTTP=%s", pdp.httpAddr)
	grpcAddr := fmt.Sprintf("CERBOS_GRPC=%s", pdp.grpcAddr)

	env := os.Environ()
	env = append([]string{httpAddr, grpcAddr}, env...)

	opt := cmd.Options{Streaming: true}
	command := cmd.NewCmdOptions(opt, c.Command[0], c.Command[1:]...)
	command.Env = env

	c.goroutine(func() {
		for line := range command.Stdout {
			fmt.Fprintln(stdout, line)
		}
	})

	c.goroutine(func() {
		for line := range command.Stderr {
			fmt.Fprintln(stderr, line)
		}
	})

	return command
}

func (c *Cmd) goroutine(fn func()) {
	c.wg.Add(1)
	go func() {
		fn()
		c.wg.Done()
	}()
}

func (c *Cmd) Help() string {
	return help
}

type pdpInstance struct {
	errors   chan error
	stopFn   context.CancelFunc
	httpAddr string
	grpcAddr string
}

func (pdp *pdpInstance) waitForReady(ctx context.Context) error {
	client := pdp.client()
	healthURL := fmt.Sprintf("%s/_cerbos/health", pdp.httpAddr)

	lastErr := pdp.checkHealth(client, healthURL)
	if lastErr == nil {
		return nil
	}

	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return lastErr
		case err := <-pdp.errors:
			return err
		case <-ticker.C:
			lastErr = pdp.checkHealth(client, healthURL)
			if lastErr == nil {
				return nil
			}
		}
	}
}

func (pdp *pdpInstance) client() *http.Client {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()      //nolint:forcetypeassert
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	return &http.Client{Transport: customTransport}
}

func (pdp *pdpInstance) checkHealth(client *http.Client, healthURL string) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), requestTimeout)
	defer cancelFunc()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status %q", resp.Status)
	}

	return nil
}
