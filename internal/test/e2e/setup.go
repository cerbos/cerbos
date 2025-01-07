// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-cmd/cmd"
)

func Setup(ctx Ctx) error {
	ctx.Logf("Setup for context %q (%+v)", ctx.ContextID, ctx.Config)

	// `helmfile apply` requires `helm diff`. `helmfile init` checks for required plugins
	if err := Cmd(ctx, "helmfile", "apply"); err != nil {
		ctx.Logf("Deployment failed: %v", err)
		if err := CmdWithOutput(ctx, "kubectl", "describe", "pods", fmt.Sprintf("--namespace=%s", ctx.Namespace())); err != nil {
			ctx.Logf("Failed to describe pods: %v", err)
		}

		if err := CmdWithOutput(ctx, "stern", ".*", fmt.Sprintf("--namespace=%s", ctx.Namespace()), "--no-follow"); err != nil {
			ctx.Logf("Failed to grab logs: %v", err)
		}
		return err
	}

	ctx.Logf("Deployment succeeded")
	if !ctx.NoCleanup {
		ctx.Cleanup(func() { _ = Teardown(ctx) })
	}

	return Retry(checkCerbosIsUp(ctx), 1*time.Minute, 1*time.Second)
}

func Teardown(ctx Ctx) error {
	return Cmd(ctx, "helmfile", "destroy")
}

func Cmd(ctx Ctx, name string, args ...string) error {
	return execCmd(ctx, false, name, args...)
}

func CmdWithOutput(ctx Ctx, name string, args ...string) error {
	return execCmd(ctx, true, name, args...)
}

func execCmd(ctx Ctx, showOutput bool, name string, args ...string) error {
	c := cmd.NewCmd(name, args...)
	c.Env = ctx.Environ()

	timeout, cancelFn := ctx.CommandTimeoutCtx()
	defer cancelFn()

	status := c.Start()

	select {
	case done := <-status:
		if done.Complete && done.Error == nil && done.Exit == 0 {
			if showOutput {
				dumpOutput(ctx, done)
			}
			return nil
		}

		dumpOutput(ctx, done)
		return fmt.Errorf("failed to run %q: exit=%d err=%v", done.Cmd, done.Exit, done.Error)

	case <-timeout.Done():
		_ = c.Stop()
		return timeout.Err()
	}
}

func dumpOutput(ctx Ctx, s cmd.Status) {
	ctx.Logf("Command=[%s] Code=%d Error=%v", s.Cmd, s.Exit, s.Error)
	ctx.Logf("-----Stdout-----")
	for _, l := range s.Stdout {
		ctx.Logf(l)
	}

	ctx.Logf("-----Stderr-----")
	for _, l := range s.Stderr {
		ctx.Logf(l)
	}
}

func checkCerbosIsUp(ctx Ctx) func() error {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	client := &http.Client{Transport: customTransport}
	healthURL := ctx.HealthURL()

	return func() error {
		ctx.Logf("Checking whether Cerbos is up")
		resp, err := client.Get(healthURL)
		if err != nil {
			ctx.Logf("Error during healthcheck: %v", err)
			return err
		}
		if resp.StatusCode != http.StatusOK {
			ctx.Logf("Received health status: %q", resp.Status)
			return fmt.Errorf("received status %q", resp.Status)
		}

		return nil
	}
}

func Retry(op func() error, timeout time.Duration, interval time.Duration) error {
	lastErr := op()
	if lastErr == nil {
		return nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-timer.C:
			return lastErr
		case <-ticker.C:
			lastErr = op()
			if lastErr == nil {
				return nil
			}
		}
	}
}
