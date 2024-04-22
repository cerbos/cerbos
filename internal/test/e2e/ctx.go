// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

const (
	cerbosHostNameEnvVar = "E2E_CERBOS_HOST"
	HTTPPort             = 3592
	GRPCPort             = 3593
	HealthEndpoint       = "/_cerbos/health"
)

var conf = Config{}

//nolint:gomnd
func init() {
	srcRoot, err := findSourceRoot()
	if err != nil {
		panic(fmt.Errorf("failed to determine source root: %w", err))
	}

	noCleanup, err := strconv.ParseBool(envOrDefault("E2E_NO_CLEANUP", "false"))
	if err != nil {
		noCleanup = false
	}

	flag.StringVar(&conf.RunID, "run-id", envOrDefault("E2E_RUN_ID", RandomStr(5)), "Run ID for this test run")
	flag.StringVar(&conf.SourceRoot, "source-root", srcRoot, "Directory containing the Cerbos source code")
	flag.StringVar(&conf.CerbosImgRepo, "cerbos-img-repo", "ghcr.io/cerbos/cerbos", "Cerbos image repo")
	flag.StringVar(&conf.CerbosImgTag, "cerbos-img-tag", "dev", "Cerbos image tag")
	flag.DurationVar(&conf.CommandTimeout, "command-timeout", 3*time.Minute, "Command execution timeout")
	flag.BoolVar(&conf.NoCleanup, "no-cleanup", noCleanup, "Do not cleanup after tests")
}

func findSourceRoot() (string, error) {
	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to find path to current file")
	}

	return filepath.Abs(filepath.Join(filepath.Dir(currFile), "..", "..", ".."))
}

func envOrDefault(envVar, def string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}

	return def
}

type Config struct {
	RunID          string        `json:"run_id"`
	SourceRoot     string        `json:"source_root"`
	CerbosImgRepo  string        `json:"cerbos_img_repo"`
	CerbosImgTag   string        `json:"cerbos_img_tag"`
	CommandTimeout time.Duration `json:"command_timeout"`
	NoCleanup      bool          `json:"no_cleanup"`
}

func NewCtx(t *testing.T, contextID string, noTLS bool) Ctx {
	return Ctx{ContextID: contextID, Config: conf, T: t, NoTLS: noTLS}
}

type Ctx struct {
	ContextID   string
	NoTLS       bool
	ComputedEnv map[string]string
	*testing.T
	Config
}

func (c Ctx) Environ() []string {
	defaults := map[string]string{
		"E2E_CERBOS_IMG_REPO": c.CerbosImgRepo,
		"E2E_CERBOS_IMG_TAG":  c.CerbosImgTag,
		"E2E_CONTEXT_ID":      c.ContextID,
		"E2E_NO_CLEANUP":      strconv.FormatBool(c.NoCleanup),
		"E2E_NS":              c.Namespace(),
		"E2E_RUN_ID":          c.RunID,
		"E2E_SRC_ROOT":        c.SourceRoot,
	}

	if c.ComputedEnv != nil {
		for k, v := range c.ComputedEnv {
			defaults[k] = v
		}
	}

	var e2eVars []string //nolint:prealloc
	for k, v := range defaults {
		// Remove conflicts. Env vars that already exist take precedence over our defaults.
		if _, ok := os.LookupEnv(k); ok {
			continue
		}
		e2eVars = append(e2eVars, fmt.Sprintf("%s=%s", k, v))
	}

	env := os.Environ()
	newEnv := make([]string, len(env)+len(e2eVars))
	copy(newEnv, env)
	copy(newEnv[len(env):], e2eVars)

	return newEnv
}

func (c Ctx) CerbosHost() string {
	if hostname, ok := c.ComputedEnv[cerbosHostNameEnvVar]; ok {
		return hostname
	}
	return fmt.Sprintf("cerbos-%s.%s", c.ContextID, c.Namespace())
}

func (c Ctx) Namespace() string {
	return fmt.Sprintf("e2e-%s", c.RunID)
}

func (c Ctx) GRPCAddr() string {
	return fmt.Sprintf("%s:%d", c.CerbosHost(), GRPCPort)
}

func (c Ctx) HTTPAddr() string {
	protocol := "https"
	if c.NoTLS {
		protocol = "http"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, c.CerbosHost(), HTTPPort)
}

func (c Ctx) HealthURL() string {
	return fmt.Sprintf("%s%s", c.HTTPAddr(), HealthEndpoint)
}

func (c Ctx) CommandTimeoutCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.CommandTimeout)
}
