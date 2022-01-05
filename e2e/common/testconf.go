// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	HTTPPort       = 3592
	GRPCPort       = 3593
	HealthEndpoint = "/_cerbos/health"
)

var TestConf = &TestConfig{}

//nolint:gomnd
func init() {
	srcRoot, err := findSourceRoot()
	if err != nil {
		panic(fmt.Errorf("failed to determine source root: %w", err))
	}

	flag.StringVar(&TestConf.RunID, "run-id", RandomStr(5), "Run ID for this test run")
	flag.StringVar(&TestConf.SourceRoot, "source-root", srcRoot, "Directory containing the Cerbos source code")
	flag.StringVar(&TestConf.CerbosImgRepo, "cerbos-img-repo", "ghcr.io/cerbos/cerbos", "Cerbos image repo")
	flag.StringVar(&TestConf.CerbosImgTag, "cerbos-img-tag", "dev", "Cerbos image tag")
	flag.DurationVar(&TestConf.DeployTimeout, "deploy-timeout", 3*time.Minute, "Test fixture deploy timeout")
}

func findSourceRoot() (string, error) {
	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to find path to current file")
	}

	return filepath.Abs(filepath.Join(filepath.Dir(currFile), "..", ".."))
}

type TestConfig struct {
	RunID         string
	SourceRoot    string
	CerbosImgRepo string
	CerbosImgTag  string
	DeployTimeout time.Duration
}

func (tc *TestConfig) Environ() []string {
	defaults := map[string]string{
		"E2E_RUN_ID":          tc.RunID,
		"E2E_SRC_ROOT":        tc.SourceRoot,
		"E2E_NS":              tc.Namespace(),
		"E2E_CERBOS_IMG_REPO": tc.CerbosImgRepo,
		"E2E_CERBOS_IMG_TAG":  tc.CerbosImgTag,
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

func (tc *TestConfig) CerbosHost() string {
	return fmt.Sprintf("cerbos.%s", tc.Namespace())
}

func (tc *TestConfig) Namespace() string {
	return fmt.Sprintf("e2e-%s", tc.RunID)
}

func (tc *TestConfig) HealthURL() string {
	return fmt.Sprintf("http://%s:%d%s", tc.CerbosHost(), HTTPPort, HealthEndpoint)
}
