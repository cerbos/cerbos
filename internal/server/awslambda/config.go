// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"fmt"

	"github.com/alecthomas/kong"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cerbos/cerbos/cmd/cerbos/server"
)

func MkConfStorageOverrides(cwd string, confOverrides map[string]any) error {
	overrides := []string{
		fmt.Sprintf("storage.disk.directory=%s", cwd),
		"storage.disk.watchForChanges=false",
	}
	for _, override := range overrides {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}
	return nil
}

func mkConfServerOverrides(confOverrides map[string]any) error {
	overrides := []string{
		"server.httpListenAddr=unix:/tmp/cerbos.http.sock",
		"server.grpcListenAddr=unix:/tmp/cerbos.grpc.sock",
	}
	for _, override := range overrides {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}
	return nil
}

func mkConfStorageHubOverrides(tmpDir string, confOverrides map[string]any) error {
	overrides := []string{
		fmt.Sprintf("storage.hub.remote.tempDir=%s", tmpDir),
	}
	for _, override := range overrides {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}
	return nil
}

const tempDir string = "/tmp" // Lambda tempDir

func GetConfOverrides(confOverrides map[string]any) error {
	if err := mkConfServerOverrides(confOverrides); err != nil {
		return err
	}
	var cmd server.Cmd
	parser := kong.Must(&cmd)
	if _, err := parser.Parse(nil); err != nil {
		return fmt.Errorf("failed to parse Hub flags: %w", err)
	}
	hubOverrides := server.MkHubOverrides(&cmd)

	for _, hubOverride := range hubOverrides {
		if err := strvals.ParseInto(hubOverride, confOverrides); err != nil {
			return fmt.Errorf("failed to parse Cerbos Hub override: %w", err)
		}
	}
	if len(hubOverrides) != 0 {
		return mkConfStorageHubOverrides(tempDir, confOverrides)
	}
	return nil
}

func HubStorageDriver(confOverrides map[string]any) bool {
	driver, ok := confOverrides["storage.driver"]
	return ok && driver == "hub"
}
