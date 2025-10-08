// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"fmt"

	"helm.sh/helm/v3/pkg/strvals"
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

func MkConfServerOverrides(confOverrides map[string]any) error {
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

func MkConfStorageHubOverrides(tmpDir string, confOverrides map[string]any) error {
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
