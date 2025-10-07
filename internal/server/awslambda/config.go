// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import "fmt"

func MkConfOverrides(cwd string) map[string]any, error {
	confOverrides := map[string]any{}
	overrides = string[]{fmt.Sprintf("storage.disk.directory=%s", cwd), "storage.disk.watchForChanges=false"}
	for _, override := range overrides {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return nil, fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}
	return confOverrides, nil
}
