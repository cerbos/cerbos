// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package hub

import (
	"os"
	"testing"
)

func ClearEnvVars(t *testing.T) {
	t.Helper()
	existingValues := make(map[string]string)
	for _, varNames := range envVars {
		for _, varName := range varNames {
			val, set := os.LookupEnv(varName)
			if set {
				existingValues[varName] = val
				t.Logf("Unsetting %s", varName)
				os.Unsetenv(varName)
			}
		}
	}

	t.Cleanup(func() {
		for varName, varVal := range existingValues {
			//nolint:usetesting
			os.Setenv(varName, varVal)
		}
	})
}
