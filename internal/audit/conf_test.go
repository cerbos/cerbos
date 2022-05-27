// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

func TestConfigLoad(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		conf := map[string]any{
			"audit": map[string]any{
				"enabled": true,
				"backend": "local",
				"local": map[string]any{
					"storagePath": t.TempDir(),
				},
				"wibble": "wobble",
			},
		}

		require.NoError(t, config.LoadMap(conf))

		c := &audit.Conf{}
		err := config.GetSection(c)

		require.NoError(t, err)
		require.True(t, c.Enabled)
		require.True(t, c.AccessLogsEnabled)
		require.True(t, c.DecisionLogsEnabled)
		require.Equal(t, "local", c.Backend)
	})

	t.Run("overrides", func(t *testing.T) {
		conf := map[string]any{
			"audit": map[string]any{
				"enabled":             true,
				"accessLogsEnabled":   false,
				"decisionLogsEnabled": false,
				"backend":             "file",
				"file": map[string]any{
					"path": "stdout",
				},
				"wibble": "wobble",
			},
		}

		require.NoError(t, config.LoadMap(conf))

		c := &audit.Conf{}
		err := config.GetSection(c)

		require.NoError(t, err)
		require.True(t, c.Enabled)
		require.False(t, c.AccessLogsEnabled)
		require.False(t, c.DecisionLogsEnabled)
		require.Equal(t, "file", c.Backend)
	})
}
