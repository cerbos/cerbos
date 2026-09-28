// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/audit"
	hubaudit "github.com/cerbos/cerbos/internal/audit/hub"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/hub"
)

func TestConfig(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]any
		env     map[string]string
		want    *hubaudit.Conf
		wantErr string
	}{
		{
			name: "file/workspace",
			conf: map[string]any{
				"audit": map[string]any{
					"hub": map[string]any{
						"workspaceID": "557IL0VLB2DR",
						"storagePath": "/tmp",
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_DEPLOYMENT_ID": "ignored",
				"CERBOS_HUB_WORKSPACE_ID":  "ignored",
			},
			want: &hubaudit.Conf{
				WorkspaceID: "557IL0VLB2DR",
				StoragePath: "/tmp",
			},
		},
		{
			name: "file/deployment",
			conf: map[string]any{
				"audit": map[string]any{
					"hub": map[string]any{
						"deploymentID": "QFR8188SHT8G",
						"storagePath":  "/tmp",
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_DEPLOYMENT_ID": "ignored",
			},
			want: &hubaudit.Conf{
				DeploymentID: "QFR8188SHT8G",
				StoragePath:  "/tmp",
			},
		},
		{
			name: "env/workspace",
			conf: map[string]any{
				"audit": map[string]any{
					"hub": map[string]any{
						"storagePath": "/tmp",
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_DEPLOYMENT_ID": "ignored",
				"CERBOS_HUB_WORKSPACE_ID":  "557IL0VLB2DR",
			},
			want: &hubaudit.Conf{
				WorkspaceID: "557IL0VLB2DR",
				StoragePath: "/tmp",
			},
		},
		{
			name: "env/deployment",
			conf: map[string]any{
				"audit": map[string]any{
					"hub": map[string]any{
						"storagePath": "/tmp",
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_DEPLOYMENT_ID": "QFR8188SHT8G",
			},
			want: &hubaudit.Conf{
				DeploymentID: "QFR8188SHT8G",
				StoragePath:  "/tmp",
			},
		},
		{
			name: "unspecified-target",
			conf: map[string]any{
				"audit": map[string]any{
					"hub": map[string]any{
						"storagePath": "/tmp",
					},
				},
			},
			want: &hubaudit.Conf{
				StoragePath: "/tmp",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hub.ClearEnvVars(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			err := config.LoadMap(tc.conf)
			require.NoError(t, err)

			have := new(hubaudit.Conf)
			err = config.Get(audit.ConfKey+"."+hubaudit.Backend, have)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(tc.want, have, cmpopts.IgnoreTypes(local.Conf{}, hubaudit.IngestConf{})))
		})
	}
}
