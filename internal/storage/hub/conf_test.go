// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage"
	hubstore "github.com/cerbos/cerbos/internal/storage/hub"
)

func TestConfig(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]any
		env     map[string]string
		wantErr string
	}{
		{
			name: "file/valid-config",
			conf: map[string]any{
				"hub": map[string]any{
					"credentials": map[string]any{
						"pdpID":        "pdp-id",
						"clientID":     "client-id",
						"clientSecret": "client-secret",
					},
				},
				"storage": map[string]any{
					"hub": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"deploymentID": "5D9JMKYXEHII",
							"tempDir":      "/tmp",
							"cacheDir":     "/tmp",
						},
					},
				},
			},
		},
		{
			name: "env/valid-config",
			conf: map[string]any{
				"storage": map[string]any{
					"hub": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_CLIENT_ID":     "client-id",
				"CERBOS_HUB_CLIENT_SECRET": "client-secret",
				"CERBOS_HUB_PDP_ID":        "pdp-id",
				"CERBOS_HUB_DEPLOYMENT_ID": "5D9JMKYXEHII",
			},
		},
		{
			name: "env/invalid-config-missing-deployment-id",
			conf: map[string]any{
				"storage": map[string]any{
					"hub": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_CLIENT_ID":     "client-id",
				"CERBOS_HUB_CLIENT_SECRET": "client-secret",
				"CERBOS_HUB_PDP_ID":        "pdp-id",
			},
			wantErr: "exactly one of storage.hub.remote.deploymentID or storage.hub.remote.playgroundID must be specified",
		},
		{
			name: "env/invalid-config-missing-client-secret",
			conf: map[string]any{
				"storage": map[string]any{
					"hub": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_CLIENT_ID":     "client-id",
				"CERBOS_HUB_PDP_ID":        "pdp-id",
				"CERBOS_HUB_DEPLOYMENT_ID": "5D9JMKYXEHII",
			},
			wantErr: "hub.credentials.clientSecret is required",
		},
	}

	want := &hubstore.Conf{
		CacheSize: 1024,
		Remote: &hubstore.RemoteSourceConf{
			DeploymentID: "5D9JMKYXEHII",
			TempDir:      "/tmp",
			CacheDir:     "/tmp",
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

			have := new(hubstore.Conf)
			err = config.Get(storage.ConfKey+"."+hubstore.DriverName, have)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(want, have))
		})
	}
}
