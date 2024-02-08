// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage/bundle"
)

func TestConfig(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]any
		env     map[string]string
		wantErr bool
	}{
		{
			name: "file/valid-config",
			conf: map[string]any{
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"credentials": map[string]any{
							"pdpID":           "pdp-id",
							"clientID":        "client-id",
							"clientSecret":    "client-secret",
							"workspaceSecret": "workspace-secret",
						},
						"remote": map[string]any{
							"bundleLabel": "latest",
							"tempDir":     "/tmp",
							"cacheDir":    "/tmp",
						},
					},
				},
			},
		},
		{
			name: "file/valid-legacy-config",
			conf: map[string]any{
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"credentials": map[string]any{
							"instanceID":   "pdp-id",
							"clientID":     "client-id",
							"clientSecret": "client-secret",
							"secretKey":    "workspace-secret",
						},
						"remote": map[string]any{
							"bundleLabel": "latest",
							"tempDir":     "/tmp",
							"cacheDir":    "/tmp",
						},
					},
				},
			},
		},
		{
			name: "file/invalid-config-missing-bundle-label",
			conf: map[string]any{
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"credentials": map[string]any{
							"pdpID":           "pdp-id",
							"clientID":        "client-id",
							"clientSecret":    "client-secret",
							"workspaceSecret": "workspace-secret",
						},
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "file/valid-credentials-from-hub",
			conf: map[string]any{
				"hub": map[string]any{
					"credentials": map[string]any{
						"pdpID":           "pdp-id",
						"clientID":        "client-id",
						"clientSecret":    "client-secret",
						"workspaceSecret": "workspace-secret",
					},
				},
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"bundleLabel": "latest",
							"tempDir":     "/tmp",
							"cacheDir":    "/tmp",
						},
					},
				},
			},
		},
		{
			name: "file/duplicate-credentials",
			conf: map[string]any{
				"hub": map[string]any{
					"credentials": map[string]any{
						"pdpID":           "pdp-id",
						"clientID":        "client-id",
						"clientSecret":    "client-secret",
						"workspaceSecret": "workspace-secret",
					},
				},
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"credentials": map[string]any{
							"pdpID":           "pdp-id",
							"clientID":        "client-id",
							"clientSecret":    "client-secret",
							"workspaceSecret": "workspace-secret",
						},
						"remote": map[string]any{
							"bundleLabel": "latest",
							"tempDir":     "/tmp",
							"cacheDir":    "/tmp",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "env/valid-config",
			conf: map[string]any{
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_CLIENT_ID":        "client-id",
				"CERBOS_HUB_CLIENT_SECRET":    "client-secret",
				"CERBOS_HUB_WORKSPACE_SECRET": "workspace-secret",
				"CERBOS_HUB_PDP_ID":           "pdp-id",
				"CERBOS_HUB_BUNDLE":           "latest",
			},
		},
		{
			name: "env/valid-legacy-config",
			conf: map[string]any{
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			env: map[string]string{
				"CERBOS_CLOUD_CLIENT_ID":     "client-id",
				"CERBOS_CLOUD_CLIENT_SECRET": "client-secret",
				"CERBOS_CLOUD_SECRET_KEY":    "workspace-secret",
				"CERBOS_PDP_ID":              "pdp-id",
				"CERBOS_CLOUD_BUNDLE":        "latest",
			},
		},
		{
			name: "env/invalid-config-missing-bundle-label",
			conf: map[string]any{
				"storage": map[string]any{
					"bundle": map[string]any{
						"cacheSize": 1024,
						"remote": map[string]any{
							"tempDir":  "/tmp",
							"cacheDir": "/tmp",
						},
					},
				},
			},
			env: map[string]string{
				"CERBOS_HUB_CLIENT_ID":        "client-id",
				"CERBOS_HUB_CLIENT_SECRET":    "client-secret",
				"CERBOS_HUB_WORKSPACE_SECRET": "workspace-secret",
				"CERBOS_HUB_PDP_ID":           "pdp-id",
			},
			wantErr: true,
		},
	}

	want := &bundle.Conf{
		CacheSize: 1024,
		Credentials: hub.CredentialsConf{
			PDPID:           "pdp-id",
			ClientID:        "client-id",
			ClientSecret:    "client-secret",
			WorkspaceSecret: "workspace-secret",
		},
		Remote: &bundle.RemoteSourceConf{
			BundleLabel: "latest",
			TempDir:     "/tmp",
			CacheDir:    "/tmp",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			err := config.LoadMap(tc.conf)
			require.NoError(t, err)

			have, err := bundle.GetConf()
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(want, have, cmpopts.IgnoreFields(hub.CredentialsConf{}, "InstanceID", "SecretKey")))
		})
	}
}
