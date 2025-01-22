// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"testing"
	"time"

	"github.com/cerbos/cloud-api/bundle"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage"
	hubstore "github.com/cerbos/cerbos/internal/storage/hub"
)

func TestConfig(t *testing.T) {
	driverNames := []string{"hub", "bundle"}
	for _, driver := range driverNames {
		t.Run(driver, doTestConfig(driver))
	}
}

func doTestConfig(driver string) func(*testing.T) {
	return func(t *testing.T) {
		testCases := []struct {
			name    string
			conf    map[string]any
			env     map[string]string
			wantErr bool
		}{
			{
				name: "file/legacy-config",
				conf: map[string]any{
					"storage": map[string]any{
						driver: map[string]any{
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
								"connection": map[string]any{
									"apiEndpoint":       "https://api.stg-spitfire.cerbos.tech",
									"bootstrapEndpoint": "https://cdn.stg-spitfire.cerbos.tech",
								},
							},
						},
					},
				},
				wantErr: true,
			},
			{
				name: "file/valid-config-from-hub",
				conf: map[string]any{
					"hub": map[string]any{
						"credentials": map[string]any{
							"pdpID":           "pdp-id",
							"clientID":        "client-id",
							"clientSecret":    "client-secret",
							"workspaceSecret": "workspace-secret",
						},
						"connection": map[string]any{
							"apiEndpoint":       "https://api.stg-spitfire.cerbos.tech",
							"bootstrapEndpoint": "https://cdn.stg-spitfire.cerbos.tech",
						},
					},
					"storage": map[string]any{
						driver: map[string]any{
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
				name: "env/valid-config",
				conf: map[string]any{
					"hub": map[string]any{
						"connection": map[string]any{
							"apiEndpoint":       "https://api.stg-spitfire.cerbos.tech",
							"bootstrapEndpoint": "https://cdn.stg-spitfire.cerbos.tech",
						},
					},
					"storage": map[string]any{
						driver: map[string]any{
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
					"hub": map[string]any{
						"connection": map[string]any{
							"apiEndpoint":       "https://api.stg-spitfire.cerbos.tech",
							"bootstrapEndpoint": "https://cdn.stg-spitfire.cerbos.tech",
						},
					},
					"storage": map[string]any{
						driver: map[string]any{
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
					"hub": map[string]any{
						"connection": map[string]any{
							"apiEndpoint":       "https://api.stg-spitfire.cerbos.tech",
							"bootstrapEndpoint": "https://cdn.stg-spitfire.cerbos.tech",
						},
					},
					"storage": map[string]any{
						driver: map[string]any{
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

		want := &hubstore.Conf{
			BundleVersion: bundle.Version1,
			CacheSize:     1024,
			Credentials: &hub.CredentialsConf{
				PDPID:           "pdp-id",
				ClientID:        "client-id",
				ClientSecret:    "client-secret",
				WorkspaceSecret: "workspace-secret",
			},
			Remote: &hubstore.RemoteSourceConf{
				BundleLabel: "latest",
				TempDir:     "/tmp",
				CacheDir:    "/tmp",
				Connection: &hub.ConnectionConf{
					APIEndpoint:       "https://api.stg-spitfire.cerbos.tech",
					BootstrapEndpoint: "https://cdn.stg-spitfire.cerbos.tech",
					MinRetryWait:      1 * time.Second,
					MaxRetryWait:      120 * time.Second,
					NumRetries:        5,
					HeartbeatInterval: 180 * time.Second,
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				for k, v := range tc.env {
					t.Setenv(k, v)
				}

				err := config.LoadMap(tc.conf)
				require.NoError(t, err)

				have := new(hubstore.Conf)
				err = config.Get(storage.ConfKey+"."+driver, have)
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(want, have, cmpopts.IgnoreFields(hub.CredentialsConf{}, "InstanceID", "SecretKey")))
			})
		}
	}
}
