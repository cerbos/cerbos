// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/cerbos/cerbos/internal/config"
)

func TestConfigValidate(t *testing.T) {
	testCases := []struct {
		name        string
		conf        map[string]any
		wantLoadErr bool
		wantErr     bool
	}{
		{
			name: "valid config",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": ":6666",
					"grpcListenAddr": ":6667",
				},
			},
		},
		{
			name: "invalid httpListenAddr",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": "wibble",
					"grpcListenAddr": ":6667",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid grpcListenAddr",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": ":6666",
					"grpcListenAddr": "wibble",
				},
			},
			wantErr: true,
		},
		{
			name: "unencodedAdminPasswordHash",
			conf: map[string]any{
				"server": map[string]any{
					"adminAPI": map[string]any{
						"enabled": true,
						"adminCredentials": map[string]any{
							"username":     defaultAdminUsername,
							"passwordHash": defaultRawAdminPasswordHash,
						},
					},
				},
			},
			wantLoadErr: true,
		},
		{
			name: "maxActionsPerResource is zero",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": ":6666",
					"grpcListenAddr": ":6667",
					"requests": map[string]any{
						"maxActionsPerResource":  "0",
						"maxResourcesPerRequest": "50",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "maxActionsPerResource is 1000",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": ":6666",
					"grpcListenAddr": ":6667",
					"requests": map[string]any{
						"maxActionsPerResource":  "1000",
						"maxResourcesPerRequest": "50",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "maxResourcesPerRequest is zero",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": ":6666",
					"grpcListenAddr": ":6667",
					"requests": map[string]any{
						"maxActionsPerResource":  "50",
						"maxResourcesPerRequest": "0",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "maxResourcesPerRequest is 1000",
			conf: map[string]any{
				"server": map[string]any{
					"httpListenAddr": ":6666",
					"grpcListenAddr": ":6667",
					"requests": map[string]any{
						"maxActionsPerResource":  "50",
						"maxResourcesPerRequest": "1000",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := config.LoadMap(tc.conf)
			if tc.wantLoadErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			var sc Conf
			err = config.GetSection(&sc)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAdminAPICredentials(t *testing.T) {
	nonDefaultUsername := "someusername"

	nonDefaultPasswordHash, err := bcrypt.GenerateFromPassword([]byte("somepassword"), bcrypt.DefaultCost)
	require.NoError(t, err)

	nonDefaultPasswordHashEncoded := base64.StdEncoding.EncodeToString(nonDefaultPasswordHash)

	testCases := []struct {
		name           string
		conf           map[string]any
		wantUsername   string
		wantPasswdHash []byte
		wantErr        bool
	}{
		{
			name: "defaults",
			conf: map[string]any{
				"server": map[string]any{
					"adminAPI": map[string]any{
						"enabled": true,
					},
				},
			},
			wantUsername:   defaultAdminUsername,
			wantPasswdHash: []byte(defaultRawAdminPasswordHash),
		},
		{
			name: "userProvidedNonDefault",
			conf: map[string]any{
				"server": map[string]any{
					"adminAPI": map[string]any{
						"enabled": true,
						"adminCredentials": map[string]any{
							"username":     nonDefaultUsername,
							"passwordHash": nonDefaultPasswordHashEncoded,
						},
					},
				},
			},
			wantUsername:   nonDefaultUsername,
			wantPasswdHash: nonDefaultPasswordHash,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, config.LoadMap(tc.conf))

			var sc Conf
			err := config.GetSection(&sc)
			require.NoError(t, err)

			adminUser, adminPasswdHash, err := sc.AdminAPI.AdminCredentials.usernameAndPasswordHash()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.wantUsername, adminUser)
				require.Equal(t, tc.wantPasswdHash, adminPasswdHash)
			}
		})
	}
}

func TestAdminCredentialsAreUnsafe(t *testing.T) {
	testCases := []struct {
		name         string
		passwordHash string
		wantUnsafe   bool
		wantErr      error
	}{
		{
			name:         "default hash",
			passwordHash: defaultRawAdminPasswordHash,
			wantUnsafe:   true,
		},
		{
			name:         "different hash of default password",
			passwordHash: "$2y$10$02xMlSOEujPEUfAubRYSTOrmY91lLUhtNMvqBtP3PwA95g5WKokkS",
			wantUnsafe:   true,
		},
		{
			name:         "hash of different password",
			passwordHash: "$2y$10$vPtxKpM/nSlTNhigYx0AteBxm2A2b4XbxUgDE4FuFlk6PNFL5o7Jq",
			wantUnsafe:   false,
		},
		{
			name:         "invalid hash",
			passwordHash: "",
			wantErr:      bcrypt.ErrHashTooShort,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			unsafe, err := adminCredentialsAreUnsafe([]byte(tc.passwordHash))

			require.Equal(t, tc.wantUnsafe, unsafe)

			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}
