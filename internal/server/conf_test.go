// Copyright 2021-2022 Zenauth Ltd.
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
	}

	for _, tc := range testCases {
		tc := tc
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
		unsafe         bool
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
			unsafe:         true,
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
		{
			name: "userProvidedDefaultUsername",
			conf: map[string]any{
				"server": map[string]any{
					"adminAPI": map[string]any{
						"enabled": true,
						"adminCredentials": map[string]any{
							"username":     defaultAdminUsername,
							"passwordHash": nonDefaultPasswordHashEncoded,
						},
					},
				},
			},
			unsafe:         true,
			wantUsername:   defaultAdminUsername,
			wantPasswdHash: nonDefaultPasswordHash,
		},
		{
			name: "userProvidedDefaultPasswordHash",
			conf: map[string]any{
				"server": map[string]any{
					"adminAPI": map[string]any{
						"enabled": true,
						"adminCredentials": map[string]any{
							"username":     nonDefaultUsername,
							"passwordHash": defaultAdminPasswordHash,
						},
					},
				},
			},
			unsafe:         true,
			wantUsername:   nonDefaultUsername,
			wantPasswdHash: []byte(defaultRawAdminPasswordHash),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, config.LoadMap(tc.conf))

			var sc Conf
			err := config.GetSection(&sc)
			require.NoError(t, err)
			require.Equal(t, tc.unsafe, sc.AdminAPI.AdminCredentials.isUnsafe())

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
