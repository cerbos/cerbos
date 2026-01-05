// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/config"
)

func TestConfigValidate(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]any
		wantErr bool
	}{
		{
			name: "valid jwt",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{"id": "foo", "remote": map[string]any{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "bar", "local": map[string]any{"data": "data"}},
						},
					},
				},
			},
		},
		{
			name: "duplicate jwt keyset ID",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{"id": "foo", "remote": map[string]any{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "foo", "local": map[string]any{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty jwt keyset",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{"id": "foo"},
							{"id": "bar", "local": map[string]any{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "both remote and local defined in jwt keyset",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{
								"id": "foo",
								"remote": map[string]any{
									"url":   "https://domain.tld/.well-known/foo.jwks",
									"local": map[string]any{"data": "data"},
								},
							},
							{"id": "bar", "local": map[string]any{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty remote URL in jwt keyset",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{"id": "foo", "remote": map[string]any{"url": ""}},
							{"id": "bar", "local": map[string]any{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "both local data and file defined in jwt keyset",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{"id": "foo", "remote": map[string]any{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "bar", "local": map[string]any{"data": "data", "file": "/path"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "both local data and file not defined in jwt keyset",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"keySets": []map[string]any{
							{"id": "foo", "remote": map[string]any{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "bar", "local": map[string]any{"data": "", "file": ""}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "positive acceptableTimeSkew",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"acceptableTimeSkew": 1 * time.Minute,
					},
				},
			},
		},
		{
			name: "negative acceptableTimeSkew",
			conf: map[string]any{
				"auxData": map[string]any{
					"jwt": map[string]any{
						"acceptableTimeSkew": -1 * time.Minute,
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, config.LoadMap(tc.conf))

			var ac auxdata.Conf
			err := config.GetSection(&ac)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
