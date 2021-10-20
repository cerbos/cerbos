// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/config"
)

func TestConfigValidate(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid jwt",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{"id": "foo", "remote": map[string]interface{}{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "bar", "local": map[string]interface{}{"data": "data"}},
						},
					},
				},
			},
		},
		{
			name: "duplicate jwt keyset ID",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{"id": "foo", "remote": map[string]interface{}{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "foo", "local": map[string]interface{}{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty jwt keyset",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{"id": "foo"},
							{"id": "bar", "local": map[string]interface{}{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "both remote and local defined in jwt keyset",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{
								"id": "foo",
								"remote": map[string]interface{}{
									"url":   "https://domain.tld/.well-known/foo.jwks",
									"local": map[string]interface{}{"data": "data"},
								},
							},
							{"id": "bar", "local": map[string]interface{}{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty remote URL in jwt keyset",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{"id": "foo", "remote": map[string]interface{}{"url": ""}},
							{"id": "bar", "local": map[string]interface{}{"data": "data"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "both local data and file defined in jwt keyset",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{"id": "foo", "remote": map[string]interface{}{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "bar", "local": map[string]interface{}{"data": "data", "file": "/path"}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "both local data and file not defined in jwt keyset",
			conf: map[string]interface{}{
				"auxData": map[string]interface{}{
					"jwt": map[string]interface{}{
						"keySets": []map[string]interface{}{
							{"id": "foo", "remote": map[string]interface{}{"url": "https://domain.tld/.well-known/foo.jwks"}},
							{"id": "bar", "local": map[string]interface{}{"data": "", "file": ""}},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
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
