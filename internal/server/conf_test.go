// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/server"
)

func TestConfigValidate(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid config",
			conf: map[string]interface{}{
				"server": map[string]interface{}{
					"httpListenAddr": ":6666",
					"grpcListenAddr": ":6667",
				},
			},
		},
		{
			name: "invalid httpListenAddr",
			conf: map[string]interface{}{
				"server": map[string]interface{}{
					"httpListenAddr": "wibble",
					"grpcListenAddr": ":6667",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid grpcListenAddr",
			conf: map[string]interface{}{
				"server": map[string]interface{}{
					"httpListenAddr": ":6666",
					"grpcListenAddr": "wibble",
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, config.LoadMap(tc.conf))

			var sc server.Conf
			err := config.GetSection(&sc)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
