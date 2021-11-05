// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/server"
)

var errTestValidate = errors.New("validation error")

type Server struct {
	DataDir    string `yaml:"dataDir"`
	ListenAddr string `yaml:"listenAddr"`
	TLS        *TLS   `yaml:"tls"`
}

func (s *Server) Key() string {
	return "server"
}

func (s *Server) SetDefaults() {
	s.DataDir = "/tmp/data"
	s.ListenAddr = ":6666"
}

func (s *Server) Validate() error {
	if s.DataDir == "xxx" {
		return errTestValidate
	}

	return nil
}

type TLS struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
}

func TestLoad(t *testing.T) {
	require.NoError(t, config.Load(filepath.Join("testdata", "test_load.yaml"), nil))

	t.Run("get_single_value", func(t *testing.T) {
		var haveCert string
		require.NoError(t, config.Get("server.tls.certificate", &haveCert))
		require.Equal(t, "cert", haveCert)
	})

	t.Run("get_tree_with_env_var_interpolation", func(t *testing.T) {
		wantServer := Server{
			DataDir:    fmt.Sprintf("%s/tmp", os.Getenv("HOME")),
			ListenAddr: ":9999",
			TLS: &TLS{
				Certificate: "cert",
				Key:         "key",
			},
		}

		var haveServer1 Server
		require.NoError(t, config.Get("server", &haveServer1))
		require.Equal(t, wantServer, haveServer1)

		var haveServer2 Server
		require.NoError(t, config.GetSection(&haveServer2))
		require.Equal(t, wantServer, haveServer2)
	})
}

func TestOverride(t *testing.T) {
	overrides := map[string]interface{}{
		"server": map[string]interface{}{
			"listenAddr": ":6666",
			"tls": map[string]interface{}{
				"certificate": "newCert",
			},
		},
	}

	require.NoError(t, config.Load(filepath.Join("testdata", "test_load.yaml"), overrides))

	t.Run("get_single_value", func(t *testing.T) {
		var haveCert string
		require.NoError(t, config.Get("server.tls.certificate", &haveCert))
		require.Equal(t, "newCert", haveCert)
	})

	t.Run("get_tree_with_env_var_interpolation", func(t *testing.T) {
		wantServer := Server{
			DataDir:    fmt.Sprintf("%s/tmp", os.Getenv("HOME")),
			ListenAddr: ":6666",
			TLS: &TLS{
				Certificate: "newCert",
				Key:         "key",
			},
		}

		var haveServer1 Server
		require.NoError(t, config.Get("server", &haveServer1))
		require.Equal(t, wantServer, haveServer1)

		var haveServer2 Server
		require.NoError(t, config.GetSection(&haveServer2))
		require.Equal(t, wantServer, haveServer2)
	})
}

func TestDefaults(t *testing.T) {
	require.NoError(t, config.Load(filepath.Join("testdata", "test_defaults.yaml"), nil))

	wantServer := Server{
		DataDir:    "/tmp/data",
		ListenAddr: ":9999",
	}

	var haveServer Server
	require.NoError(t, config.Get("server", &haveServer))
	require.Equal(t, wantServer, haveServer)
}

func TestValidate(t *testing.T) {
	require.NoError(t, config.Load(filepath.Join("testdata", "test_validate.yaml"), nil))

	var haveServer Server
	err := config.Get("server", &haveServer)

	require.ErrorIs(t, err, errTestValidate)
}

func TestCerbosConfig(t *testing.T) {
	t.Run("valid_server_conf", func(t *testing.T) {
		require.NoError(t, config.Load(filepath.Join("testdata", "valid_server_conf.yaml"), nil))
		var serverConf server.Conf
		require.NoError(t, config.Get("server", &serverConf))
		require.Equal(t, ":3592", serverConf.HTTPListenAddr)
		require.Equal(t, ":3593", serverConf.GRPCListenAddr)
	})

	t.Run("invalid_server_listen_addr", func(t *testing.T) {
		require.NoError(t, config.Load(filepath.Join("testdata", "invalid_server_listen_addr.yaml"), nil))
		var serverConf server.Conf
		require.Error(t, config.Get("server", &serverConf))
	})
}

func TestStrictParsing(t *testing.T) {
	testCases := []struct {
		name    string
		conf    map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid config",
			conf: map[string]interface{}{
				"server": map[string]interface{}{
					"listenAddr": ":6666",
					"tls": map[string]interface{}{
						"certificate": "newCert",
					},
				},
			},
		},
		{
			name: "undeclared field",
			conf: map[string]interface{}{
				"server": map[string]interface{}{
					"listenAddr": ":6666",
					"tls": map[string]interface{}{
						"certificate": "newCert",
					},
					"wibble": "wobble",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong case for field",
			conf: map[string]interface{}{
				"server": map[string]interface{}{
					"listenaddr": ":6666",
					"tls": map[string]interface{}{
						"certificate": "newCert",
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

			var s Server
			err := config.GetSection(&s)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
