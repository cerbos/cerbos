package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/cmd/server"
	"github.com/cerbos/cerbos/pkg/config"
)

type Server struct {
	DataDir    string `yaml:"dataDir"`
	ListenAddr string `yaml:"listenAddr"`
	TLS        *TLS   `yaml:"tls"`
}

type TLS struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
}

func TestLoad(t *testing.T) {
	require.NoError(t, config.Load(filepath.Join("testdata", "test_load.yaml")))

	t.Run("single_value_read", func(t *testing.T) {
		var haveCert string
		require.NoError(t, config.Get("server.tls.certificate", &haveCert))
		require.Equal(t, "cert", haveCert)
	})

	t.Run("tree_read_with_interpolation", func(t *testing.T) {
		wantServer := Server{
			DataDir:    fmt.Sprintf("%s/tmp", os.Getenv("HOME")),
			ListenAddr: ":9999",
			TLS: &TLS{
				Certificate: "cert",
				Key:         "key",
			},
		}

		var haveServer Server
		require.NoError(t, config.Get("server", &haveServer))
		require.Equal(t, wantServer, haveServer)
	})
}

func TestCerbosConfig(t *testing.T) {
	t.Run("valid_server_conf", func(t *testing.T) {
		require.NoError(t, config.Load(filepath.Join("testdata", "valid_server_conf.yaml")))
		var serverConf server.Conf
		require.NoError(t, config.Get("server", &serverConf))
		require.Equal(t, ":3592", serverConf.HTTPListenAddr)
		require.Equal(t, ":3593", serverConf.GRPCListenAddr)
	})

	t.Run("invalid_server_listen_addr", func(t *testing.T) {
		require.NoError(t, config.Load(filepath.Join("testdata", "invalid_server_listen_addr.yaml")))
		var serverConf server.Conf
		require.Error(t, config.Get("server", &serverConf))
	})
}
