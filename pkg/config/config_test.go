package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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
	require.NoError(t, Load(filepath.Join("testdata", "test.yaml")))

	t.Run("single_value_read", func(t *testing.T) {
		var haveCert string
		require.NoError(t, Get("server.tls.certificate", &haveCert))
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
		require.NoError(t, Get("server", &haveServer))
		require.Equal(t, wantServer, haveServer)
	})
}
