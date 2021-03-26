package server

import (
	"errors"
	"fmt"
	"net"

	"github.com/cerbos/cerbos/pkg/config"
)

const (
	confKey = "server"
)

var errEmptyListenAddr = errors.New("server.listenAddr must be a non-empty string")

// Conf holds configuration pertaining to the server.
type Conf struct {
	// ListenAddr is the address the server should listen on. Defaults to :9999.
	ListenAddr string `yaml:"listenAddr"`
	// TLS defines the TLS configuration for the server.
	TLS *TLSConf `yaml:"tls"`
}

// TLSConf holds TLS configuration.
type TLSConf struct {
	// Cert is the path to the TLS certificate file.
	Cert string `yaml:"cert"`
	// Key is the path to the TLS private key file.
	Key string `yaml:"key"`
	//	CACert is the path to the optional CA certificate for verifying client requests.
	CACert string `yaml:"caCert"`
}

func (c *Conf) Validate() error {
	if c.ListenAddr == "" {
		return errEmptyListenAddr
	}

	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("invalid listenAddr '%s': %w", c.ListenAddr, err)
	}

	return nil
}

func getServerConf() (Conf, error) {
	conf := Conf{}

	if err := config.Get(confKey, &conf); err != nil {
		return conf, err
	}

	return conf, nil
}
