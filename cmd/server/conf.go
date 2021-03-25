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
	// Static defines statically defined TLS settings.
	Static *TLSStaticConf `yaml:"static"`
}

// TLSStaticConf holds static TLS configuration values.
type TLSStaticConf struct {
	// Cert is the path to the TLS certificate file.
	Cert string `yaml:"cert"`
	// Key is the path to the TLS private key file.
	Key string `yaml:"key"`
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

func getServerConf(listenAddrFlag string) (Conf, error) {
	conf := Conf{}

	if err := config.Get(confKey, &conf); err != nil {
		return conf, err
	}

	// override the listenAddr if the flag is defined.
	if listenAddrFlag != "" {
		conf.ListenAddr = listenAddrFlag
	}

	return conf, nil
}
