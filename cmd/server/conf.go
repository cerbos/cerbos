package server

import (
	"fmt"

	"github.com/cerbos/cerbos/pkg/config"
)

const (
	confKey               = "server"
	defaultHTTPListenAddr = ":3592"
	defaultGRPCListenAddr = ":3593"
)

// Conf holds configuration pertaining to the server.
type Conf struct {
	// HTTPListenAddr is the dedicated HTTP address.
	HTTPListenAddr string `yaml:"httpListenAddr"`
	// GRPCListenAddr is the dedicated GRPC address.
	GRPCListenAddr string `yaml:"grpcListenAddr"`
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
	if c.HTTPListenAddr == "" {
		c.HTTPListenAddr = defaultHTTPListenAddr
	}

	if c.GRPCListenAddr == "" {
		c.GRPCListenAddr = defaultGRPCListenAddr
	}

	if _, _, err := parseListenAddress(c.HTTPListenAddr); err != nil {
		return fmt.Errorf("invalid httpListenAddr '%s': %w", c.HTTPListenAddr, err)
	}

	if _, _, err := parseListenAddress(c.GRPCListenAddr); err != nil {
		return fmt.Errorf("invalid grpcListenAddr '%s': %w", c.GRPCListenAddr, err)
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
