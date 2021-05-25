// Copyright 2021 Zenauth Ltd.

package server

import (
	"fmt"

	"github.com/cerbos/cerbos/internal/util"
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
	// MetricsEnabled defines whether the metrics endpoint is enabled.
	MetricsEnabled bool `yaml:"metricsEnabled"`
	// LogRequestPayloads defines whether the request payloads should be logged.
	LogRequestPayloads bool `yaml:"logRequestPayloads"`
	// PlaygroundEnabled defines whether the playground API is enabled.
	PlaygroundEnabled bool `yaml:"playgroundEnabled"`
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

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.HTTPListenAddr = defaultHTTPListenAddr
	c.GRPCListenAddr = defaultGRPCListenAddr
	c.MetricsEnabled = true
}

func (c *Conf) Validate() error {
	if _, _, err := util.ParseListenAddress(c.HTTPListenAddr); err != nil {
		return fmt.Errorf("invalid httpListenAddr '%s': %w", c.HTTPListenAddr, err)
	}

	if _, _, err := util.ParseListenAddress(c.GRPCListenAddr); err != nil {
		return fmt.Errorf("invalid grpcListenAddr '%s': %w", c.GRPCListenAddr, err)
	}

	return nil
}
