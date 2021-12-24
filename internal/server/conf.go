// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/util"
)

const (
	confKey                     = "server"
	defaultHTTPListenAddr       = ":3592"
	defaultGRPCListenAddr       = ":3593"
	defaultAdminUsername        = "cerbos"
	defaultRawAdminPasswordHash = "$2y$10$VlPwcwpgcGZ5KjTaN1Pzk.vpFiQVG6F2cSWzQa9RtrNo3IacbzsEi" //nolint:gosec
)

var (
	defaultAdminPasswordHash = base64.StdEncoding.EncodeToString([]byte(defaultRawAdminPasswordHash))
	errAdminCredsUndefined   = errors.New("admin credentials not defined")
)

// Conf is required configuration for the server.
type Conf struct {
	// AdminAPI defines the admin API configuration.
	AdminAPI AdminAPIConf `yaml:"adminAPI"`
	// TLS defines the TLS configuration for the server.
	TLS *TLSConf `yaml:"tls"`
	// HTTPListenAddr is the dedicated HTTP address.
	HTTPListenAddr string `yaml:"httpListenAddr" conf:"required,example=\":3592\""`
	// GRPCListenAddr is the dedicated GRPC address.
	GRPCListenAddr string `yaml:"grpcListenAddr" conf:"required,example=\":3593\""`
	// CORS defines the CORS configuration for the server.
	CORS CORSConf `yaml:"cors"`
	// MetricsEnabled defines whether the metrics endpoint is enabled.
	MetricsEnabled bool `yaml:"metricsEnabled" conf:",example=true"`
	// LogRequestPayloads defines whether the request payloads should be logged.
	LogRequestPayloads bool `yaml:"logRequestPayloads" conf:",example=false"`
	// PlaygroundEnabled defines whether the playground API is enabled.
	PlaygroundEnabled bool `yaml:"playgroundEnabled" conf:",example=false"`
}

// TLSConf holds TLS configuration.
type TLSConf struct {
	// Cert is the path to the TLS certificate file.
	Cert string `yaml:"cert" conf:",example=/path/to/certificate"`
	// Key is the path to the TLS private key file.
	Key string `yaml:"key" conf:",example=/path/to/private_key"`
	// CACert is the path to the optional CA certificate for verifying client requests.
	CACert string `yaml:"caCert" conf:",example=/path/to/CA_certificate"`
}

type CORSConf struct {
	// AllowedOrigins is the contents of the allowed-origins header.
	AllowedOrigins []string `yaml:"allowedOrigins" conf:",example=['*']"`
	// AllowedHeaders is the contents of the allowed-headers header.
	AllowedHeaders []string `yaml:"allowedHeaders" conf:",example=['content-type']"`
	// Disabled sets whether CORS is disabled.
	Disabled bool `yaml:"disabled" conf:",example=false"`
	// MaxAge is the max age of the CORS preflight check.
	MaxAge time.Duration `yaml:"maxAge" conf:",example=10s"`
}

type AdminAPIConf struct {
	// AdminCredentials defines the admin user credentials.
	AdminCredentials *AdminCredentialsConf `yaml:"adminCredentials"`
	// Enabled defines whether the admin API is enabled.
	Enabled bool `yaml:"enabled" conf:",example=true"`
}

type AdminCredentialsConf struct {
	// Username is the hardcoded username to use for authentication.
	Username string `yaml:"username" conf:",example=cerbos"`
	// PasswordHash is the base64-encoded bcrypt hash of the password to use for authentication.
	PasswordHash string `yaml:"passwordHash" conf:",example=JDJ5JDEwJEdEOVFzZDE2VVhoVkR0N2VkUFBVM09nalc0QnNZaC9xc2E4bS9mcUJJcEZXenp5OUpjMi91Cgo="`
}

func (a *AdminCredentialsConf) isUnsafe() bool {
	if a == nil {
		return false
	}

	return a.Username == defaultAdminUsername || a.PasswordHash == defaultAdminPasswordHash
}

func (a *AdminCredentialsConf) usernameAndPasswordHash() (string, []byte, error) {
	if a == nil {
		return "", nil, errAdminCredsUndefined
	}

	passwordHashBytes, err := base64.StdEncoding.DecodeString(a.PasswordHash)
	if err != nil {
		return "", nil, fmt.Errorf("failed to base64 decode admin passwordHash: %w", err)
	}

	return a.Username, passwordHashBytes, nil
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.HTTPListenAddr = defaultHTTPListenAddr
	c.GRPCListenAddr = defaultGRPCListenAddr
	c.MetricsEnabled = true
	if c.AdminAPI.AdminCredentials == nil {
		c.AdminAPI.AdminCredentials = &AdminCredentialsConf{
			Username:     defaultAdminUsername,
			PasswordHash: defaultAdminPasswordHash,
		}
	}
}

func (c *Conf) Validate() (errs error) {
	if _, _, err := util.ParseListenAddress(c.HTTPListenAddr); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("invalid httpListenAddr '%s': %w", c.HTTPListenAddr, err))
	}

	if _, _, err := util.ParseListenAddress(c.GRPCListenAddr); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("invalid grpcListenAddr '%s': %w", c.GRPCListenAddr, err))
	}

	return errs
}
