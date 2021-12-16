// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../hack/tools/confdocs.go

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

// Required. Configuration pertaining to the server.
type Conf struct {
	// The dedicated HTTP address to listen.
	HTTPListenAddr string `yaml:"httpListenAddr" conf:"required,defaultValue=\":3592\""`
	// The dedicated HTTP address to listen.
	GRPCListenAddr string `yaml:"grpcListenAddr" conf:"required,defaultValue=\":3593\""`
	// The TLS configuration for the server.
	TLS *TLSConf `yaml:"tls"`
	// CORS defines the CORS configuration for the server.
	CORS CORSConf `yaml:"cors"`
	// Defines whether the metrics endpoint (/_cerbos/metrics) is enabled.
	MetricsEnabled bool `yaml:"metricsEnabled" conf:",defaultValue=true"`
	// Defines whether the request payloads should be logged.
	LogRequestPayloads bool `yaml:"logRequestPayloads" conf:",defaultValue=false"`
	// Defines whether the playground API is enabled.
	PlaygroundEnabled bool `yaml:"playgroundEnabled" conf:",defaultValue=false"`
	// Defines the admin API configuration.
	AdminAPI AdminAPIConf `yaml:"adminAPI"`
}

// TLSConf holds TLS configuration.
type TLSConf struct {
	// Path to the TLS certificate file.
	Cert string `yaml:"cert" conf:",defaultValue=/path/to/certificate"`
	// Path to the TLS private key file.
	Key string `yaml:"key" conf:",defaultValue=/path/to/private_key"`
	// Path to the optional CA certificate for verifying client requests.
	CACert string `yaml:"caCert" conf:",defaultValue=/path/to/CA_certificate"`
}

type CORSConf struct {
	// Sets whether CORS is disabled.
	Disabled bool `yaml:"disabled" conf:",defaultValue=false"`
	// The contents of the allowed-origins header.
	AllowedOrigins []string `yaml:"allowedOrigins" conf:",defaultValue=['*']"`
	// The contents of the allowed-headers header.
	AllowedHeaders []string `yaml:"allowedHeaders" conf:",defaultValue=['content-type']"`
	// The max age of the CORS preflight check.
	MaxAge time.Duration `yaml:"maxAge" conf:",defaultValue=10s"`
}

type AdminAPIConf struct {
	// Enabled defines whether the admin API is enabled.
	Enabled bool `yaml:"enabled" conf:",defaultValue=true"`
	// AdminCredentials defines the admin user credentials.
	AdminCredentials *AdminCredentialsConf `yaml:"adminCredentials"`
}

type AdminCredentialsConf struct {
	// Username is the hardcoded username to use for authentication.
	Username string `yaml:"username" conf:",defaultValue=cerbos"`
	// PasswordHash is the base64-encoded bcrypt hash of the password to use for authentication.
	PasswordHash string `yaml:"passwordHash" conf:",defaultValue=JDJ5JDEwJEdEOVFzZDE2VVhoVkR0N2VkUFBVM09nalc0QnNZaC9xc2E4bS9mcUJJcEZXenp5OUpjMi91Cgo="`
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
