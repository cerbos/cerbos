// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cloud-api/base"
)

type Cmd struct {
	LogLevel      string `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
	APIEndpoint   string `name:"api-endpoint" default:"https://api.cerbos.cloud" env:"CERBOS_HUB_API_ENDPOINT"`
	ClientID      string `name:"client-id" help:"Client ID of the access credential" env:"CERBOS_HUB_CLIENT_ID" and:"client-id,client-secret"`
	ClientSecret  string `name:"client-secret" help:"Client secret of the access credential" env:"CERBOS_HUB_CLIENT_SECRET" and:"client-id,client-secret"` //nolint:gosec
	TLSCACert     string `name:"tls-ca-cert" hidden:"" help:"Path to the CA certificate for verifying server identity" type:"existingfile" env:"CERBOS_HUB_TLS_CA_CERT"`
	TLSClientCert string `name:"tls-client-cert" hidden:"" help:"Path to the TLS client certificate" type:"existingfile" env:"CERBOS_HUB_TLS_CLIENT_CERT" and:"tls-client-key"`
	TLSClientKey  string `name:"tls-client-key" hidden:"" help:"Path to the TLS client key" type:"existingfile" env:"CERBOS_HUB_TLS_CLIENT_KEY" and:"tls-client-cert"`
	TLSInsecure   bool   `name:"tls-insecure" hidden:"" help:"Skip validating server certificate" env:"CERBOS_HUB_TLS_INSECURE"`
}

func (c *Cmd) Run(k *kong.Kong, cmd *Cmd) error {
	tlsConf, err := c.buildTLSConf()
	if err != nil {
		return err
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	logging.InitLogging(ctx, c.LogLevel, nil)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.L().Named("auth")

	if c.ClientID != "" && c.ClientSecret != "" {
		log.Debug("Logging in using client credentials")
		if err := base.ClientLogin(ctx, c.APIEndpoint, tlsConf, c.ClientID, c.ClientSecret); err != nil {
			log.Error("Failed to log in using client credentials", zap.Error(err))
			return err
		}

		log.Info("Successfully authenticated using client credentials")
		return nil
	}

	log.Debug("Initiating device auth flow")
	if err := base.DeviceLogin(ctx, c.APIEndpoint, tlsConf); err != nil {
		log.Error("Failed to authenticate", zap.Error(err))
		return err
	}

	log.Info("Device successfully authenticated")
	return nil
}

func (c *Cmd) buildTLSConf() (*tls.Config, error) {
	tlsConf := util.DefaultTLSConfig()

	if c.TLSInsecure {
		tlsConf.InsecureSkipVerify = true
	}

	if c.TLSCACert != "" {
		bs, err := os.ReadFile(c.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate from %s: %w", c.TLSCACert, err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append CA certificates to the pool")
		}

		tlsConf.RootCAs = certPool
	}

	if c.TLSClientCert != "" && c.TLSClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(c.TLSClientCert, c.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key from [%s, %s]: %w", c.TLSClientCert, c.TLSClientKey, err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	return tlsConf, nil
}
