// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cloud-api/base"
)

var (
	DeviceAuthClientID = "7dMG4MO7GXv4liZFoLDDzqM4yN8s0YFy"
	DeviceAuthURL      = "https://spitfire-development.eu.auth0.com/oauth/device/code"
	TokenURL           = "https://spitfire-development.eu.auth0.com/oauth/token"
)

type Cmd struct {
	LogLevel     string `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
	APIEndpoint  string `name:"api-endpoint" default:"https://api.cerbos.cloud" env:"CERBOS_HUB_API_ENDPOINT"`
	ClientID     string `name:"client-id" help:"Client ID of the access credential" env:"CERBOS_HUB_CLIENT_ID" and:"client-id,client-secret"`
	ClientSecret string `name:"client-secret" help:"Client secret of the access credential" env:"CERBOS_HUB_CLIENT_SECRET" and:"client-id,client-secret"` //nolint:gosec
}

func (c *Cmd) Run(k *kong.Kong, cmd *Cmd) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	logging.InitLogging(ctx, c.LogLevel, nil)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.L().Named("auth")

	if c.ClientID != "" && c.ClientSecret != "" {
		log.Debug("Logging in using client credentials")
		if err := base.ClientLogin(ctx, c.APIEndpoint, c.ClientID, c.ClientSecret); err != nil {
			log.Error("Failed to log in using client credentials", zap.Error(err))
			return err
		}

		log.Info("Successfully authenticated using client credentials")
		return nil
	}

	log.Debug("Initiating device auth flow")
	if err := base.DeviceLogin(ctx, c.APIEndpoint, DeviceAuthURL, TokenURL, DeviceAuthClientID); err != nil {
		log.Error("Failed to authenticate", zap.Error(err))
		return err
	}

	log.Info("Device successfully authenticated")
	return nil
}
