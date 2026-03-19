// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/adrg/xdg"
	"github.com/alecthomas/kong"
	"github.com/zalando/go-keyring"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/cerbos/cerbos/internal/observability/logging"
)

var (
	ClientID      = "7dMG4MO7GXv4liZFoLDDzqM4yN8s0YFy"
	DeviceAuthURL = "https://spitfire-development.eu.auth0.com/oauth/device/code"
)

type Cmd struct {
	LogLevel string `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
}

func (c *Cmd) Run(k *kong.Kong, cmd *Cmd) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	logging.InitLogging(ctx, c.LogLevel, nil)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.L().Named("auth")
	config := &oauth2.Config{
		ClientID: ClientID,
		Scopes:   []string{"openid"},
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: DeviceAuthURL,
		},
	}
	verifier := oauth2.GenerateVerifier()
	response, err := config.DeviceAuth(ctx, oauth2.S256ChallengeOption(verifier))
	if err != nil {
		log.Error("Failed to start auth flow", zap.Error(err))
		return fmt.Errorf("failed to start auth flow: %w", err)
	}

	fmt.Fprintf(k.Stdout, "Log in and connect this machine to your account by visiting %s\n", response.VerificationURIComplete)
	token, err := config.DeviceAccessToken(ctx, response)
	if err != nil {
		log.Error("Failed to obtain token", zap.Error(err))
		return fmt.Errorf("failed to obtain token: %w", err)
	}

	if err := saveToken(log, token); err != nil {
		log.Error("Failed to save token", zap.Error(err))
		return fmt.Errorf("failed to save token: %w", err)
	}

	fmt.Fprintln(k.Stdout, "Successfully logged in to Cerbos Hub")
	return nil
}

func saveToken(log *zap.Logger, token *oauth2.Token) error {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := keyring.Set("cerbosctl", "token", string(tokenBytes)); err != nil {
		log.Debug("Failed to save token to key ring: falling back to disk storage", zap.Error(err))
		savePath, err := xdg.StateFile(".cerbosctl")
		if err != nil {
			log.Debug("Failed to determine path to credentials", zap.Error(err))
			return fmt.Errorf("failed to determine path to credentials: %w", err)
		}

		credentialsFile, err := os.Create(savePath)
		if err != nil {
			log.Debug("Failed to create file", zap.Error(err))
			return fmt.Errorf("failed to save ")
		}
		defer credentialsFile.Close()

		n, err := credentialsFile.Write(tokenBytes)
		if err != nil || n != len(tokenBytes) {
			log.Debug("Failed to write token", zap.Error(err))
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	return nil
}
