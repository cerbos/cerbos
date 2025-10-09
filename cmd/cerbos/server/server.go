// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cerbos/cerbos/pkg/cerbos"
)

const help = `
Examples:

# Start the server

cerbos server

# Start the server with the Admin API enabled and the 'sqlite' storage driver

cerbos server --set=server.adminAPI.enabled=true --set=storage.driver=sqlite3 --set=storage.sqlite3.dsn=':memory:'`

type LogLevelFlag string

func (ll *LogLevelFlag) Decode(ctx *kong.DecodeContext) error {
	var loglevel LogLevelFlag
	if err := ctx.Scan.PopValueInto("log-level", &loglevel); err != nil {
		return err
	}

	*ll = LogLevelFlag(strings.ToLower(string(loglevel)))
	return nil
}

type Cmd struct {
	DebugListenAddr string       `help:"Address to start the gops listener" placeholder:":6666"`
	LogLevel        LogLevelFlag `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
	Config          string       `help:"Path to config file" optional:"" placeholder:".cerbos.yaml" env:"CERBOS_CONFIG"`
	HubBundle       string       `help:"[Legacy] Use Cerbos Hub to pull the policy bundle with the given label. Overrides the store defined in the configuration." optional:"" env:"CERBOS_HUB_BUNDLE,CERBOS_CLOUD_BUNDLE" group:"hubv1" xor:"hub.deployment-id,hub.playground-id"`
	Hub             HubFlags     `embed:"" prefix:"hub."`
	Set             []string     `help:"Config overrides" placeholder:"server.adminAPI.enabled=true"`
}

type HubFlags struct {
	DeploymentID string `help:"Use Cerbos Hub to pull the policy bundle for the given deployment ID. Overrides the store defined in the configuration." optional:"" env:"CERBOS_HUB_DEPLOYMENT_ID" group:"hubv2" xor:"hub-bundle,hub.playground-id"`
	PlaygroundID string `help:"Use Cerbos Hub to pull the policy bundle for the given playground ID. Overrides the store defined in the configuration." optional:"" env:"CERBOS_HUB_PLAYGROUND_ID" group:"hubv2" xor:"hub-bundle,hub.deployment-id"`
}

func MkHubOverrides(c *Cmd) []string {
	switch {
	case c.Hub.DeploymentID != "":
		return []string{
			"storage.driver=hub",
			fmt.Sprintf("storage.hub.remote.deploymentID=%s", hub.DeploymentID),
		}
	case c.Hub.PlaygroundID != "":
		return []string{
			"storage.driver=hub",
			fmt.Sprintf("storage.hub.remote.playgroundID=%s", hub.PlaygroundID),
		}
	case c.HubBundle != "":
		return []string{
			"storage.driver=hub",
			fmt.Sprintf("storage.hub.remote.bundleLabel=%s", c.HubBundle),
		}
	}
	return nil
}

func (c *Cmd) Run() error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	confOverrides := map[string]any{}
	for _, override := range c.Set {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}

	for _, hubOverride := range MkHubOverrides(c) {
		if err := strvals.ParseInto(hubOverride, confOverrides); err != nil {
			return fmt.Errorf("failed to parse Cerbos Hub override [%s]: %w", hubOverride, err)
		}
	}

	return cerbos.Serve(ctx,
		cerbos.WithConfigFile(c.Config),
		cerbos.WithConfig(confOverrides),
		cerbos.WithDebug(c.DebugListenAddr),
		cerbos.WithLogLevel(cerbos.LogLevel(c.LogLevel)),
	)
}

func (c *Cmd) Help() string {
	return help
}
