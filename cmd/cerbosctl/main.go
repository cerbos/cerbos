// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/audit"
	"github.com/cerbos/cerbos/cmd/cerbosctl/decisions"
	"github.com/cerbos/cerbos/cmd/cerbosctl/list"
	"github.com/cerbos/cerbos/cmd/cerbosctl/version"
	"github.com/cerbos/cerbos/internal/util"
)

type connectConf struct {
	serverAddr    string
	username      string
	password      string
	caCert        string
	tlsClientCert string
	tlsClientKey  string
	insecure      bool
	plaintext     bool
}

var (
	connConf              = connectConf{}
	errInvalidCredentials = errors.New("invalid credentials: username and password must be non-empty strings")
)

var longDesc = `Cerbos instance administration commands
The Cerbos Admin API must be enabled in order for these commands to work.
The Admin API requires credentials. They can be provided using a netrc file, 
environment variables or command-line arguments. 

Environment variables

CERBOS_SERVER: gRPC address of the Cerbos server
CERBOS_USERNAME: Admin username
CERBOS_PASSWORD: Admin password

When more than one method is used to provide credentials, the precedence from lowest to 
highest is: netrc < environment < command line.`

var exampleDesc = `
# Connect to a TLS enabled server while skipping certificate verification and launch the decisions viewer
cerbosctl --server=localhost:3593 --username=user --password=password --insecure decisions

# Connect to a non-TLS server and launch the decisions viewer
cerbosctl --server=localhost:3593 --username=user --password=password --plaintext decisions`

func main() {
	cmd := &cobra.Command{
		Use:               "cerbosctl",
		Short:             "A remote control tool for Cerbos",
		Version:           fmt.Sprintf("%s; commit sha: %s, build date: %s", util.Version, util.Commit, util.BuildDate),
		Long:              longDesc,
		Example:           exampleDesc,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: checkConnConf,
	}

	cmd.PersistentFlags().StringVar(&connConf.serverAddr, "server", "", "Address of the Cerbos server")
	cmd.PersistentFlags().StringVar(&connConf.username, "username", "", "Admin username")
	cmd.PersistentFlags().StringVar(&connConf.password, "password", "", "Admin password")
	cmd.PersistentFlags().StringVar(&connConf.caCert, "ca-cert", "", "Path to the CA certificate for verifying server identity")
	cmd.PersistentFlags().StringVar(&connConf.tlsClientCert, "client-cert", "", "Path to the TLS client certificate")
	cmd.PersistentFlags().StringVar(&connConf.tlsClientKey, "client-key", "", "Path to the TLS client key")
	cmd.PersistentFlags().BoolVar(&connConf.insecure, "insecure", false, "Skip validating server certificate")
	cmd.PersistentFlags().BoolVar(&connConf.plaintext, "plaintext", false, "Use plaintext protocol without TLS")

	cmd.AddCommand(audit.NewAuditCmd(withAdminClient), decisions.NewDecisionsCmd(withAdminClient), version.NewVersionCmd(withClient), list.NewListCmd(withAdminClient))

	if err := cmd.Execute(); err != nil {
		cmd.PrintErrf("ERROR: %v\n", err)
		os.Exit(1)
	}
}

func checkConnConf(_ *cobra.Command, _ []string) error {
	connConf.serverAddr = coalesceWithEnv(connConf.serverAddr, "CERBOS_SERVER")
	connConf.username = coalesceWithEnv(connConf.username, "CERBOS_USERNAME")
	connConf.password = coalesceWithEnv(connConf.password, "CERBOS_PASSWORD")

	if connConf.serverAddr == "" {
		connConf.serverAddr = "localhost:3593"
	}

	return nil
}

func coalesceWithEnv(val, envVar string) string {
	if v := strings.TrimSpace(val); v != "" {
		return v
	}

	if envVal, ok := os.LookupEnv(envVar); ok {
		return envVal
	}

	return val
}

func withAdminClient(fn func(c client.AdminClient, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if connConf.username == "" || connConf.password == "" {
			return errInvalidCredentials
		}
		opts := connConf.toClientOpts()

		ac, err := client.NewAdminClientWithCredentials(connConf.serverAddr, connConf.username, connConf.password, opts...)
		if err != nil {
			return fmt.Errorf("could not create the admin client: %w", err)
		}

		return fn(ac, cmd, args)
	}
}

func withClient(fn func(c client.Client, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts := connConf.toClientOpts()

		ac, err := client.New(connConf.serverAddr, opts...)
		if err != nil {
			return fmt.Errorf("could not create the client: %w", err)
		}

		return fn(ac, cmd, args)
	}
}

func (c connectConf) toClientOpts() []client.Opt {
	opts := make([]client.Opt, 0)
	if c.plaintext {
		opts = append(opts, client.WithPlaintext())
	}
	if c.insecure {
		opts = append(opts, client.WithTLSInsecure())
	}
	if cert := c.caCert; cert != "" {
		opts = append(opts, client.WithTLSCACert(cert))
	}
	if cert := c.tlsClientCert; cert != "" {
		opts = append(opts, client.WithTLSClientCert(cert, c.tlsClientKey))
	}

	return opts
}
