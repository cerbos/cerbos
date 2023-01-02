// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "github.com/cerbos/cerbos/client"

type Globals struct {
	Server        string `help:"Address of the Cerbos server" env:"CERBOS_SERVER" default:"localhost:3593"`
	Username      string `help:"Admin username" env:"CERBOS_USERNAME"`
	Password      string `help:"Admin password" env:"CERBOS_PASSWORD"`
	CaCert        string `help:"Path to the CA certificate for verifying server identity"`
	TLSClientCert string `name:"client-cert" help:"Path to the TLS client certificate"`
	TLSClientKey  string `name:"client-key" help:"Path to the TLS client key"`
	Insecure      bool   `help:"Skip validating server certificate"`
	Plaintext     bool   `help:"Use plaintext protocol without TLS"`
}

func (g *Globals) ToClientOpts() []client.Opt {
	opts := make([]client.Opt, 0)
	if g.Plaintext {
		opts = append(opts, client.WithPlaintext())
	}
	if g.Insecure {
		opts = append(opts, client.WithTLSInsecure())
	}
	if cert := g.CaCert; cert != "" {
		opts = append(opts, client.WithTLSCACert(cert))
	}
	if cert := g.TLSClientCert; cert != "" {
		opts = append(opts, client.WithTLSClientCert(cert, g.TLSClientKey))
	}

	return opts
}
