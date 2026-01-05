// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "github.com/cerbos/cerbos-sdk-go/cerbos"

const maxRecvMsgSizeBytes = 25 * 1024 * 1024 // 25MiB

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

func (g *Globals) ToClientOpts() []cerbos.Opt {
	opts := []cerbos.Opt{cerbos.WithMaxRecvMsgSizeBytes(maxRecvMsgSizeBytes)}
	if g.Plaintext {
		opts = append(opts, cerbos.WithPlaintext())
	}
	if g.Insecure {
		opts = append(opts, cerbos.WithTLSInsecure())
	}
	if cert := g.CaCert; cert != "" {
		opts = append(opts, cerbos.WithTLSCACert(cert))
	}
	if cert := g.TLSClientCert; cert != "" {
		opts = append(opts, cerbos.WithTLSClientCert(cert, g.TLSClientKey))
	}

	return opts
}
