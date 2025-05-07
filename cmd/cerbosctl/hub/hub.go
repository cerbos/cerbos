// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/hub/epdp"
	"github.com/cerbos/cerbos/cmd/cerbosctl/hub/store"
)

const hubCmdHelp = `Interact with Cerbos Hub (https://www.cerbos.dev/product-cerbos-hub).`

var hideGlobals = map[string]struct{}{
	"server":      {},
	"username":    {},
	"password":    {},
	"ca-cert":     {},
	"client-cert": {},
	"client-key":  {},
	"insecure":    {},
	"plaintext":   {},
}

type Cmd struct {
	EmbeddedPDP epdp.Cmd  `cmd:"" name:"embedded_pdp" aliases:"epdp"`
	Store       store.Cmd `cmd:"" name:"store"`
}

func (c *Cmd) BeforeReset(ctx *kong.Context) error {
	flags := ctx.Flags()
	for _, f := range flags {
		if _, exists := hideGlobals[f.Name]; exists {
			f.Hidden = true
		}
	}

	return nil
}

func (*Cmd) Help() string {
	return hubCmdHelp
}
