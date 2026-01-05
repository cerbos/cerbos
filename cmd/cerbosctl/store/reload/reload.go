// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package reload

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const help = `# Reload the store
cerbosctl store reload

# Reload the store and wait until it finishes
cerbosctl store reload --wait`

type Cmd struct { //betteralign:ignore
	Wait bool `help:"Wait until the reloading process finishes"`
}

func (c *Cmd) Run(k *kong.Kong, ctx *cmdclient.Context) error {
	_, _ = fmt.Fprint(k.Stdout, "Initiated a store reload\n")
	err := ctx.AdminClient.ReloadStore(context.Background(), c.Wait)
	if err != nil {
		return err
	}

	if c.Wait {
		_, _ = fmt.Fprint(k.Stdout, "Successfully reloaded the store\n")
	} else {
		_, _ = fmt.Fprint(k.Stdout, "Reload request submitted\n")
	}

	return nil
}

func (c *Cmd) Help() string {
	return help
}
