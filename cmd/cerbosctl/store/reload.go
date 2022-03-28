// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const reloadCmdHelp = `# Reload the store
cerbosctl store reload

# Reload the store and wait until it finishes
cerbosctl store reload --wait`

type ReloadCmd struct {
	Wait bool `help:""`
}

func (rc *ReloadCmd) Run(k *kong.Kong, ctx *cmdclient.Context) error {
	_, _ = fmt.Fprint(k.Stdout, "Initiated a store reload\n")
	if rc.Wait {
		_, _ = fmt.Fprint(k.Stdout, "Waiting until the reloading process completes\n")
	}

	err := ctx.AdminClient.ReloadStore(context.Background(), rc.Wait)
	if err != nil {
		return err
	}

	if rc.Wait {
		_, _ = fmt.Fprint(k.Stdout, "Successfully reloaded the store\n")
	} else {
		_, _ = fmt.Fprint(k.Stdout, "Successfully transmitted the reload store call to the Admin API\n")
	}

	return nil
}

func (rc *ReloadCmd) Help() string {
	return reloadCmdHelp
}
