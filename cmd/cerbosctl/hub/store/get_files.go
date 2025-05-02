// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

type GetFilesCmd struct {
	Files      []string `arg:"" required:"" help:"List of files to retrieve"`
	OutputPath string   `name:"output-path" short:"O" type:"path" required:"" help:"Path to write the retrieved files"`
}

func (gfc *GetFilesCmd) Run(_ *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return err
	}

	req := hub.NewGetFilesRequest(cmd.StoreID, gfc.Files)
	resp, err := client.GetFiles(context.Background(), req)
	if err != nil {
		return err
	}

	return writeFiles(gfc.OutputPath, resp.GetFiles())
}
