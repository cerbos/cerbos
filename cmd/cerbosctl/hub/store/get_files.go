// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

type GetFilesCmd struct {
	Output     `embed:""`
	Files      []string `arg:"" required:"" help:"List of files to retrieve"`
	OutputPath string   `name:"output-path" short:"O" type:"path" required:"" help:"Path to write the retrieved files. Must be a path to a directory, zip file or - for stdout."`
}

func (gfc *GetFilesCmd) Run(k *kong.Kong, cmd *Cmd) (outErr error) {
	client, err := cmd.storeClient()
	if err != nil {
		return gfc.toCommandError(k.Stderr, err)
	}

	fw, err := newFileWriter(gfc.OutputPath)
	if err != nil {
		return gfc.toCommandError(k.Stderr, err)
	}
	defer func() {
		outErr = errors.Join(outErr, gfc.toCommandError(k.Stderr, fw.Close()))
	}()

	req := hub.NewGetFilesRequest(cmd.StoreID, gfc.Files)
	resp, err := client.GetFiles(context.Background(), req)
	if err != nil {
		return gfc.toCommandError(k.Stderr, err)
	}

	downloaded := resp.GetFiles()
	if len(downloaded) == 0 {
		return newNoFilesDownloadedError()
	}

	if err := fw.writeFiles(downloaded); err != nil {
		return gfc.toCommandError(k.Stderr, err)
	}

	return nil
}
