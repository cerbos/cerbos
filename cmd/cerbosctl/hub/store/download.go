// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"slices"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

const downloadBatchSize = 10

type DownloadCmd struct {
	OutputPath string `name:"output-path" short:"O" type:"path" required:"" help:"Path to write the retrieved files"`
}

func (dc *DownloadCmd) Run(k *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return err
	}

	listResp, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(cmd.StoreID))
	if err != nil {
		return fmt.Errorf("failled to list files in store: %w", err)
	}

	files := listResp.GetFiles()
	fmt.Fprintf(k.Stdout, "Downloading %d files.", len(files))

	for batch := range slices.Chunk(files, downloadBatchSize) {
		resp, err := client.GetFiles(context.Background(), hub.NewGetFilesRequest(cmd.StoreID, batch))
		if err != nil {
			fmt.Fprintln(k.Stdout, "x")
			return fmt.Errorf("failed to download batch: %w", err)
		}

		if err := writeFiles(dc.OutputPath, resp.GetFiles()); err != nil {
			fmt.Fprintln(k.Stdout, "x")
			return fmt.Errorf("failed to write batch: %w", err)
		}

		fmt.Fprint(k.Stdout, ".")
	}

	return nil
}
