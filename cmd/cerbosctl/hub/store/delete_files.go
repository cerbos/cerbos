// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"slices"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

type DeleteFilesCmd struct {
	Output        `embed:""`
	Paths         []string `arg:"" help:"List of paths to delete from the store" required:""`
	Message       string   `help:"Commit message for this change" default:"Uploaded using cerbosctl"`
	VersionMustEq int64    `help:"Require that the store is at this version before commiting the change" optional:""`
}

func (dfc *DeleteFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return dfc.toCommandError(k.Stderr, err)
	}

	version := dfc.VersionMustEq
	for batch := range slices.Chunk(dfc.Paths, modifyFilesBatchSize) {
		req := hub.NewModifyFilesRequest(cmd.StoreID, dfc.Message)
		for _, path := range batch {
			req.DeleteFile(path)
		}
		if version > 0 {
			req.OnlyIfVersionEquals(version)
		}

		resp, err := client.ModifyFilesLenient(context.Background(), req)
		if err != nil {
			return dfc.toCommandError(k.Stderr, err)
		}

		if resp != nil {
			version = resp.GetNewStoreVersion()
		}
	}

	if version > 0 {
		dfc.printNewVersion(k.Stdout, version)
		return nil
	}

	return newStoreNotModifiedError()
}
