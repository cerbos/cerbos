// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"slices"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

const deleteFilesHelp = `
The following exit codes have a special meaning.
	- 5: Command didn't change the remote store because it's already at the desired state
	- 6: The version condition supplied using --version-must-eq wasn't satisfied

# Delete foo/bar.yaml from the remote store

cerbosctl hub store delete-files --message="Deleting foo/bar.yaml" foo/bar.yaml
`

type DeleteFilesCmd struct {
	Output        `embed:""`
	Message       string   `help:"Commit message for this change" default:"Uploaded using cerbosctl"`
	Paths         []string `arg:"" help:"List of paths to delete from the store" required:""`
	VersionMustEq int64    `help:"Require that the store is at this version before committing the change" optional:""`
}

func (*DeleteFilesCmd) Help() string {
	return deleteFilesHelp
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
