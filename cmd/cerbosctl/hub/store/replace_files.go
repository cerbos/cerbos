// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

const replaceFilesHelp = `
Replaces or deletes all files in the remote store so that it only contains the files provided.

The following exit codes have a special meaning.
	- 6: The version condition supplied using --version-must-eq wasn't satisfied

# Upload a local directory

cerbosctl hub store replace-files /path/to/dir

# Upload a local zip archive

cerbosctl hub store replace-files /path/to/archive.zip
`

type ReplaceFilesCmd struct {
	Output        `embed:""`
	Message       string `help:"Commit message for this change" default:"Uploaded using cerbosctl"`
	Path          string `arg:"" type:"path" help:"Path to a directory or a zip file containing the contents to upload" required:""`
	VersionMustEq int64  `help:"Require that the store is at this version before committing the change" optional:""`
}

func (*ReplaceFilesCmd) Help() string {
	return replaceFilesHelp
}

func (rfc *ReplaceFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	var zipContents []byte
	var err error

	//nolint:nestif
	if rfc.Path == "-" {
		zipContents, err = io.ReadAll(os.Stdin)
		if err != nil {
			return rfc.toCommandError(k.Stderr, fmt.Errorf("failed to read stdin: %w", err))
		}

		if _, err = zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents))); err != nil {
			return rfc.toCommandError(k.Stderr, errors.New("piped content is not valid zip data"))
		}
	} else {
		stat, err := os.Stat(rfc.Path)
		if err != nil {
			return rfc.toCommandError(k.Stderr, err)
		}

		if stat.IsDir() {
			zipContents, err = hub.Zip(os.DirFS(rfc.Path))
			if err != nil {
				return rfc.toCommandError(k.Stderr, fmt.Errorf("failed to zip %s: %w", rfc.Path, err))
			}
		} else {
			if _, err = zip.OpenReader(rfc.Path); err != nil {
				return rfc.toCommandError(k.Stderr, fmt.Errorf("invalid zip file %s: %w", rfc.Path, err))
			}

			zipContents, err = os.ReadFile(rfc.Path)
			if err != nil {
				return rfc.toCommandError(k.Stderr, fmt.Errorf("failed to read zip file %s: %w", rfc.Path, err))
			}
		}
	}

	if len(zipContents) > replaceFilesZipMaxSize {
		return rfc.toCommandError(k.Stderr, errors.New("zipped data size is too large"))
	}

	client, err := cmd.storeClient()
	if err != nil {
		return rfc.toCommandError(k.Stderr, err)
	}

	req := hub.NewReplaceFilesRequest(cmd.StoreID, rfc.Message).WithZippedContents(zipContents)
	if rfc.VersionMustEq > 0 {
		req.OnlyIfVersionEquals(rfc.VersionMustEq)
	}

	resp, err := client.ReplaceFilesLenient(context.Background(), req)
	if err != nil {
		return rfc.toCommandError(k.Stderr, err)
	}

	rfc.printNewVersion(k.Stdout, resp.GetNewStoreVersion())
	return nil
}
