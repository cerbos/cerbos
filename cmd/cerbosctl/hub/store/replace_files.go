// Copyright 2021-2026 Zenauth Ltd.
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
	"github.com/go-git/go-git/v5"
)

const (
	defaultMessage = "Uploaded using cerbosctl"
	defaultName    = "cerbosctl"
	defaultSource  = "cerbosctl"
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

type ReplaceFilesCmd struct { //betteralign:ignore
	Output        `embed:""`
	Path          string `arg:"" type:"path" help:"Path to a directory or a zip file containing the contents to upload" required:""`
	ChangeDetails `embed:""`
	VersionMustEq int64 `help:"Require that the store is at this version before committing the change" optional:""`
}

func (*ReplaceFilesCmd) Help() string {
	return replaceFilesHelp
}

func (rfc *ReplaceFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return rfc.toCommandError(k.Stderr, err)
	}

	newStoreVersion, err := replaceFiles(client, cmd.StoreID, rfc.Path, rfc.ChangeDetails, rfc.VersionMustEq)
	if err != nil {
		return rfc.toCommandError(k.Stderr, err)
	}

	rfc.printNewVersion(k.Stdout, newStoreVersion)
	return nil
}

func replaceFiles(storeClient *hub.StoreClient, storeID, path string, cd ChangeDetails, versionMustEq int64) (int64, error) {
	var zipContents []byte
	var err error
	var gitChangeDetails *changeDetails

	//nolint:nestif
	if path == "-" {
		zipContents, err = io.ReadAll(os.Stdin)
		if err != nil {
			return 0, fmt.Errorf("failed to read stdin: %w", err)
		}

		if _, err = zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents))); err != nil {
			return 0, errors.New("piped content is not valid zip data")
		}
	} else {
		stat, err := os.Stat(path)
		if err != nil {
			return 0, err
		}

		if stat.IsDir() {
			zipContents, err = hub.Zip(os.DirFS(path))
			if err != nil {
				return 0, fmt.Errorf("failed to zip %s: %w", path, err)
			}

			gitChangeDetails, _ = changeDetailsFromGit(path)
		} else {
			if _, err = zip.OpenReader(path); err != nil {
				return 0, fmt.Errorf("invalid zip file %s: %w", path, err)
			}

			zipContents, err = os.ReadFile(path)
			if err != nil {
				return 0, fmt.Errorf("failed to read zip file %s: %w", path, err)
			}
		}
	}

	if len(zipContents) > replaceFilesZipMaxSize {
		return 0, errors.New("zipped data size is too large")
	}

	changeDetails, message, err := cd.ChangeDetails(gitChangeDetails)
	if err != nil {
		return 0, fmt.Errorf("failed to get change details: %w", err)
	}

	req := hub.
		NewReplaceFilesRequest(storeID, message).
		WithChangeDetails(changeDetails).
		WithZippedContents(zipContents)
	if versionMustEq > 0 {
		req.OnlyIfVersionEquals(versionMustEq)
	}

	resp, err := storeClient.ReplaceFilesLenient(context.Background(), req)
	if err != nil {
		return 0, err
	}

	return resp.GetNewStoreVersion(), nil
}

func changeDetailsFromGit(path string) (*changeDetails, error) {
	r, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open git repository at %q: %w", path, err)
	}

	ref, err := r.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	return changeDetailsFromHash(r, ref.Hash())
}
