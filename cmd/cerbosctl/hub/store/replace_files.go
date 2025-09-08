// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/go-git/go-git/v5"
	"google.golang.org/protobuf/encoding/protojson"
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

type ReplaceFilesCmd struct {
	Output        `embed:""`
	Message       string          `help:"Commit message for this change"`
	Path          string          `arg:"" type:"path" help:"Path to a directory or a zip file containing the contents to upload" required:""`
	Origin        json.RawMessage `help:"Metadata of the origin for this change as JSON string" placeholder:"{\"internal\":{\"source\":\"CI workflow\",\"metadata\":{\"id\":\"1\"}}}"`
	Uploader      json.RawMessage `help:"Metadata of the uploader for this change as JSON string" placeholder:"{\"name\":\"cerbos-sdk-go\",\"metadata\":{\"version\":\"v0.1\"}}"`
	VersionMustEq int64           `help:"Require that the store is at this version before committing the change" optional:""`
}

func (*ReplaceFilesCmd) Help() string {
	return replaceFilesHelp
}

func (rfc *ReplaceFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	var zipContents []byte
	var err error
	var gitChangeDetails *changeDetails

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

			gitChangeDetails, _ = rfc.changeDetailsFromGit()
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

	var message string
	switch {
	case rfc.Message != "":
		message = rfc.Message
	case gitChangeDetails != nil:
		message = gitChangeDetails.message
	default:
		message = defaultMessage
	}

	changeDetails := hub.NewChangeDetails(message)

	switch {
	case rfc.Origin != nil:
		cd := &storev1.ChangeDetails{}
		if err := protojson.Unmarshal(rfc.Origin, cd); err != nil {
			return rfc.toCommandError(k.Stderr, fmt.Errorf("failed to unmarshal origin: %w", err))
		}
		switch cd.GetOrigin().(type) {
		case *storev1.ChangeDetails_Git_:
			changeDetails.WithOriginGitDetails(cd.GetGit())
		case *storev1.ChangeDetails_Internal_:
			changeDetails.WithOriginInternalDetails(cd.GetInternal())
		}
	case gitChangeDetails != nil:
		changeDetails.WithOriginGitDetails(gitChangeDetails.origin)
	default:
		changeDetails.WithOriginInternal(defaultSource)
	}

	switch {
	case rfc.Uploader != nil:
		uploader := &storev1.ChangeDetails_Uploader{}
		if err := protojson.Unmarshal(rfc.Uploader, uploader); err != nil {
			return rfc.toCommandError(k.Stderr, fmt.Errorf("failed to unmarshal uploader: %w", err))
		}
		changeDetails.WithUploaderDetails(uploader)
	case gitChangeDetails != nil:
		changeDetails.WithUploaderDetails(gitChangeDetails.uploader)
	default:
		changeDetails.WithUploaderDetails(&storev1.ChangeDetails_Uploader{
			Name: defaultName,
		})
	}

	req := hub.
		NewReplaceFilesRequest(cmd.StoreID, message).
		WithChangeDetails(changeDetails).
		WithZippedContents(zipContents)
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

func (rfc *ReplaceFilesCmd) changeDetailsFromGit() (*changeDetails, error) {
	r, err := git.PlainOpenWithOptions(rfc.Path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open git repository: %w", err)
	}

	ref, err := r.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	return changeDetailsFromHash(r, ref.Hash())
}
