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
	"github.com/cerbos/cloud-api/store"
)

type ReplaceFilesCmd struct {
	Message       string `help:"Commit message for this change" default:"Uploaded by cerbosctl"`
	VersionMustEq int64  `help:"Require that the store is at this version before commiting the change" optional:""`
	Path          string `arg:"" type:"path" help:"Path to a directory or a zip file containing the contents to upload" required:""`
}

func (rfc *ReplaceFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	var zipContents []byte
	var err error

	//nolint:nestif
	if rfc.Path == "-" {
		zipContents, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}

		if _, err = zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents))); err != nil {
			return errors.New("piped content is not valid zip data")
		}
	} else {
		stat, err := os.Stat(rfc.Path)
		if err != nil {
			return err
		}

		if stat.IsDir() {
			zipContents, err = hub.Zip(os.DirFS(rfc.Path))
			if err != nil {
				return fmt.Errorf("failed to zip %s: %w", rfc.Path, err)
			}
		} else {
			if _, err = zip.OpenReader(rfc.Path); err != nil {
				return fmt.Errorf("invalid zip file %s: %w", rfc.Path, err)
			}

			zipContents, err = os.ReadFile(rfc.Path)
			if err != nil {
				return fmt.Errorf("failed to read zip file %s: %w", rfc.Path, err)
			}
		}
	}

	client, err := cmd.storeClient()
	if err != nil {
		return err
	}

	req := hub.NewReplaceFilesRequest(cmd.StoreID, rfc.Message, zipContents)
	if rfc.VersionMustEq > 0 {
		req.OnlyIfVersionEquals(rfc.VersionMustEq)
	}

	resp, err := client.ReplaceFilesLenient(context.Background(), req)
	if err != nil {
		rpcErr := new(hub.StoreRPCError)
		if errors.As(err, rpcErr) {
			switch rpcErr.Kind {
			case store.RPCErrorConditionUnsatisfied:
				fmt.Fprintln(k.Stderr, "Store not modified due to unsatisfied version condition")
			case store.RPCErrorNoUsableFiles:
				fmt.Fprintln(k.Stderr, "No usable files in the request")
				for _, f := range rpcErr.IgnoredFiles {
					fmt.Fprintf(k.Stderr, "%s: Unsupported\n", f)
				}
			case store.RPCErrorValidationFailure:
				for _, f := range rpcErr.ValidationErrors {
					fmt.Fprintf(k.Stderr, "%s: [%s] %s\n", f.GetFile(), f.GetCause(), f.GetDetails())
				}
			}
		}
		return err
	}

	if resp == nil {
		fmt.Fprintln(k.Stdout, "Store is already at the desired state")
	} else {
		fmt.Fprintf(k.Stdout, "New version: %d\n", resp.GetNewStoreVersion())
	}

	return nil
}
