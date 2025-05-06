// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"buf.build/go/protovalidate"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	"github.com/cerbos/cloud-api/store"
)

const (
	dirMode                = 0o700
	downloadBatchSize      = 10
	fileMode               = 0o600
	maxFileSize            = 5 * 1024 * 1024
	modifyFilesBatchSize   = 25
	pathSeparator          = string(filepath.Separator)
	replaceFilesZipMaxSize = 15728640
)

type Conn struct {
	APIEndpoint  string `name:"api-endpoint" hidden:"" default:"https://api.cerbos.cloud" env:"CERBOS_HUB_API_ENDPOINT"`
	StoreID      string `name:"store-id" help:"ID of the store to operate on" env:"CERBOS_HUB_STORE_ID" required:""`
	ClientID     string `name:"client-id" help:"Client ID of the access credential" env:"CERBOS_HUB_CLIENT_ID" required:""`
	ClientSecret string `name:"client-secret" help:"Client secret of the access credential" env:"CERBOS_HUB_CLIENT_SECRET" required:""`
}

func (c Conn) storeClient() (*hub.StoreClient, error) {
	hc, err := cerbos.NewHubClient(cerbos.WithHubAPIEndpoint(c.APIEndpoint), cerbos.WithHubCredentials(c.ClientID, c.ClientSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to create Hub client: %w", err)
	}

	return hc.StoreClient(), nil
}

type Cmd struct {
	Conn         `embed:""`
	ListFiles    ListFilesCmd    `cmd:"" name:"list-files" help:"List store files"`
	GetFiles     GetFilesCmd     `cmd:"" name:"get-files" help:"Get file contents"`
	Download     DownloadCmd     `cmd:"" name:"download" help:"Download the entire store"`
	ReplaceFiles ReplaceFilesCmd `cmd:"" name:"replace-files" help:"Overwrite the store with the given set of files"`
	AddFiles     AddFilesCmd     `cmd:"" name:"add-files" help:"Add files to the store"`
	DeleteFiles  DeleteFilesCmd  `cmd:"" name:"delete-files" help:"Delete files from the store"`
}

type Output struct {
	Format string `name:"output" short:"o" default:"text" help:"Output format." enum:"text,json,prettyjson"`
}

func (o Output) toCommandError(w io.Writer, err error) error {
	if err == nil {
		return nil
	}

	cerr := commandError{
		exitCode: 2, //nolint:mnd
	}

	defer func() {
		o.format(w, cerr)
	}()

	valErr := new(hub.InvalidRequestError)
	if errors.As(err, valErr) {
		cerr.ErrorMessage = "invalid request"
		cerr.ErrorDetails = make([]any, len(valErr.Violations))
		for i, v := range valErr.Violations {
			cerr.ErrorDetails[i] = violation{Field: protovalidate.FieldPathString(v.Proto.Field), Message: v.Proto.GetMessage()}
		}
		return cerr
	}

	rpcErr := new(hub.StoreRPCError)
	if errors.As(err, rpcErr) {
		switch rpcErr.Kind {
		case store.RPCErrorAuthenticationFailed:
			cerr.ErrorMessage = "failed to authenticate to Cerbos Hub"
		case store.RPCErrorPermissionDenied:
			cerr.ErrorMessage = "permission denied for store"
		case store.RPCErrorStoreNotFound:
			cerr.ErrorMessage = "store doesn't exist"
		case store.RPCErrorConditionUnsatisfied:
			cerr.exitCode = 6 //nolint:mnd
			cerr.ErrorMessage = "store not modified due to unsatisfied version condition"
		case store.RPCErrorNoUsableFiles:
			cerr.ErrorMessage = "no usable files"
			cerr.ErrorDetails = make([]any, len(rpcErr.IgnoredFiles))
			for i, ignored := range rpcErr.IgnoredFiles {
				cerr.ErrorDetails[i] = ignored
			}
		case store.RPCErrorValidationFailure:
			cerr.ErrorMessage = "invalid files"
			cerr.ErrorDetails = make([]any, len(rpcErr.ValidationErrors))
			for i, f := range rpcErr.ValidationErrors {
				cerr.ErrorDetails[i] = validationErr{File: f.GetFile(), Cause: f.GetCause().String(), Details: f.GetDetails()}
			}
		default:
			cerr.ErrorMessage = rpcErr.Error()
		}

		return cerr
	}

	cerr.ErrorMessage = err.Error()
	return cerr
}

func newStoreNotModifiedError() error {
	//nolint:mnd
	return commandError{exitCode: 5, ErrorMessage: "store not modified"}
}

func newNoFilesDownloadedError() error {
	//nolint:mnd
	return commandError{exitCode: 1, ErrorMessage: "nothing to download"}
}

func (o Output) printNewVersion(w io.Writer, version int64) {
	switch o.Format {
	case "json":
		bytes, _ := json.Marshal(map[string]int64{"version": version})
		fmt.Fprintf(w, "%s\n", bytes)
	case "prettyjson":
		bytes, _ := json.MarshalIndent(map[string]int64{"version": version}, "", "  ")
		fmt.Fprintf(w, "%s\n", bytes)
	default:
		fmt.Fprintf(w, "New version: %d\n", version)
	}
}

func (o Output) format(w io.Writer, value any) {
	switch o.Format {
	case "json":
		bytes, _ := json.Marshal(value)
		fmt.Fprintf(w, "%s\n", bytes)
	case "prettyjson":
		bytes, _ := json.MarshalIndent(value, "", "  ")
		fmt.Fprintf(w, "%s\n", bytes)
	default:
		if cerr, ok := value.(commandError); ok {
			fmt.Fprintf(w, "%s\n", cerr.String())
		} else {
			fmt.Fprintf(w, "%s\n", value)
		}
	}
}

type commandError struct {
	exitCode     int
	ErrorMessage string `json:"errorMessage,omitempty"`
	ErrorDetails []any  `json:"errorDetails,omitempty"`
}

func (ce commandError) Error() string {
	return ce.ErrorMessage
}

func (ce commandError) String() string {
	sb := new(strings.Builder)
	sb.WriteString(ce.ErrorMessage)
	if len(ce.ErrorDetails) > 0 {
		for _, ed := range ce.ErrorDetails {
			fmt.Fprintf(sb, "\n- %s", ed)
		}
	}
	return sb.String()
}

func (ce commandError) ExitCode() int {
	return ce.exitCode
}

type violation struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
}

func (v violation) String() string {
	if v.Field != "" {
		return fmt.Sprintf("%s: %s", v.Field, v.Message)
	}
	return v.Message
}

type validationErr struct {
	File    string `json:"file,omitempty"`
	Cause   string `json:"cause,omitempty"`
	Details string `json:"details,omitempty"`
}

func (ve validationErr) String() string {
	if ve.Details != "" {
		return fmt.Sprintf("%s: %s - %s", ve.File, ve.Cause, ve.Details)
	}

	return fmt.Sprintf("%s: %s", ve.File, ve.Cause)
}
