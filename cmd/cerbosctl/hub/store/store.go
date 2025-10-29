// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/cerbos/cloud-api/store"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	dirMode                = 0o700
	downloadBatchSize      = 10
	fileMode               = 0o600
	maxFileSize            = 5 * 1024 * 1024
	modifyFilesBatchSize   = 25
	replaceFilesZipMaxSize = 15728640
)

const storeCmdHelp = `Interact with Cerbos Hub managed stores.

Requires an existing managed store and the API credentials to access it.
The store ID and credentials can be provided using either command-line flags or environment variables.
`

type Conn struct {
	APIEndpoint   string `name:"api-endpoint" default:"https://api.cerbos.cloud" env:"CERBOS_HUB_API_ENDPOINT"`
	TLSCACert     string `name:"tls-ca-cert" hidden:"" help:"Path to the CA certificate for verifying server identity" type:"existingfile" env:"CERBOS_HUB_TLS_CA_CERT"`
	TLSClientCert string `name:"tls-client-cert" hidden:"" help:"Path to the TLS client certificate" type:"existingfile" env:"CERBOS_HUB_TLS_CLIENT_CERT" and:"tls-client-key"`
	TLSClientKey  string `name:"tls-client-key" hidden:"" help:"Path to the TLS client key" type:"existingfile" env:"CERBOS_HUB_TLS_CLIENT_KEY" and:"tls-client-cert"`
	StoreID       string `name:"store-id" help:"ID of the store to operate on" env:"CERBOS_HUB_STORE_ID" required:""`
	ClientID      string `name:"client-id" help:"Client ID of the access credential" env:"CERBOS_HUB_CLIENT_ID" required:""`
	ClientSecret  string `name:"client-secret" help:"Client secret of the access credential" env:"CERBOS_HUB_CLIENT_SECRET" required:""`
	TLSInsecure   bool   `name:"tls-insecure" hidden:"" help:"Skip validating server certificate" env:"CERBOS_HUB_TLS_INSECURE"`
}

func (c Conn) storeClient() (*hub.StoreClient, error) {
	hubOpts := []cerbos.HubOpt{
		cerbos.WithHubAPIEndpoint(c.APIEndpoint),
		cerbos.WithHubCredentials(c.ClientID, c.ClientSecret),
	}

	var advancedOpts []cerbos.Opt
	if c.TLSCACert != "" {
		advancedOpts = append(advancedOpts, cerbos.WithTLSCACert(c.TLSCACert))
	}
	if c.TLSClientCert != "" && c.TLSClientKey != "" {
		advancedOpts = append(advancedOpts, cerbos.WithTLSClientCert(c.TLSClientCert, c.TLSClientKey))
	}
	if c.TLSInsecure {
		advancedOpts = append(advancedOpts, cerbos.WithTLSInsecure())
	}

	if len(advancedOpts) > 0 {
		hubOpts = append(hubOpts, cerbos.WithAdvancedOptions(advancedOpts...))
	}
	hc, err := cerbos.NewHubClient(hubOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Hub client: %w", err)
	}

	return hc.StoreClient(), nil
}

type Cmd struct {
	UploadGit    UploadGitCmd `cmd:"" name:"upload-git" help:"Upload files from a local git repository to the store"`
	Conn         `embed:""`
	ListFiles    ListFilesCmd    `cmd:"" name:"list-files" help:"List store files"`
	Download     DownloadCmd     `cmd:"" name:"download" help:"Download the entire store"`
	GetFiles     GetFilesCmd     `cmd:"" name:"get-files" help:"Download files from the store"`
	ReplaceFiles ReplaceFilesCmd `cmd:"" name:"replace-files" help:"Overwrite the store with the given set of files"`
	AddFiles     AddFilesCmd     `cmd:"" name:"add-files" help:"Add files to the store"`
	DeleteFiles  DeleteFilesCmd  `cmd:"" name:"delete-files" help:"Delete files from the store"`
}

func (*Cmd) Help() string {
	return storeCmdHelp
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

type ChangeDetails struct {
	Message  string          `help:"Commit message for this change"`
	Origin   json.RawMessage `help:"Metadata of the origin for this change as JSON string" placeholder:"{\"internal\":{\"source\":\"CI workflow\",\"metadata\":{\"id\":\"1\"}}}"`
	Uploader json.RawMessage `help:"Metadata of the uploader for this change as JSON string" placeholder:"{\"name\":\"cerbos-sdk-go\",\"metadata\":{\"version\":\"v0.1\"}}"`
}

func (cd ChangeDetails) ChangeDetails(gitChangeDetails *changeDetails) (*hub.ChangeDetails, string, error) {
	var message string
	switch {
	case cd.Message != "":
		message = cd.Message
	case gitChangeDetails != nil:
		message = gitChangeDetails.message
	default:
		message = defaultMessage
	}

	hubChangeDetails := hub.NewChangeDetails(message)

	switch {
	case cd.Origin != nil:
		tmp := &storev1.ChangeDetails{}
		if err := protojson.Unmarshal(cd.Origin, tmp); err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal origin: %w", err)
		}

		switch tmp.GetOrigin().(type) {
		case *storev1.ChangeDetails_Git_:
			hubChangeDetails.WithOriginGitDetails(tmp.GetGit())
		case *storev1.ChangeDetails_Internal_:
			hubChangeDetails.WithOriginInternalDetails(tmp.GetInternal())
		}
	case gitChangeDetails != nil:
		hubChangeDetails.WithOriginGitDetails(gitChangeDetails.origin)
	default:
		hubChangeDetails.WithOriginInternal(defaultSource)
	}

	switch {
	case cd.Uploader != nil:
		uploader := &storev1.ChangeDetails_Uploader{}
		if err := protojson.Unmarshal(cd.Uploader, uploader); err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal uploader: %w", err)
		}
		hubChangeDetails.WithUploaderDetails(uploader)
	case gitChangeDetails != nil:
		hubChangeDetails.WithUploaderDetails(gitChangeDetails.uploader)
	default:
		hubChangeDetails.WithUploaderDetails(&storev1.ChangeDetails_Uploader{
			Name: defaultName,
		})
	}

	return hubChangeDetails, message, nil
}

func changeDetailsFromHash(r *git.Repository, hash plumbing.Hash) (*changeDetails, error) {
	commit, err := r.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	return &changeDetails{
		message: commit.Message,
		uploader: &storev1.ChangeDetails_Uploader{
			Name: commit.Committer.String(),
		},
		origin: &storev1.ChangeDetails_Git{
			Hash:       commit.Hash.String(),
			Message:    commit.Message,
			Committer:  commit.Committer.String(),
			CommitDate: timestamppb.New(commit.Committer.When),
			Author:     commit.Author.String(),
			AuthorDate: timestamppb.New(commit.Author.When),
		},
	}, nil
}

type changeDetails struct {
	uploader *storev1.ChangeDetails_Uploader
	origin   *storev1.ChangeDetails_Git
	message  string
}

type commandError struct {
	ErrorMessage string `json:"errorMessage,omitempty"`
	ErrorDetails []any  `json:"errorDetails,omitempty"`
	exitCode     int
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
