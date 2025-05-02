// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	securejoin "github.com/cyphar/filepath-securejoin"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

type Output struct {
	Format string `name:"output" short:"o" default:"text" help:"Output format." enum:"text,json,prettyjson"`
}

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
}

func formatOutput[T proto.Message](format string, value T, plain func(T) string) string {
	switch format {
	case "json":
		bytes, err := protojson.Marshal(value)
		if err != nil {
			return "Error converting output to JSON"
		}
		return unsafe.String(unsafe.SliceData(bytes), len(bytes))
	case "prettyjson":
		return protojson.Format(value)
	default:
		return plain(value)
	}
}

func writeFiles(dir string, files []*storev1.File) error {
	for _, f := range files {
		fullPath, err := securejoin.SecureJoin(dir, f.GetPath())
		if err != nil {
			return err
		}

		fileDir := filepath.Dir(fullPath)
		if fileDir != "." {
			if err := os.MkdirAll(fileDir, dirMode); err != nil {
				return fmt.Errorf("failed to create %s: %w", fileDir, err)
			}
		}

		if err := os.WriteFile(fullPath, f.GetContents(), fileMode); err != nil {
			return fmt.Errorf("failed to write %s: %w", fullPath, err)
		}
	}

	return nil
}
