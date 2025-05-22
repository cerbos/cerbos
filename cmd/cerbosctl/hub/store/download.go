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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	"github.com/cerbos/cerbos/internal/util"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
)

const downloadHelp = `

# Download the store to a directory

cerbosctl hub store download /path/to/dir

# Download the store as a zip file

cerbosctl hub store download /path/to/archive.zip

`

type DownloadCmd struct {
	Output     `embed:""`
	OutputPath string `arg:"" type:"path" required:"" help:"Path to write the retrieved files. Must be a path to a directory, zip file or - for stdout."`
}

func (*DownloadCmd) Help() string {
	return downloadHelp
}

func (dc *DownloadCmd) Run(k *kong.Kong, cmd *Cmd) (outErr error) {
	client, err := cmd.storeClient()
	if err != nil {
		return dc.toCommandError(k.Stderr, err)
	}

	listResp, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(cmd.StoreID))
	if err != nil {
		return dc.toCommandError(k.Stderr, fmt.Errorf("failled to list files in store: %w", err))
	}

	fw, err := newFileWriter(dc.OutputPath)
	if err != nil {
		return dc.toCommandError(k.Stderr, err)
	}
	defer func() {
		outErr = errors.Join(outErr, dc.toCommandError(k.Stderr, fw.Close()))
	}()

	files := listResp.GetFiles()
	for batch := range slices.Chunk(files, downloadBatchSize) {
		resp, err := client.GetFiles(context.Background(), hub.NewGetFilesRequest(cmd.StoreID, batch))
		if err != nil {
			return dc.toCommandError(k.Stderr, fmt.Errorf("failed to download batch: %w", err))
		}

		downloaded := resp.GetFiles()
		if len(downloaded) == 0 {
			return newNoFilesDownloadedError()
		}

		if err := fw.writeFiles(downloaded); err != nil {
			return dc.toCommandError(k.Stderr, fmt.Errorf("failed to write batch: %w", err))
		}
	}

	return nil
}

type fileWriter struct {
	outputRoot *os.Root
	zipWriter  *zip.Writer
	close      func() error
}

func newFileWriter(outputPath string) (*fileWriter, error) {
	if outputPath == "-" {
		zipWriter := zip.NewWriter(os.Stdout)
		return &fileWriter{zipWriter: zipWriter, close: zipWriter.Close}, nil
	}

	if util.IsZip(outputPath) {
		parent := filepath.Dir(outputPath)
		if parent != "." {
			if err := os.MkdirAll(parent, dirMode); err != nil {
				return nil, fmt.Errorf("failed to create directory tree %s: %w", parent, err)
			}
		}

		zipFile, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", outputPath, err)
		}

		zipWriter := zip.NewWriter(zipFile)
		return &fileWriter{
			zipWriter: zipWriter,
			close: func() (outErr error) {
				outErr = errors.Join(outErr, zipWriter.Close(), zipFile.Close())
				return outErr
			},
		}, nil
	}

	if err := os.MkdirAll(outputPath, dirMode); err != nil {
		return nil, fmt.Errorf("failed to create directory tree %s: %w", outputPath, err)
	}

	outputRoot, err := os.OpenRoot(outputPath)
	if err != nil {
		return nil, err
	}

	return &fileWriter{outputRoot: outputRoot, close: outputRoot.Close}, nil
}

func (fw *fileWriter) writeFiles(files []*storev1.File) error {
	for _, file := range files {
		//nolint:nestif
		if fw.zipWriter != nil {
			dest, err := fw.zipWriter.Create(file.GetPath())
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", file.GetPath(), err)
			}

			if _, err := io.Copy(dest, bytes.NewReader(file.GetContents())); err != nil {
				return fmt.Errorf("failed to write %s: %w", file.GetPath(), err)
			}
		} else {
			dir := filepath.Dir(file.GetPath())
			if dir != "." {
				if err := mkdirAll(fw.outputRoot, dir); err != nil {
					return fmt.Errorf("failed to create directory tree %s: %w", dir, err)
				}
			}

			dest, err := fw.outputRoot.Create(file.GetPath())
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", file.GetPath(), err)
			}

			if _, err := io.Copy(dest, bytes.NewReader(file.GetContents())); err != nil {
				return fmt.Errorf("failed to write %s: %w", file.GetPath(), err)
			}

			if err := dest.Close(); err != nil {
				return fmt.Errorf("failed to close %s: %w", file.GetPath(), err)
			}
		}
	}

	return nil
}

func (fw *fileWriter) Close() error {
	if fw.close != nil {
		return fw.close()
	}

	return nil
}

func mkdirAll(root *os.Root, path string) error {
	var dirs []string
	tmp := path
	for {
		parent, child := filepath.Split(tmp)
		dirs = append(dirs, child)
		parent = strings.TrimSuffix(parent, util.PathSeparator)
		if parent == "" {
			break
		}

		tmp = parent
	}

	slices.Reverse(dirs)
	for i := range dirs {
		if err := root.Mkdir(filepath.Join(dirs[:i+1]...), dirMode); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return err
		}
	}

	return nil
}
