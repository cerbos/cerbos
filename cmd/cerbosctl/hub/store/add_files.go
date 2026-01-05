// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	"github.com/cerbos/cerbos/internal/util"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
)

const addFilesHelp = `
The following exit codes have a special meaning.
	- 6: The version condition supplied using --version-must-eq wasn't satisfied

# Upload foo.yaml and all files in the bar directory

cerbosctl hub store add-files foo.yaml bar

# Upload bar.yaml, renaming it to foo/bar.yaml in the store

cerbosctl hub store add-files --message="Adding foo/bar.yaml" foo/bar.yaml=bar.yaml
`

type AddFilesCmd struct { //betteralign:ignore
	filesToAdd    map[string]string
	Output        `embed:""`
	Message       string   `help:"Commit message for this change" default:"Uploaded using cerbosctl"`
	Paths         []string `arg:"" help:"List of files or directories to add to the store. To rename how the file appears in the store, use store_path=actual_path as the input format." required:""`
	VersionMustEq int64    `help:"Require that the store is at this version before committing the change" optional:""`
}

func (*AddFilesCmd) Help() string {
	return addFilesHelp
}

func (afc *AddFilesCmd) Validate() error {
	afc.filesToAdd = make(map[string]string)
	for _, path := range afc.Paths {
		storePath, filePath, ok := strings.Cut(path, "=")
		if !ok {
			filePath = path
			storePath = filepath.Base(path)
		}
		storePath = filepath.ToSlash(storePath)

		var err error
		filePath, err = filepath.Abs(filePath)
		if err != nil {
			return fmt.Errorf("failed to find absolute path of %s: %w", filePath, err)
		}
		storePath = filepath.Clean(storePath)
		if storePath == "" || util.PathIsHidden(storePath) || !util.IsSupportedFileType(storePath) {
			return fmt.Errorf("invalid store path %q: must not be hidden and must be a YAML or JSON file", storePath)
		}

		stat, err := os.Stat(filePath)
		if err != nil {
			return err
		}

		//nolint:nestif
		if stat.IsDir() {
			root, err := os.OpenRoot(filePath)
			if err != nil {
				return fmt.Errorf("failed to open %s: %w", filePath, err)
			}
			defer root.Close()

			if err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					if util.IsHidden(d.Name()) {
						return fs.SkipDir
					}
					return nil
				}

				if util.IsHidden(d.Name()) {
					return nil
				}

				if !util.IsSupportedFileType(d.Name()) {
					return nil
				}

				finfo, err := d.Info()
				if err != nil {
					return fmt.Errorf("failed to get file information on %s: %w", path, err)
				}

				if finfo.Size() > maxFileSize {
					return fmt.Errorf("file too large: %s", path)
				}

				relativePath, err := filepath.Rel(filePath, path)
				if err != nil {
					return fmt.Errorf("failed to determine relative path of %s: %w", path, err)
				}

				afc.filesToAdd[path] = filepath.Join(storePath, relativePath)
				return nil
			}); err != nil {
				return fmt.Errorf("failed to list files under %s: %w", filePath, err)
			}
		} else if util.IsSupportedFileType(filePath) {
			if stat.Size() > maxFileSize {
				return fmt.Errorf("file too large: %s", filePath)
			}
			afc.filesToAdd[filePath] = storePath
		}
	}

	return nil
}

func (afc *AddFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return afc.toCommandError(k.Stderr, err)
	}

	version := afc.VersionMustEq
	for batch, err := range afc.batch() {
		if err != nil {
			return afc.toCommandError(k.Stderr, err)
		}

		req := hub.NewModifyFilesRequest(cmd.StoreID, afc.Message).AddOps(batch...)
		if version > 0 {
			req.OnlyIfVersionEquals(version)
		}
		resp, err := client.ModifyFilesLenient(context.Background(), req)
		if err != nil {
			return afc.toCommandError(k.Stderr, err)
		}

		if resp != nil {
			version = resp.GetNewStoreVersion()
		}
	}

	afc.printNewVersion(k.Stdout, version)
	return nil
}

func (afc *AddFilesCmd) batch() iter.Seq2[[]*storev1.FileOp, error] {
	return func(yield func([]*storev1.FileOp, error) bool) {
		batch := make([]*storev1.FileOp, 0, modifyFilesBatchSize)
		batchCounter := 0

		for actualPath, storePath := range afc.filesToAdd {
			contents, err := os.ReadFile(actualPath)
			if err != nil {
				yield(nil, fmt.Errorf("failed to read %s: %w", actualPath, err))
				return
			}

			if len(contents) > maxFileSize {
				yield(nil, fmt.Errorf("file too large: %s", actualPath))
				return
			}

			batch = append(batch, &storev1.FileOp{
				Op: &storev1.FileOp_AddOrUpdate{
					AddOrUpdate: &storev1.File{
						Path:     storePath,
						Contents: contents,
					},
				},
			})
			batchCounter++
			if batchCounter == modifyFilesBatchSize {
				if !yield(batch, nil) {
					return
				}

				batch = make([]*storev1.FileOp, 0, modifyFilesBatchSize)
				batchCounter = 0
			}
		}

		if batchCounter > 0 {
			yield(batch, nil)
		}
	}
}
