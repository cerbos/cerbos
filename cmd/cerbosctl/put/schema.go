// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/util"

	"github.com/alecthomas/kong"
)

const schemaCmdHelp = `# Put schemas
cerbosctl put schemas ./path/to/schema.json
cerbosctl put schema ./path/to/schema.json
cerbosctl put s ./path/to/schema.json

# Put multiple schemas
cerbosctl put schema ./path/to/schema.json ./path/to/other/schema.json

# Put schemas under a directory
cerbosctl put schema ./dir/to/schemas ./other/dir/to/schemas

# Put schemas under a directory recursively
cerbosctl put schema --recursive ./dir/to/schemas
cerbosctl put schema -R ./dir/to/schemas`

type SchemaCmd struct {
	Paths []string `arg:"" type:"path" help:"Path to schema file or directory"`
}

func (sc *SchemaCmd) Run(k *kong.Kong, put *Cmd, ctx *cmdclient.Context) error {
	if len(sc.Paths) == 0 {
		return fmt.Errorf("no filename(s) provided")
	}

	schemas, err := sc.findFiles(sc.Paths, put.Recursive)
	if err != nil {
		return err
	}

	err = ctx.AdminClient.AddOrUpdateSchema(context.TODO(), schemas)
	if err != nil {
		return fmt.Errorf("failed to add or update the schemas: %w", err)
	}

	return nil
}

func (sc *SchemaCmd) Help() string {
	return schemaCmdHelp
}

func (sc *SchemaCmd) findFiles(paths []string, recursive bool) ([]*schemav1.Schema, error) {
	var schemas []*schemav1.Schema
	for _, path := range paths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		//nolint:nestif
		if fileInfo.IsDir() {
			fsys := os.DirFS(path)
			err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() && recursive {
					return nil
				} else if d.IsDir() && !recursive && d.Name() != "." {
					return fs.SkipDir
				}

				if d.IsDir() {
					return nil
				}

				if !util.IsSupportedFileType(d.Name()) {
					return nil
				}

				f, err := fsys.Open(path)
				if err != nil {
					return nil //nolint:nilerr
				}

				defer f.Close()

				definition, err := io.ReadAll(io.Reader(f))
				if err != nil {
					return nil //nolint:nilerr
				}

				schemas = append(schemas, &schemav1.Schema{
					Id:         filepath.Base(path),
					Definition: definition,
				})

				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			if !util.IsSupportedFileType(fileInfo.Name()) {
				return nil, fmt.Errorf("unsupported file type %q: %w", path, err)
			}

			f, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open file %q: %w", path, err)
			}

			definition, err := io.ReadAll(io.Reader(f))
			if err != nil {
				return nil, err
			}

			err = f.Close()
			if err != nil {
				return nil, err
			}

			schemas = append(schemas, &schemav1.Schema{
				Id:         filepath.Base(path),
				Definition: definition,
			})
		}
	}

	return schemas, nil
}
