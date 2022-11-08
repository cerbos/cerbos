// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/client"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put/internal/files"
	"github.com/cerbos/cerbos/internal/util"
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
cerbosctl put schema -R ./dir/to/schemas

# Put schemas from a zip file
cerbosctl put schema ./dir/to/schemas.zip`

type SchemaCmd struct {
	Paths []string `arg:"" type:"path" help:"Path to schema file or directory"`
}

func (sc *SchemaCmd) Run(k *kong.Kong, put *Cmd, ctx *cmdclient.Context) error {
	if len(sc.Paths) == 0 {
		return fmt.Errorf("no filename(s) provided")
	}

	schemas := client.NewSchemaSet()
	var errs []error
	err := files.Find(sc.Paths, put.Recursive, util.FileTypeSchema, func(found files.Found) error {
		switch f := found.(type) {
		case files.FoundFile:
			_, err := schemas.AddSchemaFromFileWithIDAndErr(f.AbsolutePath(), f.Path())
			if err != nil {
				errs = append(errs, errors.NewPutError(f.AbsolutePath(), err.Error()))
			}
		case files.FoundZip:
			id := strings.TrimPrefix(f.Path(), fmt.Sprintf("%s%s", util.SchemasDirectory, string(filepath.Separator)))
			_, err := schemas.AddSchemaFromZipFile(f.File(), id, f.Path())
			if err != nil {
				errs = append(errs, errors.NewPutError(fmt.Sprintf("from zip file: %s", f.Path()), err.Error()))
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = ctx.AdminClient.AddOrUpdateSchema(context.TODO(), schemas)
	if err != nil {
		return fmt.Errorf("failed to add or update the schemas: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Uploaded: %d\nIgnored: %d\n", schemas.Size(), len(errs))
	if len(errs) != 0 {
		_, _ = fmt.Fprintln(k.Stdout, "Errors:")
	}
	for _, putErr := range errs {
		_, _ = fmt.Fprintf(k.Stdout, "- %s\n", putErr.Error())
	}

	return nil
}

func (sc *SchemaCmd) Help() string {
	return schemaCmdHelp
}
