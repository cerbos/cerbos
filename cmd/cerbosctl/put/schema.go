// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

import (
	"context"
	"fmt"

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
cerbosctl put schema -R ./dir/to/schemas`

type SchemaCmd struct {
	Paths []string `arg:"" type:"path" help:"Path to schema file or directory"`
}

func (sc *SchemaCmd) Run(k *kong.Kong, put *Cmd, ctx *cmdclient.Context) error {
	if len(sc.Paths) == 0 {
		return fmt.Errorf("no filename(s) provided")
	}

	schemas := client.NewSchemaSet()
	var errs []error
	err := files.Find(sc.Paths, put.Recursive, func(filePath string) error {
		_, err := schemas.AddSchemaFromFileWithErr(filePath, true)
		if err != nil {
			errs = append(errs, errors.NewPutError(filePath, err.Error()))
		}

		return nil
	}, util.IsJSONFileTypeExt)
	if err != nil {
		return err
	}

	err = ctx.AdminClient.AddOrUpdateSchema(context.TODO(), schemas)
	if err != nil {
		return fmt.Errorf("failed to add or update the schemas: %w", err)
	}

	_, err = fmt.Fprintf(k.Stdout, "Uploaded: %d - Ignored: %d\n", schemas.Size(), len(errs))
	if err != nil {
		return fmt.Errorf("failed to print: %w", err)
	}
	if len(errs) != 0 {
		_, err = fmt.Fprintln(k.Stdout, "Errors for the ignored files;")
		if err != nil {
			return fmt.Errorf("failed to print: %w", err)
		}
	}
	for _, putErr := range errs {
		_, err = fmt.Fprintf(k.Stdout, "- %s\n", putErr.Error())
		if err != nil {
			return fmt.Errorf("failed to print: %w", err)
		}
	}

	return nil
}

func (sc *SchemaCmd) Help() string {
	return schemaCmdHelp
}
