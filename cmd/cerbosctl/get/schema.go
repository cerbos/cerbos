// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

func listSchemas(c client.AdminClient, cmd *cobra.Command, args *Arguments) error {
	schemaIds, err := c.ListSchemas(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting schemas: %w", err)
	}

	if !args.NoHeaders {
		err = internal.PrintSchemaHeader(cmd.OutOrStdout())
		if err != nil {
			return fmt.Errorf("failed to print header: %w", err)
		}
	}

	err = internal.PrintIds(cmd.OutOrStdout(), schemaIds...)
	if err != nil {
		return fmt.Errorf("failed to print schema ids: %w", err)
	}

	return nil
}

func getSchema(c client.AdminClient, cmd *cobra.Command, args *Arguments, ids ...string) error {
	for idx := range ids {
		if idx%internal.MaxIDPerReq == 0 {
			schemas, err := c.GetSchema(context.Background(), ids[idx:internal.MinInt(idx+internal.MaxIDPerReq, len(ids)-idx)]...)
			if err != nil {
				return fmt.Errorf("error while requesting schema: %w", err)
			}

			if err = printSchema(cmd.OutOrStdout(), schemas, args.Output); err != nil {
				return fmt.Errorf("could not print schemas: %w", err)
			}
		}
	}
	return nil
}

func printSchema(w io.Writer, schemas []*schemav1.Schema, output string) error {
	switch output {
	case "json":
		return internal.PrintSchemaJSON(w, schemas)
	case "prettyjson", "pretty-json":
		return internal.PrintSchemaPrettyJSON(w, schemas)
	default:
		return fmt.Errorf("only json and prettyjson formats are supported")
	}
}
