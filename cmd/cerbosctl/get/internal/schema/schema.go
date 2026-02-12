// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"fmt"
	"sort"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
)

func List(k *kong.Kong, c *cerbos.GRPCAdminClient, format *flagset.Format) error {
	schemaIDs, err := c.ListSchemas(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting schemas: %w", err)
	}

	tw := printer.NewTableWriter(k.Stdout)
	if !format.NoHeaders {
		tw.Header([]string{"SCHEMA ID"})
	}

	sort.Strings(schemaIDs)
	for _, id := range schemaIDs {
		if err := tw.Append([]string{id}); err != nil {
			return fmt.Errorf("failed to append row to the table: %w", err)
		}
	}

	if err := tw.Render(); err != nil {
		return fmt.Errorf("failed to render table: %w", err)
	}

	return nil
}

func Get(k *kong.Kong, c *cerbos.GRPCAdminClient, format *flagset.Format, ids ...string) error {
	if err := cerbos.BatchAdminClientCall2(context.Background(), c.GetSchema, func(_ context.Context, schemas []*schemav1.Schema) error {
		if err := printSchema(k.Stdout, schemas, format.Output); err != nil {
			return fmt.Errorf("could not print schemas: %w", err)
		}

		return nil
	}, ids...); err != nil {
		return fmt.Errorf("error while getting schemas: %w", err)
	}

	return nil
}
