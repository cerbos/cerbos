// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"fmt"
	"sort"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/printer"
)

func List(k *kong.Kong, c client.AdminClient, format *flagset.Format) error {
	schemaIds, err := c.ListSchemas(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting schemas: %w", err)
	}

	tw := printer.NewTableWriter(k.Stdout)
	if !format.NoHeaders {
		tw.SetHeader([]string{"SCHEMA ID"})
	}

	sort.Strings(schemaIds)
	for _, id := range schemaIds {
		tw.Append([]string{id})
	}
	tw.Render()

	return nil
}

func Get(k *kong.Kong, c client.AdminClient, format *flagset.Format, policyIds ...string) error {
	for idx := range policyIds {
		if idx%client.MaxIDPerReq == 0 {
			idxEnd := client.MinInt(idx+client.MaxIDPerReq, len(policyIds)-idx)
			schemas, err := c.GetSchema(context.Background(), policyIds[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting schema: %w", err)
			}

			if err = printSchema(k.Stdout, schemas, format.Output); err != nil {
				return fmt.Errorf("could not print schemas: %w", err)
			}
		}
	}
	return nil
}
