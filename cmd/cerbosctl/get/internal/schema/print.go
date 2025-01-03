// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
)

func printSchema(w io.Writer, schemas []*schemav1.Schema, output flagset.OutputFormat) error {
	switch output {
	case flagset.OutputFormatNone, flagset.OutputFormatJSON:
		return printSchemaJSON(w, schemas)
	case flagset.OutputFormatPrettyJSON:
		return printSchemaPrettyJSON(w, schemas)
	default:
		return fmt.Errorf("only json and prettyjson formats are supported")
	}
}

func printSchemaPrettyJSON(w io.Writer, schemas []*schemav1.Schema) error {
	for _, s := range schemas {
		_, err := fmt.Fprintf(w, "%s\n", s.Definition)
		if err != nil {
			return fmt.Errorf("failed to print schema: %w", err)
		}
	}
	return nil
}

func printSchemaJSON(w io.Writer, schemas []*schemav1.Schema) error {
	for _, s := range schemas {
		var b bytes.Buffer
		err := json.Compact(&b, s.Definition)
		if err != nil {
			return fmt.Errorf("failed to produce compact json for schema: %w", err)
		}

		_, err = fmt.Fprintf(w, "%s\n", b.String())
		if err != nil {
			return fmt.Errorf("failed to print schema: %w", err)
		}
	}

	return nil
}
