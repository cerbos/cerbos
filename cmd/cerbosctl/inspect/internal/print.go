// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"io"
	"strings"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/inspect/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
)

const (
	separator = ","
)

func Print(w io.Writer, format flagset.Format, results []*responsev1.InspectPoliciesResponse_Result) error {
	switch format.Output {
	case flagset.OutputFormatNone:
		printTable(w, format.NoHeaders, results)
	case flagset.OutputFormatJSON:
	case flagset.OutputFormatPrettyJSON:
	case flagset.OutputFormatYAML:
	}

	return nil
}

func printTable(w io.Writer, noHeaders bool, results []*responsev1.InspectPoliciesResponse_Result) {
	tw := printer.NewTableWriter(w)
	if !noHeaders {
		tw.SetHeader([]string{"POLICY ID", "ACTIONS", "VARIABLES"})
	}

	for _, result := range results {
		variables := make([]string, len(result.Variables))
		for idx, variable := range result.Variables {
			variables[idx] = variable.Name
		}

		tw.Append([]string{
			result.StoreIdentifier,
			strings.Join(result.Actions, separator),
			strings.Join(variables, separator),
		})
	}

	tw.Render()
}
