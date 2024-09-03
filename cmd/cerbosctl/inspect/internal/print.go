// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/inspect/internal/flagset"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	separator = ","
	width     = 80
)

func Print(w io.Writer, format flagset.Format, response *responsev1.InspectPoliciesResponse) error {
	results := make([]*responsev1.InspectPoliciesResponse_Result, 0, len(response.Results))
	for _, result := range response.Results {
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].PolicyId < results[j].PolicyId
	})

	switch format.Output {
	case flagset.OutputFormatNone:
		printTable(w, format.NoHeaders, results)
	case flagset.OutputFormatJSON:
		return printJSON(w, results)
	case flagset.OutputFormatPrettyJSON:
		return printPrettyJSON(w, results)
	case flagset.OutputFormatYAML:
		return printYAML(w, results)
	}

	return nil
}

func printYAML(w io.Writer, results []*responsev1.InspectPoliciesResponse_Result) error {
	for _, result := range results {
		if _, err := fmt.Fprintln(w, "---"); err != nil {
			return fmt.Errorf("failed to print header: %w", err)
		}

		if err := util.WriteYAML(w, result); err != nil {
			return fmt.Errorf("failed to write as yaml: %w", err)
		}
	}

	return nil
}

func printPrettyJSON(w io.Writer, results []*responsev1.InspectPoliciesResponse_Result) error {
	for _, result := range results {
		s := protojson.Format(result)
		if _, err := fmt.Fprintf(w, "%s\n", s); err != nil {
			return fmt.Errorf("failed to print result: %w", err)
		}
	}

	return nil
}

func printJSON(w io.Writer, results []*responsev1.InspectPoliciesResponse_Result) error {
	for _, result := range results {
		b, err := protojson.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}

		if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
			return fmt.Errorf("failed to print result: %w", err)
		}
	}

	return nil
}

func printTable(w io.Writer, noHeaders bool, results []*responsev1.InspectPoliciesResponse_Result) {
	rowSeparator := strings.Repeat("-", width)
	for _, result := range results {
		attributes := make([]string, len(result.Attributes))
		for idx, attribute := range result.Attributes {
			switch attribute.Kind {
			case responsev1.InspectPoliciesResponse_Attribute_KIND_PRINCIPAL_ATTRIBUTE:
				attributes[idx] = fmt.Sprintf("%s.attr.%s", conditions.CELPrincipalAbbrev, attribute.Name)
			case responsev1.InspectPoliciesResponse_Attribute_KIND_RESOURCE_ATTRIBUTE:
				attributes[idx] = fmt.Sprintf("%s.attr.%s", conditions.CELResourceAbbrev, attribute.Name)
			default:
				attributes[idx] = attribute.Name
			}
		}

		variables := make([]string, len(result.Variables))
		for idx, variable := range result.Variables {
			variables[idx] = variable.Name
		}

		//nolint:nestif
		if noHeaders {
			fmt.Fprintf(w, "%s\n", result.PolicyId)
			if len(result.Actions) > 0 {
				fmt.Fprintf(w, "%s\n", strings.Join(result.Actions, separator))
			}
			if len(attributes) > 0 {
				fmt.Fprintf(w, "%s\n", strings.Join(attributes, separator))
			}
			if len(variables) > 0 {
				fmt.Fprintf(w, "%s\n", strings.Join(variables, separator))
			}
		} else {
			fmt.Fprintf(w, "POLICY ID : %s\n", result.PolicyId)
			if len(result.Actions) > 0 {
				fmt.Fprintf(w, "ACTIONS   : %s\n", strings.Join(result.Actions, separator))
			}
			if len(attributes) > 0 {
				fmt.Fprintf(w, "ATTRIBUTES: %s\n", strings.Join(attributes, separator))
			}
			if len(variables) > 0 {
				fmt.Fprintf(w, "VARIABLES : %s\n", strings.Join(variables, separator))
			}
		}
		fmt.Fprintf(w, "%s\n", rowSeparator)
	}
}
