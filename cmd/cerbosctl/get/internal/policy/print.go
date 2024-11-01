// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

func printPolicy(w io.Writer, policies []policy.Wrapper, output flagset.OutputFormat) error {
	switch output {
	case flagset.OutputFormatNone, flagset.OutputFormatJSON:
		return printPolicyJSON(w, policies)
	case flagset.OutputFormatYAML:
		return printPolicyYAML(w, policies)
	case flagset.OutputFormatPrettyJSON:
		return printPolicyPrettyJSON(w, policies)
	default:
		return fmt.Errorf("only %q, %q and %q formats are supported", flagset.OutputFormatJSON, flagset.OutputFormatYAML, flagset.OutputFormatPrettyJSON)
	}
}

func printPolicyJSON(w io.Writer, policies []policy.Wrapper) error {
	for _, p := range policies {
		b, err := protojson.Marshal(p.Policy)
		if err != nil {
			return fmt.Errorf("could not marshal policy: %w", err)
		}
		_, err = fmt.Fprintf(w, "%s\n", b)
		if err != nil {
			return fmt.Errorf("failed to print policy: %w", err)
		}
	}
	return nil
}

func printPolicyPrettyJSON(w io.Writer, policies []policy.Wrapper) error {
	for _, p := range policies {
		s := protojson.Format(p.Policy)

		_, err := fmt.Fprintf(w, "%s\n", s)
		if err != nil {
			return fmt.Errorf("failed to print policy: %w", err)
		}
	}
	return nil
}

func printPolicyYAML(w io.Writer, policies []policy.Wrapper) error {
	for _, p := range policies {
		_, err := fmt.Fprintln(w, "---")
		if err != nil {
			return fmt.Errorf("failed to print header: %w", err)
		}

		err = util.WriteYAML(w, p.Policy)
		if err != nil {
			return fmt.Errorf("could not write policy: %w", err)
		}
	}
	return nil
}

func getHeaders(kind policy.Kind) []string {
	switch kind {
	case policy.DerivedRolesKind, policy.ExportConstantsKind, policy.ExportVariablesKind:
		return []string{"POLICY ID", "NAME"}

	case policy.PrincipalKind, policy.ResourceKind:
		return []string{"POLICY ID", "NAME", "VERSION", "SCOPE"}

	case policy.RolePolicyKind:
		return []string{"POLICY ID", "NAME", "SCOPE"}
	}

	panic(fmt.Errorf("unknown policy kind %d", kind))
}
