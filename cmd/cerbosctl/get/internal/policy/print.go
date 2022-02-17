// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

func printPolicy(w io.Writer, policies []policy.Wrapper, format string) error {
	switch format {
	case "json":
		return printPolicyJSON(w, policies)
	case "yaml":
		return printPolicyYAML(w, policies)
	case "prettyjson", "pretty-json":
		return printPolicyPrettyJSON(w, policies)
	default:
		return fmt.Errorf("only yaml, json and prettyjson formats are supported")
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
	if kind == policy.DerivedRolesKind {
		return []string{"POLICY ID", "NAME"}
	}
	return []string{"POLICY ID", "NAME", "VERSION", "SCOPE"}
}
