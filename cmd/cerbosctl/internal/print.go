// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/util"
)

const prettyPrintIndent = "  "

func PrintIds(w io.Writer, ids ...string) error {
	for _, id := range ids {
		_, err := fmt.Fprintf(w, "%s\n", id)
		if err != nil {
			return fmt.Errorf("failed to print to writer: %w", err)
		}
	}

	return nil
}

func PrintSchemaHeader(w io.Writer) error {
	_, err := fmt.Fprintf(w, "SCHEMA ID\n")
	if err != nil {
		return fmt.Errorf("failed print to writer: %w", err)
	}

	return nil
}

func PrintSchemaPrettyJSON(w io.Writer, schemas []*schemav1.Schema) error {
	for _, s := range schemas {
		_, err := fmt.Fprintf(w, "%s\n", s.Definition)
		if err != nil {
			return fmt.Errorf("failed to print schema: %w", err)
		}
	}
	return nil
}

func PrintSchemaJSON(w io.Writer, schemas []*schemav1.Schema) error {
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

func PrintPolicyHeader(w io.Writer) error {
	_, err := fmt.Fprintf(w, "POLICY ID\n")
	if err != nil {
		return fmt.Errorf("failed print to writer: %w", err)
	}

	return nil
}

func PrintPolicyJSON(w io.Writer, policies []*policyv1.Policy) error {
	for _, p := range policies {
		b, err := protojson.Marshal(p)
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

func PrintPolicyPrettyJSON(w io.Writer, policies []*policyv1.Policy) error {
	for _, p := range policies {
		b, err := protojson.Marshal(p)
		if err != nil {
			return fmt.Errorf("could not marshal policy: %w", err)
		}

		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, b, "", prettyPrintIndent)
		if err != nil {
			return fmt.Errorf("could not indent policy: %w", err)
		}

		_, err = fmt.Fprintf(w, "%s\n", prettyJSON.String())
		if err != nil {
			return fmt.Errorf("failed to print policy: %w", err)
		}
	}
	return nil
}

func PrintPolicyYAML(w io.Writer, policies []*policyv1.Policy) error {
	for _, p := range policies {
		_, err := fmt.Fprintln(w, "---")
		if err != nil {
			return fmt.Errorf("failed to print header: %w", err)
		}

		err = util.WriteYAML(w, p)
		if err != nil {
			return fmt.Errorf("could not write policy: %w", err)
		}
	}
	return nil
}
