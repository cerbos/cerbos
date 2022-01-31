// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

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

func PrintPolicyJSON(w io.Writer, policies map[string]policy.Wrapper) error {
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

func PrintPolicyPrettyJSON(w io.Writer, policies map[string]policy.Wrapper) error {
	for _, p := range policies {
		s := protojson.Format(p.Policy)

		_, err := fmt.Fprintf(w, "%s\n", s)
		if err != nil {
			return fmt.Errorf("failed to print policy: %w", err)
		}
	}
	return nil
}

func PrintPolicyYAML(w io.Writer, policies map[string]policy.Wrapper) error {
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
