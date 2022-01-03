// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	policy "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/util"
)

func PrintJSON(w io.Writer, policies []*policy.Policy) error {
	for _, policy := range policies {
		b, err := protojson.Marshal(policy)
		if err != nil {
			return fmt.Errorf("could not marshal policy: %w", err)
		}
		fmt.Fprintf(w, "%s\n", b)
	}
	return nil
}

func PrintYAML(w io.Writer, policies []*policy.Policy) error {
	for _, policy := range policies {
		err := util.WriteYAML(w, policy)
		if err != nil {
			return fmt.Errorf("could not write policy: %w", err)
		}
		fmt.Fprintln(w, "---")
	}
	return nil
}
