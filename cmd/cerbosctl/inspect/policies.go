// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos/cmd/cerbosctl/inspect/internal"
	"github.com/cerbos/cerbos/cmd/cerbosctl/inspect/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const (
	help = `# Inspect policies

cerbosctl inspect policies

# Inspect policies, print no headers

cerbosctl inspect policies`
)

//nolint:govet
type PoliciesCmd struct { //betteralign:ignore
	flagset.Filters
	flagset.Format
}

func (c *PoliciesCmd) Run(k *kong.Kong, cctx *client.Context) error {
	var opts []cerbos.FilterOption
	if len(c.PolicyIDs) > 0 {
		opts = append(opts, cerbos.WithPolicyID(c.PolicyIDs...))
	}

	if c.IncludeDisabled {
		opts = append(opts, cerbos.WithIncludeDisabled())
	}
	if c.NameRegexp != "" {
		opts = append(opts, cerbos.WithNameRegexp(c.NameRegexp))
	}
	if c.ScopeRegexp != "" {
		opts = append(opts, cerbos.WithScopeRegexp(c.ScopeRegexp))
	}
	if c.VersionRegexp != "" {
		opts = append(opts, cerbos.WithVersionRegexp(c.VersionRegexp))
	}

	response, err := cctx.AdminClient.InspectPolicies(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("error while inspecting policies: %w", err)
	}

	if err := internal.Print(k.Stdout, c.Format, response); err != nil {
		return fmt.Errorf("failed to print inspection results: %w", err)
	}

	return nil
}

func (c *PoliciesCmd) Help() string {
	return help
}
