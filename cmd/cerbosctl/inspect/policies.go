// Copyright 2021-2024 Zenauth Ltd.
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
type PoliciesCmd struct {
	flagset.Filters
	flagset.Format
}

func (c *PoliciesCmd) Run(k *kong.Kong, cctx *client.Context) error {
	var opts []cerbos.FilterOption
	if len(c.PolicyIDs) > 0 {
		opts = append(opts, cerbos.WithPolicyID(c.PolicyIDs...))
	}

	if c.Filters.IncludeDisabled {
		opts = append(opts, cerbos.WithIncludeDisabled())
	}
	if c.Filters.NameRegexp != "" {
		opts = append(opts, cerbos.WithNameRegexp(c.Filters.NameRegexp))
	}
	if c.Filters.ScopeRegexp != "" {
		opts = append(opts, cerbos.WithScopeRegexp(c.Filters.ScopeRegexp))
	}
	if c.Filters.VersionRegexp != "" {
		opts = append(opts, cerbos.WithVersionRegexp(c.Filters.VersionRegexp))
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
