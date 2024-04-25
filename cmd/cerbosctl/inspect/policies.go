// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"context"
	"fmt"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos"

	"github.com/cerbos/cerbos/cmd/cerbosctl/inspect/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
)

const (
	help = `# Inspect policies

cerbosctl inspect policies

# Inspect policies, print no headers

cerbosctl inspect policies`
	separator = ","
)

type PoliciesCmd struct {
	flagset.Filters
	flagset.Format
}

func (c *PoliciesCmd) Run(k *kong.Kong, cctx *client.Context) error {
	var opts []cerbos.FilterOption
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

	tw := printer.NewTableWriter(k.Stdout)
	if !c.Format.NoHeaders {
		tw.SetHeader([]string{"POLICY ID", "ACTIONS", "VARIABLES"})
	}

	for policyKey, result := range response.Results {
		variables := make([]string, len(result.Variables))
		for idx, variable := range result.Variables {
			variables[idx] = variable.Name
		}

		tw.Append([]string{
			policyKey,
			strings.Join(result.Actions, separator),
			strings.Join(variables, separator),
		})
	}

	tw.Render()
	return nil
}

func (c *PoliciesCmd) Help() string {
	return help
}
