// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package resourcepolicy

import (
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

const example = `# List resource policies
cerbosctl get resource_policies
cerbosctl get resource_policy
cerbosctl get rp

# List and filter resource policies
cerbosctl get resource_policies --name leave_request

# List and sort resource policies by column
cerbosctl get resource_policies --sort-by policyId
cerbosctl get resource_policies --sort-by name
cerbosctl get resource_policies --sort-by version

# Get resource policy definition (disk, git, blob stores)
cerbosctl get resource_policies leave_request.yaml

# Get resource policy definition (mutable stores)
cerbosctl get resource_policies resource.leave_request.default

# Get resource policy definition as yaml
cerbosctl get resource_policies resource.leave_request.default -oyaml

# Get resource policy definition as json
cerbosctl get resource_policies resource.leave_request.default -ojson

# Get resource policy definition as pretty json
cerbosctl get resource_policies resource.leave_request.default -oprettyjson`

type flag struct {
	flagset.Sort
	flagset.Format
	flagset.Filters
}

var flags = &flag{}

func NewResourcePolicyCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "resource_policies",
		Aliases: []string{"resource_policy", "rp"},
		Example: example,
		PreRunE: policy.PreRunFn(policy.ResourcePolicy),
		RunE:    fn(policy.MakeGetCmd(policy.ResourcePolicy, &flags.Filters, &flags.Format, &flags.Sort)),
	}

	cmd.Flags().AddFlagSet(flags.Sort.FlagSet())
	cmd.Flags().AddFlagSet(flags.Format.FlagSet("yaml"))
	cmd.Flags().AddFlagSet(flags.Filters.FlagSet())

	return cmd
}
