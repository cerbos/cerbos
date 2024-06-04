// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package resourcepolicy

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	cmdpolicy "github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/policy"
)

const help = `# List resource policies
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

type Cmd struct {
	flagset.Format
	flagset.Sort
	flagset.Filters
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	return cmdpolicy.DoCmd(k, ctx.AdminClient, policy.ResourceKind, &c.Filters, &c.Format, &c.Sort, c.PolicyIDs)
}

func (c *Cmd) Validate() error {
	if err := c.Filters.Validate(policy.ResourceKind, len(c.PolicyIDs) == 0); err != nil {
		return err
	}

	if err := c.Format.Validate(len(c.PolicyIDs) == 0); err != nil {
		return err
	}

	return c.Sort.Validate(policy.ResourceKind, len(c.PolicyIDs) == 0)
}

func (c *Cmd) Help() string {
	return help
}
