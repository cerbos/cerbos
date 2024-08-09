// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rolepolicy

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	cmdpolicy "github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/policy"
)

const help = `# List role policies
cerbosctl get role_policies
cerbosctl get role_policy
cerbosctl get rlp

# List and filter role policies
cerbosctl get role_policies --name acme_admin

# List and sort role policies by column
cerbosctl get role_policies --sort-by policyId
cerbosctl get role_policies --sort-by name

# Get role policy definition (disk, git, blob stores)
cerbosctl get role_policies acme_admin.yaml

# Get role policy definition (mutable stores)
cerbosctl get role_policies role.acme_admin

# Get role policy definition as yaml
cerbosctl get role_policies role.acme_admin -oyaml

# Get role policy definition as json
cerbosctl get role_policies role.acme_admin -ojson

# Get role policy definition as pretty json
cerbosctl get role_policies role.acme_admin -oprettyjson`

type Cmd struct {
	flagset.Format
	flagset.Sort
	flagset.Filters
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	return cmdpolicy.DoCmd(k, ctx.AdminClient, policy.RolePolicyKind, &c.Filters, &c.Format, &c.Sort, c.PolicyIDs)
}

func (c *Cmd) Validate() error {
	if err := c.Filters.Validate(policy.RolePolicyKind, len(c.PolicyIDs) == 0); err != nil {
		return err
	}

	if err := c.Format.Validate(len(c.PolicyIDs) == 0); err != nil {
		return err
	}

	return c.Sort.Validate(policy.RolePolicyKind, len(c.PolicyIDs) == 0)
}

func (c *Cmd) Help() string {
	return help
}
