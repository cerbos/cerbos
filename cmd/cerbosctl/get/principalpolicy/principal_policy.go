// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package principalpolicy

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	cmdpolicy "github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/policy"
)

const help = `# List principal policies
cerbosctl get principal_policies
cerbosctl get principal_policy
cerbosctl get pp

# List and filter principal policies
cerbosctl get principal_policies --name donald_duck

# List and sort principal policies by column
cerbosctl get principal_policies --sort-by policyId
cerbosctl get principal_policies --sort-by name
cerbosctl get principal_policies --sort-by version

# Get principal policy definition (disk, git, blob stores)
cerbosctl get principal_policies donald_duck.yaml

# Get principal policy definition (mutable stores)
cerbosctl get principal_policies principal.donald_duck.default

# Get principal policy definition as yaml
cerbosctl get principal_policies principal.donald_duck.default -oyaml

# Get principal policy definition as json
cerbosctl get principal_policies principal.donald_duck.default -ojson

# Get principal policy definition as pretty json
cerbosctl get principal_policies principal.donald_duck.default -oprettyjson`

type Cmd struct {
	flagset.Filters
	flagset.Format
	flagset.Sort

	PolicyIds []string `arg:"" name:"id" optional:"" help:"list of policy ids to retrieve"` //nolint:revive
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	err := cmdpolicy.DoCmd(k, ctx.AdminClient, policy.PrincipalKind, &c.Filters, &c.Format, &c.Sort, c.PolicyIds)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cmd) Validate() error {
	if err := c.Filters.Validate(policy.PrincipalKind, len(c.PolicyIds) == 0); err != nil {
		return err
	}

	if err := c.Format.Validate(len(c.PolicyIds) == 0); err != nil {
		return err
	}

	return c.Sort.Validate(policy.PrincipalKind, len(c.PolicyIds) == 0)
}

func (c *Cmd) Help() string {
	return help
}
