// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package exportconstants

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	cmdpolicy "github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/policy"
)

const help = `# List exported constants
cerbosctl get export_constants
cerbosctl get ec

# List and filter exported constants
cerbosctl get export_constants --name my_constants

# List and sort exported constants by column
cerbosctl get export_constants --sort-by policyId
cerbosctl get export_constants --sort-by name

# List all policies including disabled policies
cerbosctl get export_constants --include-disabled

# Get exported constants policy definition (disk, git, blob stores)
cerbosctl get export_constants my_constants.yaml

# Get exported constants policy definition (mutable stores)
cerbosctl get export_constants export_constants.my_constants

# Get exported constants policy definition as yaml
cerbosctl get export_constants export_constants.my_constants -oyaml

# Get exported constants policy definition as json
cerbosctl get export_constants export_constants.my_constants -ojson

# Get exported constants policy definition as pretty json
cerbosctl get export_constants export_constants.my_constants -oprettyjson`

type Cmd struct { //betteralign:ignore
	flagset.Format
	flagset.Sort
	flagset.Filters
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	return cmdpolicy.DoCmd(k, ctx.AdminClient, policy.ExportConstantsKind, &c.Filters, &c.Format, &c.Sort, c.PolicyIDs)
}

func (c *Cmd) Validate() error {
	if err := c.Filters.Validate(policy.ExportConstantsKind, len(c.PolicyIDs) == 0); err != nil {
		return err
	}

	if err := c.Format.Validate(len(c.PolicyIDs) == 0); err != nil {
		return err
	}

	return c.Sort.Validate(policy.ExportConstantsKind, len(c.PolicyIDs) == 0)
}

func (c *Cmd) Help() string {
	return help
}
