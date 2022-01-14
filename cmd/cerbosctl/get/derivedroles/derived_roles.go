// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package derivedroles

import (
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

const example = `# List derived roles
cerbosctl get derived_roles
cerbosctl get derived_role
cerbosctl get dr

# List and filter derived roles
cerbosctl get derived_roles --name my_derived_roles

# Get derived role policy definition (disk, git, blob stores)
cerbosctl get derived_roles blog_derived_roles.yaml

# Get derived role policy definition (mutable stores)
cerbosctl get derived_roles derived_roles.my_derived_roles

# Get derived role policy definition as yaml
cerbosctl get derived_roles derived_roles.my_derived_roles -oyaml

# Get derived role policy definition as json
cerbosctl get derived_roles derived_roles.my_derived_roles -ojson

# Get derived role policy definition as pretty json
cerbosctl get derived_roles derived_roles.my_derived_roles -oprettyjson`

type flag struct {
	flagset.Format
	flagset.Filters
}

var flags = &flag{}

func NewDerivedRolesCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "derived_roles",
		Aliases: []string{"derived_role", "dr"},
		Example: example,
		PreRunE: policy.PreRunFn(policy.DerivedRoles),
		RunE:    fn(policy.MakeGetCmd(policy.DerivedRoles, &flags.Filters, &flags.Format)),
	}

	cmd.Flags().AddFlagSet(flags.Format.FlagSet("yaml"))
	cmd.Flags().AddFlagSet(flags.Filters.FlagSet())

	return cmd
}
