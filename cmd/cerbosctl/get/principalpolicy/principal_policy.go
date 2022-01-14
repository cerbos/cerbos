// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package principalpolicy

import (
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

const example = `# List principal policies
cerbosctl get principal_policies
cerbosctl get principal_policy
cerbosctl get pp

# List and filter principal policies
cerbosctl get principal_policies --name donald_duck

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

type flag struct {
	flagset.Format
	flagset.Filters
}

var flags = &flag{}

func NewPrincipalPolicyCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "principal_policies",
		Aliases: []string{"principal_policy", "pp"},
		Example: example,
		PreRunE: policy.PreRunFn(policy.PrincipalPolicy),
		RunE:    fn(policy.MakeGetCmd(policy.PrincipalPolicy, &flags.Filters, &flags.Format)),
	}

	cmd.Flags().AddFlagSet(flags.Format.FlagSet())
	cmd.Flags().AddFlagSet(flags.Filters.FlagSet())

	return cmd
}
