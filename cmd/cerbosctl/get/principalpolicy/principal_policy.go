// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package principalpolicy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
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
		PreRunE: policy.PreRunFn(policy.PrincipalPolicy, &flags.Filters, &flags.Format),
		RunE:    fn(runPrincipalPolicyCmd),
	}

	cmd.Flags().AddFlagSet(flags.Format.FlagSet())
	cmd.Flags().AddFlagSet(flags.Filters.FlagSet())

	return cmd
}

func runPrincipalPolicyCmd(c client.AdminClient, cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		err := policy.List(c, cmd, &flags.Filters, &flags.Format, policy.PrincipalPolicy)
		if err != nil {
			return fmt.Errorf("failed to list principal policies: %w", err)
		}

		return nil
	}

	err := policy.Get(c, cmd, &flags.Format, args[1:]...)
	if err != nil {
		return fmt.Errorf("failed to get principal policies: %w", err)
	}

	return nil
}
