// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disable

import (
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/disable/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const policyCmdHelp = `# Disable policies
cerbosctl disable policies derived_roles.my_derived_roles
cerbosctl disable policy derived_roles.my_derived_roles
cerbosctl disable p derived_roles.my_derived_roles

# Disable multiple policies
cerbosctl disable policies derived_roles.my_derived_roles resource.leave_request.default
cerbosctl disable policy derived_roles.my_derived_roles resource.leave_request.default
cerbosctl disable p derived_roles.my_derived_roles resource.leave_request.default`

type PolicyCmd struct {
	PolicyIds []string `arg:"" name:"id" help:"list of policy ids to disable"`
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	if len(c.Policy.PolicyIds) == 0 {
		return fmt.Errorf("no policy id(s) provided")
	}

	disabledPolicies, err := policy.Disable(ctx.AdminClient, c.Policy.PolicyIds...)
	if err != nil {
		return fmt.Errorf("failed to disable policies: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Number of policies disabled is %d", disabledPolicies)
	return nil
}

func (pc *PolicyCmd) Help() string {
	return policyCmdHelp
}
