// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disable

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	internalclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const policyCmdHelp = `# Disable policies
cerbosctl disable policies derived_roles.my_derived_roles
cerbosctl disable policy derived_roles.my_derived_roles
cerbosctl disable p derived_roles.my_derived_roles

# Disable multiple policies
cerbosctl disable policies derived_roles.my_derived_roles resource.leave_request.default
cerbosctl disable policy derived_roles.my_derived_roles resource.leave_request.default
cerbosctl disable p derived_roles.my_derived_roles resource.leave_request.default`

type Cmd struct {
	Policy PolicyCmd `cmd:"" aliases:"policies,p"`
}

type PolicyCmd struct {
	PolicyIds []string `arg:"" name:"id" help:"list of policy ids to disable"` //nolint:revive
}

func (c *Cmd) Run(k *kong.Kong, ctx *internalclient.Context) error {
	if len(c.Policy.PolicyIds) == 0 {
		return fmt.Errorf("no policy id(s) provided")
	}

	disabledPolicies, err := cerbos.BatchAdminClientCall(context.Background(), ctx.AdminClient.DisablePolicy, c.Policy.PolicyIds...)
	if err != nil {
		return fmt.Errorf("failed to disable policies: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Number of policies disabled is %d", disabledPolicies)
	return nil
}

func (pc *PolicyCmd) Help() string {
	return policyCmdHelp
}
