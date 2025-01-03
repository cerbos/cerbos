// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package enable

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	internalclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const policyCmdHelp = `# Enable policies
cerbosctl enable policies derived_roles.my_derived_roles
cerbosctl enable policy derived_roles.my_derived_roles
cerbosctl enable p derived_roles.my_derived_roles

# Enable multiple policies
cerbosctl enable policies derived_roles.my_derived_roles resource.leave_request.default
cerbosctl enable policy derived_roles.my_derived_roles resource.leave_request.default
cerbosctl enable p derived_roles.my_derived_roles resource.leave_request.default`

type Cmd struct {
	Policy PolicyCmd `cmd:"" aliases:"policies,p"`
}

type PolicyCmd struct {
	PolicyIds []string `arg:"" name:"id" help:"list of policy ids to enable"` //nolint:revive
}

func (c *Cmd) Run(k *kong.Kong, ctx *internalclient.Context) error {
	if len(c.Policy.PolicyIds) == 0 {
		return fmt.Errorf("no policy id(s) provided")
	}

	enabledPolicies, err := cerbos.BatchAdminClientCall(context.Background(), ctx.AdminClient.EnablePolicy, c.Policy.PolicyIds...)
	if err != nil {
		return fmt.Errorf("failed to enable policies: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Number of policies enabled is %d", enabledPolicies)
	return nil
}

func (pc *PolicyCmd) Help() string {
	return policyCmdHelp
}
