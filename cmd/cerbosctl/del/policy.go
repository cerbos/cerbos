// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package del

import (
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/del/internal/policy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const policyCmdHelp = `# Delete policies

cerbosctl delete policies derived_roles.my_derived_roles

cerbosctl delete policy derived_roles.my_derived_roles

cerbosctl delete p derived_roles.my_derived_roles

# Delete multiple policies

cerbosctl delete policies derived_roles.my_derived_roles resource.leave_request.default

cerbosctl delete policy derived_roles.my_derived_roles resource.leave_request.default

cerbosctl delete p derived_roles.my_derived_roles resource.leave_request.default`

type PolicyCmd struct { //betteralign:ignore
	PolicyIds []string `arg:"" name:"id" help:"list of policy ids to delete"` //nolint:revive
}

func (c *PolicyCmd) Run(k *kong.Kong, ctx *client.Context) error {
	if len(c.PolicyIds) == 0 {
		return fmt.Errorf("no policy id(s) provided")
	}

	deletedPolicies, err := policy.Delete(ctx.AdminClient, c.PolicyIds...)
	if err != nil {
		return fmt.Errorf("failed to delete policies: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Number of policies deleted is %d", deletedPolicies)
	return nil
}

func (c *PolicyCmd) Help() string {
	return policyCmdHelp
}
