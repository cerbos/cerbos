// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/derivedroles"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/principalpolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/resourcepolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/schema"
)

type Cmd struct {
	DerivedRoles    derivedroles.Cmd    `cmd:"" name:"derived_roles" aliases:"derived_role,dr"`
	PrincipalPolicy principalpolicy.Cmd `cmd:"" name:"principal_policies" aliases:"principal_policy,pp"`
	ResourcePolicy  resourcepolicy.Cmd  `cmd:"" name:"resource_policies" aliases:"resource_policy,rp"`
	Schema          schema.Cmd          `cmd:""  name:"schemas" aliases:"schema,s"`
}
