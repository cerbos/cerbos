// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/derivedroles"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/exportvariables"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/principalpolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/resourcepolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/rolepolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/schema"
)

type Cmd struct {
	DerivedRoles    derivedroles.Cmd    `cmd:"" name:"derived_roles" aliases:"derived_role,dr"`
	ExportVariables exportvariables.Cmd `cmd:"" name:"export_variables" aliases:"ev"`
	PrincipalPolicy principalpolicy.Cmd `cmd:"" name:"principal_policies" aliases:"principal_policy,pp"`
	ResourcePolicy  resourcepolicy.Cmd  `cmd:"" name:"resource_policies" aliases:"resource_policy,rp"`
	RolePolicy      rolepolicy.Cmd      `cmd:"" name:"role_policies" aliases:"role_policy,rlp"`
	Schema          schema.Cmd          `cmd:"" name:"schemas" aliases:"schema,s"`
}
