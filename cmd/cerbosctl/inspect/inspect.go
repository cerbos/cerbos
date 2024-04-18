// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

type Cmd struct {
	Policies PoliciesCmd `cmd:"" name:"policies" aliases:"p" help:"Inspect policies in the store"`
}
