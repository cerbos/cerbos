// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

type Cmd struct { //betteralign:ignore
	Policies PoliciesCmd `cmd:"" name:"policies" aliases:"p" help:"Inspect policies in the store"`
}
