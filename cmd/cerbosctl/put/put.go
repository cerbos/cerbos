// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

type Cmd struct { //betteralign:ignore
	Policy    PolicyCmd `cmd:"" aliases:"policies,p"`
	Schema    SchemaCmd `cmd:"" aliases:"schemas,s"`
	Recursive bool      `short:"R" help:"Process the directory used in -f, --filename recursively"`
}
