// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package del

type Cmd struct { //betteralign:ignore
	Policy PolicyCmd `cmd:"" aliases:"policies,p"`
	Schema SchemaCmd `cmd:"" aliases:"schemas,s"`
}
