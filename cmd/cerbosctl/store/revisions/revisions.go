// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package revisions

type Cmd struct {
	Purge PurgeCmd `cmd:"" name:"purge" aliases:"p"`
}
