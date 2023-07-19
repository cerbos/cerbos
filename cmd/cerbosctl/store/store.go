// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"github.com/cerbos/cerbos/cmd/cerbosctl/store/export"
	"github.com/cerbos/cerbos/cmd/cerbosctl/store/reload"
)

type Cmd struct {
	Export export.Cmd `cmd:"" name:"export" aliases:"e"`
	Reload reload.Cmd `cmd:"" name:"reload" aliases:"r"`
}
