// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"github.com/cerbos/cerbos/cmd/cerbosctl/hub/epdp"
	"github.com/cerbos/cerbos/cmd/cerbosctl/hub/store"
)

type Cmd struct {
	EmbeddedPDP epdp.Cmd  `cmd:"" name:"embedded_pdp" aliases:"epdp"`
	Store       store.Cmd `cmd:"" name:"store"`
}
