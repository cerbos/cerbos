// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import "github.com/cerbos/cerbos/cmd/cerbosctl/hub/epdp"

type Cmd struct {
	EmbeddedPDP epdp.Cmd `cmd:"" name:"embedded_pdp" aliases:"epdp"`
}
