// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package epdp

import "github.com/cerbos/cerbos/cmd/cerbosctl/hub/epdp/list"

type Cmd struct {
	List list.Cmd `cmd:"" name:"list-candidates" aliases:"lc" help:"List candidates to be included in the ePDP bundle"`
}
