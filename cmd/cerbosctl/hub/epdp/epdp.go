// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package epdp

type Cmd struct { //betteralign:ignore
	ListCandidates ListCandidatesCmd `cmd:"" name:"list-candidates" aliases:"lc" help:"List candidates to be included in the ePDP bundle"`
}
