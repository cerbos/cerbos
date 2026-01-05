// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
)

func main() {
	root.Run(os.Args[1:], os.Exit, os.Stdout, os.Stderr)
}
