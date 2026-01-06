// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/alecthomas/kong"
)

func main() {
	var cli struct {
		Combine combineCmd `cmd:""`
		Split   splitCmd   `cmd:""`
	}

	ctx := kong.Parse(&cli)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
