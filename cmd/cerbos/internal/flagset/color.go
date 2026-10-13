// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "github.com/cerbos/cerbos/internal/outputcolor"

type Color struct {
	Level   *outputcolor.Level `help:"Output color level (auto,never,always,256,16m). Defaults to auto." name:"color" xor:"color"`
	Disable bool               `help:"Disable colored output" name:"no-color" xor:"color"`
}
