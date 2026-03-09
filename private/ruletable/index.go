// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	"github.com/cerbos/cerbos/internal/ruletable/index"
)

type (
	Binding = index.Binding
	Index   = index.Index
)

var New = index.New
