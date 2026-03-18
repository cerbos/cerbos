// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	"github.com/cerbos/cerbos/internal/ruletable/index"
)

type (
	Binding        = index.Binding
	FunctionalCore = index.FunctionalCore
	Index          = index.Index
	RowParams      = index.RowParams
)

var New = index.New
