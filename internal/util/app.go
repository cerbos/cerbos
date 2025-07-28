// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package util

import (
	"go.uber.org/zap"
)

func DeprecationWarning(deprecated string) {
	zap.S().Warnf("[DEPRECATED CONFIG] %s is deprecated and will be removed in a future release.", deprecated)
}

func DeprecationReplacedWarning(deprecated, replacement string) {
	zap.S().Warnf("[DEPRECATED CONFIG] %s is deprecated and will be removed in a future release. Please use %s instead.", deprecated, replacement)
}
