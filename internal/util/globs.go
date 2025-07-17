// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package util

import (
	"go.uber.org/zap"
)

func logError(globExpr string, err error) {
	zap.L().Named("glob-cache").Warn("Invalid glob expression", zap.String("glob", globExpr), zap.Error(err))
}
