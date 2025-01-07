// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package logging

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func handleUSR1Signal(_ context.Context, _ zapcore.Level, _ *zap.AtomicLevel) {
	return
}
