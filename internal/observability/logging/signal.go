// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package logging

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// handleUSR1Signal temporarily sets the log level to debug when a SIGUSR1 signal is received.
func handleUSR1Signal(ctx context.Context, originalLevel zapcore.Level, atomicLevel *zap.AtomicLevel) {
	sigusr1 := make(chan os.Signal, 1)
	signal.Notify(sigusr1, syscall.SIGUSR1)

	go func() {
		inProgress := false
		doneChan := make(chan struct{}, 1)
		extendChan := make(chan struct{}, 1)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigusr1:
				if inProgress {
					extendChan <- struct{}{}
				} else {
					inProgress = true
					go setLogLevelForDuration(ctx, doneChan, extendChan, originalLevel, atomicLevel)
				}
			case <-doneChan:
				inProgress = false
			}
		}
	}()
}
