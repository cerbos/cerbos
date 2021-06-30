// Copyright 2021 Zenauth Ltd.

package janitor

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

var (
	mu           sync.Mutex
	cleanupFuncs []CleanupFunc
)

type CleanupFunc func(context.Context) error

// Register a cleanup function to be called later.
func Register(fn CleanupFunc) {
	mu.Lock()
	cleanupFuncs = append(cleanupFuncs, fn)
	mu.Unlock()
}

func Cleanup(ctx context.Context) {
	log := zap.L().Named("janitor")

	mu.Lock()

	for i := len(cleanupFuncs) - 1; i >= 0; i-- {
		fn := cleanupFuncs[i]
		if err := fn(ctx); err != nil {
			log.Warn("Error during cleanup", zap.Error(err))
		}
	}

	cleanupFuncs = nil

	mu.Unlock()
}
