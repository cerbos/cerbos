// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/singleflight"
)

var (
	sfGroup  singleflight.Group
	reloadMu sync.Mutex
)

// Reload triggers a reload of the given store. Reloads never run concurrently and each
// caller is served by a reload that started after its call.
// Callers arriving while a reload is in flight join a single follow-up reload
// instead of joining the in-flight one, whose snapshot of the storage may
// predate their changes.
func Reload(ctx context.Context, rs Reloadable) error {
	_, err, _ := sfGroup.Do("admin_reload", func() (any, error) {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		// Forgetting the key only after acquiring the lock makes callers that arrive
		// mid-reload share the next flight, which blocks here until this one finishes.
		sfGroup.Forget("admin_reload")

		if err := rs.Reload(ctx); err != nil {
			return nil, fmt.Errorf("failed to reload the store: %w", err)
		}
		return nil, nil
	})

	return err
}
