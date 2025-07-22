// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage

import (
	"context"
	"fmt"

	"golang.org/x/sync/singleflight"
)

var sfGroup singleflight.Group

func Reload(ctx context.Context, rs Reloadable) error {
	_, err, _ := sfGroup.Do("admin_reload", func() (any, error) {
		if err := rs.Reload(ctx); err != nil {
			return nil, fmt.Errorf("failed to reload the store: %w", err)
		}
		return nil, nil
	})
	if err != nil {
		return err
	}

	return nil
}
