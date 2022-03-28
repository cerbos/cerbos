// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

var sfGroup singleflight.Group

func Reload(ctx context.Context, log *zap.SugaredLogger, rs ReloadableStore) error {
	_, err, shared := sfGroup.Do("admin_reload", func() (interface{}, error) {
		if err := rs.Reload(ctx); err != nil {
			return nil, fmt.Errorf("failed to reload the store: %w", err)
		}
		return nil, nil
	})
	if err != nil {
		return err
	}
	if shared {
		log.Debug("shared multiple calls to the reload store API")
	}

	return nil
}
