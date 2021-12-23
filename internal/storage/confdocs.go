// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

// Conf is required configuration for storage.
type Conf struct{}

func (c *Conf) Key() string {
	return ConfKey
}
