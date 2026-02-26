// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package namer

import (
	"database/sql"
	"fmt"
)

func (m *ModuleID) Scan(src any) error {
	switch v := src.(type) {
	case uint64:
		m.hash = v
		return nil
	case int64:
		m.hash = uint64(v)
		return nil
	default:
		// hack to work around unpredictable behaviour from the MySQL driver (it's a feature, not a bug).
		// https://github.com/go-sql-driver/mysql/issues/861
		val := sql.NullInt64{}
		if err := val.Scan(src); err == nil {
			m.hash = uint64(val.Int64)
			return nil
		}

		return fmt.Errorf("unexpected type for module ID: %T", src)
	}
}
