// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package sqlite_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
)

func TestSQLite(t *testing.T) {
	e2e.RunSuites(t, e2e.WithContextID("sqlite"), e2e.WithMutableStoreSuites())
}
