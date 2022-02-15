// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package sqlserver_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
)

func TestSqlServer(t *testing.T) {
	e2e.RunSuites(t, e2e.WithContextID("sqlserver"), e2e.WithMutableStoreSuites())
}
