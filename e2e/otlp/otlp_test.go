// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package otlp_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
)

func TestOTLP(t *testing.T) {
	e2e.RunSuites(t, e2e.WithContextID("otlp"), e2e.WithMutableStoreSuites())
}
