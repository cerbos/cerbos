// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package notls_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
)

func TestNoTLS(t *testing.T) {
	e2e.RunSuites(t, e2e.WithContextID("notls"), e2e.WithImmutableStoreSuites(), e2e.WithTLSDisabled())
}
