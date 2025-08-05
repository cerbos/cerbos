// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package overlay

import (
	"context"

	"github.com/cerbos/cerbos/internal/engine/policyloader"
)

// The interface is defined here because placing in storage causes a circular dependency,
// probably because it blurs the lines by implementing `SourceStore` whilst having a dependency on
// `schema` in order to build the compile managers in the GetOverlayPolicyLoader method.
type Overlay interface {
	// GetOverlayPolicyLoader returns a PolicyLoader implementation that wraps two SourceStores
	GetOverlayPolicyLoader(ctx context.Context) (policyloader.PolicyLoader, error)
}
