// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"

	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

// The interface is defined here because placing in storage causes a circular dependency,
// probably because it blurs the lines by implementing `SourceStore` whilst having a dependency on
// `schema` in order to build the compile manager in the GetOverlayPolicyLoader method.
type Overlay interface {
	storage.SourceStore
	// GetOverlayPolicyLoader returns a PolicyLoader implementation that wraps two SourceStores
	GetOverlayPolicyLoader(ctx context.Context, schemaMgr schema.Manager) (engine.PolicyLoader, error)
}
