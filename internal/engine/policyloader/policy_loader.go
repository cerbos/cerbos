// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policyloader

import (
	"context"
	"iter"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

type PolicyLoader interface {
	GetFirstMatch(context.Context, []namer.ModuleID) (*runtimev1.RunnablePolicySet, error)
	GetAll(context.Context) ([]*runtimev1.RunnablePolicySet, error)
	GetAllMatching(context.Context, []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error)
	Source() *auditv1.PolicySource
}

// IterablePolicyLoader is an optional interface for loaders that can yield compiled
// policy sets one at a time.
type IterablePolicyLoader interface {
	Iter(ctx context.Context) iter.Seq2[*runtimev1.RunnablePolicySet, error]
}
