// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policyloader

import (
	"context"
	"time"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

type PolicyLoader interface {
	GetFirstMatch(context.Context, []namer.ModuleID) (*runtimev1.RunnablePolicySet, error)
	GetAll(context.Context) ([]*runtimev1.RunnablePolicySet, error)
	GetAllMatching(context.Context, []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error)
	GetCacheDuration() time.Duration
}
