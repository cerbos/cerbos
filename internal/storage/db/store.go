// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

var ErrNoResults = errors.New("no results")

type Store interface {
	AddOrUpdate(context.Context, ...policy.Wrapper) error
	Delete(context.Context, ...namer.ModuleID) error
	GetCompilationUnits(context.Context, ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetPolicies(context.Context, storage.PolicyFilter) ([]*policy.Wrapper, error)
}
