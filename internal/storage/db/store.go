// Copyright 2021 Zenauth Ltd.

package db

import (
	"context"
	"errors"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

var ErrNoResults = errors.New("no results")

type Store interface {
	AddOrUpdate(context.Context, ...policy.Wrapper) error
	Delete(context.Context, ...namer.ModuleID) error
	GetCompilationUnits(context.Context, ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
}
