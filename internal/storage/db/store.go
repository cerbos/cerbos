// Copyright 2021 Zenauth Ltd.

package db

import (
	"context"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

type Store interface {
	AddOrUpdate(context.Context, ...policy.Wrapper) error
	Delete(context.Context, ...namer.ModuleID) error
	GetPolicyUnit(context.Context, namer.ModuleID) (*policy.Unit, error)
}
