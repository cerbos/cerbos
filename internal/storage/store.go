// Copyright 2021 Zenauth Ltd.

package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/cerbos/cerbos/internal/compile"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/git"
)

// Store is the common interface implemented by storage backends.
type Store interface {
	Driver() string
	GetAllPolicies(context.Context) <-chan *compile.Unit
	SetNotificationChannel(chan<- compile.Notification)
}

// WritableStore is a store that supports modifications.
type WritableStore interface {
	Store
	AddOrUpdate(context.Context, *policyv1.Policy) error
	Remove(context.Context, *policyv1.Policy) error
}

// New creates a new store based on the config.
func New(ctx context.Context) (Store, error) {
	conf, err := getStorageConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read storage config: %w", err)
	}

	switch conf.Driver {
	case disk.DriverName:
		if conf.Disk == nil {
			return nil, errors.New("disk storage configuration not provided")
		}

		if conf.Disk.ReadOnly {
			return disk.NewReadOnlyStore(ctx, conf.Disk)
		}

		return disk.NewReadWriteStore(ctx, conf.Disk)
	case git.DriverName:
		if conf.Git == nil {
			return nil, errors.New("git storage configuration not provided")
		}

		return git.NewStore(ctx, conf.Git)
	default:
		return nil, fmt.Errorf("unknown storage driver: %s", conf.Driver)
	}
}
