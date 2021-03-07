package storage

import (
	"context"
	"errors"
	"fmt"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/storage/disk"
	"github.com/charithe/menshen/pkg/storage/git"
)

// Store is the common interface implemented by storage backends.
type Store interface {
	Driver() string
}

// WritableStore is a store that supports modifications.
type WritableStore interface {
	Store
	AddOrUpdate(context.Context, *policyv1.Policy) error
	Remove(context.Context, *policyv1.Policy) error
}

// Reloader is an interface implemented by stores that support reloading.
type Reloader interface {
	Reload(context.Context) error
}

// New creates a new store based on the config.
func New(ctx context.Context, registry policy.Registry) (Store, error) {
	conf, err := getStorageConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read storage config: %w", err)
	}

	switch conf.Driver {
	case disk.DriverName:
		if conf.Disk == nil {
			return nil, errors.New("disk storage configuration not provided")
		}

		return newDiskStore(ctx, registry, conf.Disk)

	case git.DriverName:
		if conf.Git == nil {
			return nil, errors.New("git storage configuration not provided")
		}

		return git.NewStore(ctx, registry, conf.Git)
	default:
		return nil, fmt.Errorf("unknown storage driver: %s", conf.Driver)
	}
}

func newDiskStore(ctx context.Context, registry policy.Registry, conf *disk.Conf) (Store, error) {
	if conf.ReadOnly {
		return disk.NewReadOnlyStore(ctx, registry, conf.Directory)
	}

	return disk.NewReadWriteStore(ctx, registry, conf.Directory)
}
