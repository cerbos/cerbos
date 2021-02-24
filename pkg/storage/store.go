package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/charithe/menshen/pkg/config"
	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/storage/disk"
)

// Store is the common interface implemented by storage backends.
type Store interface {
	GetIndex() *policy.Index
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
func New(ctx context.Context, conf config.StorageConf) (Store, error) {
	switch conf.Driver {
	case "disk":
		if conf.Disk == nil {
			return nil, errors.New("disk storage configuration not provided")
		}

		return newDiskStore(ctx, conf.Disk)
	default:
		return nil, fmt.Errorf("unknown storage driver: %s", conf.Driver)
	}
}

func newDiskStore(ctx context.Context, conf *config.DiskStorageConf) (Store, error) {
	if conf.ReadOnly {
		return disk.NewReadOnlyStore(ctx, conf.Directory)
	}

	return disk.NewReadWriteStore(ctx, conf.Directory)
}
