package disk

import (
	"context"
	"os"

	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/compile"
)

type ReadOnlyStore struct {
	index Index
}

func NewReadOnlyStore(ctx context.Context, policyDir string) (*ReadOnlyStore, error) {
	zap.S().Named("disk.store").Infow("Creating read-only disk store", "root", policyDir)
	idx, err := BuildIndex(ctx, os.DirFS(policyDir), ".")
	if err != nil {
		return nil, err
	}

	return &ReadOnlyStore{index: idx}, nil
}

func (s *ReadOnlyStore) Driver() string {
	return DriverName
}

func (s *ReadOnlyStore) GetAllPolicies(ctx context.Context) <-chan *compile.Unit {
	return s.index.GetAllPolicies(ctx)
}

func (s *ReadOnlyStore) SetNotificationChannel(chan<- *compile.Incremental) {
	// nothing to do because this is a read-only store
}
