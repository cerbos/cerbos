package disk

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/charithe/menshen/pkg/policy"
)

type ReadOnlyStore struct{}

func NewReadOnlyStore(ctx context.Context, registry policy.Registry, policyDir string) (*ReadOnlyStore, error) {
	if err := checkValidDir(policyDir); err != nil {
		return nil, err
	}

	log := zap.S().Named("disk.store.ro").With("root", policyDir)

	if _, err := LoadPoliciesFromDir(ctx, registry, policyDir, log); err != nil && !errors.Is(err, policy.ErrEmptyTransaction) {
		return nil, err
	}

	return &ReadOnlyStore{}, nil
}

func (s *ReadOnlyStore) Driver() string {
	return DriverName
}
