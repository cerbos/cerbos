package disk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/google/renameio"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/namer"
	"github.com/charithe/menshen/pkg/policy"
)

type ReadWriteStore struct {
	*ReadOnlyStore
}

func NewReadWriteStore(ctx context.Context, policyDir string) (*ReadWriteStore, error) {
	ros, err := NewReadOnlyStore(ctx, policyDir)
	if err != nil {
		return nil, err
	}

	ros.log = zap.S().Named("disk.store.readwrite").With("root", policyDir)

	return &ReadWriteStore{ReadOnlyStore: ros}, nil
}

func (s *ReadWriteStore) AddOrUpdate(ctx context.Context, p *policyv1.Policy) error {
	filePath := s.fileNameForPolicy(p)

	f, err := renameio.TempFile("", filePath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	defer f.Cleanup()

	if _, err := policy.WritePolicy(f, p); err != nil {
		return err
	}

	tx := s.index.NewTxn()
	if err := tx.Add(p); err != nil {
		return err
	}

	if err := s.index.Commit(ctx, tx); err != nil {
		return err
	}

	return f.CloseAtomicallyReplace()
}

func (s *ReadWriteStore) Remove(ctx context.Context, p *policyv1.Policy) error {
	tx := s.index.NewTxn()
	if err := tx.Remove(p); err != nil {
		return err
	}

	if err := s.index.Commit(ctx, tx); err != nil {
		return err
	}

	return os.Remove(s.fileNameForPolicy(p))
}

func (s *ReadWriteStore) fileNameForPolicy(p *policyv1.Policy) string {
	modHash := hash(namer.ModuleName(p))

	// if we have seen this module before, reuse the filename from that module.
	if prev, ok := s.seen[modHash]; ok {
		return prev
	}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return filepath.Join(s.policyDir, resourcePoliciesDir, fmt.Sprintf("%s.%s.yaml", pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version))
	case *policyv1.Policy_PrincipalPolicy:
		return filepath.Join(s.policyDir, principalPoliciesDir, fmt.Sprintf("%s.%s.yaml", pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version))
	case *policyv1.Policy_DerivedRoles:
		return filepath.Join(s.policyDir, derivedRolesDir, fmt.Sprintf("%s.yaml", pt.DerivedRoles.Name))
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}
