package disk

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/google/renameio"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/namer"
	"github.com/charithe/menshen/pkg/policy"
)

const (
	resourcePoliciesDir  = "resource_policies"
	principalPoliciesDir = "principal_policies"
	derivedRolesDir      = "derived_roles"
)

type ReadWriteStore struct {
	log       *zap.SugaredLogger
	registry  policy.Registry
	policyDir string
	index     FileIndex
}

func NewReadWriteStore(ctx context.Context, registry policy.Registry, policyDir string) (*ReadWriteStore, error) {
	if err := checkValidDir(policyDir); err != nil {
		return nil, err
	}

	log := zap.S().Named("disk.store.rw").With("root", policyDir)

	idx, err := LoadPoliciesFromDir(ctx, registry, policyDir, log)
	if err != nil && !errors.Is(err, policy.ErrEmptyTransaction) {
		return nil, err
	}

	return &ReadWriteStore{log: log, registry: registry, policyDir: policyDir, index: idx}, nil
}

func (s *ReadWriteStore) Driver() string {
	return DriverName
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

	tx := s.registry.NewTransaction()
	if err := tx.Add(p); err != nil {
		return err
	}

	if err := s.registry.Update(ctx, tx); err != nil {
		return err
	}

	return f.CloseAtomicallyReplace()
}

func (s *ReadWriteStore) Remove(ctx context.Context, p *policyv1.Policy) error {
	tx := s.registry.NewTransaction()
	if err := tx.Remove(p); err != nil {
		return err
	}

	if err := s.registry.Update(ctx, tx); err != nil {
		return err
	}

	return os.Remove(s.fileNameForPolicy(p))
}

func (s *ReadWriteStore) fileNameForPolicy(p *policyv1.Policy) string {
	// if we have seen this module before, reuse the filename from that module.
	if prev, ok := s.index.Get(namer.ModuleName(p)); ok {
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
