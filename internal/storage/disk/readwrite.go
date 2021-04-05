package disk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/renameio"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/compile"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
)

type ReadWriteStore struct {
	policyDir  string
	index      Index
	mu         sync.RWMutex
	notifyChan chan<- *compile.Incremental
}

func NewReadWriteStore(ctx context.Context, policyDir string) (*ReadWriteStore, error) {
	zap.S().Named("disk.store").Infow("Creating disk store", "root", policyDir)

	idx, err := BuildIndex(ctx, os.DirFS(policyDir), ".")
	if err != nil {
		return nil, err
	}

	return &ReadWriteStore{policyDir: policyDir, index: idx}, nil
}

func (s *ReadWriteStore) Driver() string {
	return DriverName
}

func (s *ReadWriteStore) GetAllPolicies(ctx context.Context) <-chan *compile.Unit {
	return s.index.GetAllPolicies(ctx)
}

func (s *ReadWriteStore) SetNotificationChannel(channel chan<- *compile.Incremental) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.notifyChan = channel
}

func (s *ReadWriteStore) notify(ctx context.Context, change *compile.Incremental) error {
	s.mu.RLock()
	notifyChan := s.notifyChan //nolint:ifshort
	s.mu.RUnlock()

	if notifyChan != nil {
		select {
		case <-ctx.Done():
			return fmt.Errorf("failed to send notification: %w", ctx.Err())
		case notifyChan <- change:
		}
	}

	return nil
}

func (s *ReadWriteStore) AddOrUpdate(ctx context.Context, p *policyv1.Policy) error {
	if err := policy.Validate(p); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	fileName := s.fileNameForPolicy(p)

	f, err := renameio.TempFile("", filepath.Join(s.policyDir, fileName))
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	defer f.Cleanup() //nolint:errcheck

	if err := policy.WritePolicy(f, p); err != nil {
		return err
	}

	change, err := s.index.Add(fileName, p)
	if err != nil {
		return err
	}

	if err := f.CloseAtomicallyReplace(); err != nil {
		return err
	}

	return s.notify(ctx, change)
}

func (s *ReadWriteStore) Remove(ctx context.Context, p *policyv1.Policy) error {
	fileName := s.fileNameForPolicy(p)

	change, err := s.index.RemoveIfSafe(fileName)
	if err != nil {
		return err
	}

	if err := os.Remove(filepath.Join(s.policyDir, fileName)); err != nil {
		return err
	}

	return s.notify(ctx, change)
}

func (s *ReadWriteStore) fileNameForPolicy(p *policyv1.Policy) string {
	// if we have seen this module before, reuse the filename from that module.
	if prev := s.index.FilenameFor(p); prev != "" {
		return prev
	}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return fmt.Sprintf("resource_%s.%s.yaml", pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
	case *policyv1.Policy_PrincipalPolicy:
		return fmt.Sprintf("principal_%s.%s.yaml", pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
	case *policyv1.Policy_DerivedRoles:
		return fmt.Sprintf("derived_roles_%s.yaml", pt.DerivedRoles.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}
