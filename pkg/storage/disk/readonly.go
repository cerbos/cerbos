package disk

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/cespare/xxhash"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/namer"
	"github.com/charithe/menshen/pkg/policy"
)

const (
	resourcePoliciesDir  = "resource_policies"
	principalPoliciesDir = "principal_policies"
	derivedRolesDir      = "derived_roles"
)

var (
	supportedFileTypes  = map[string]struct{}{".yaml": {}, ".yml": {}, ".json": {}}
	errNoCompiledPolicy = errors.New("no compiled policy")
)

type ReadOnlyStore struct {
	log       *zap.SugaredLogger
	index     *policy.Index
	policyDir string
	seen      map[uint64]string
}

func NewReadOnlyStore(ctx context.Context, policyDir string) (*ReadOnlyStore, error) {
	if err := checkValidDir(policyDir); err != nil {
		return nil, err
	}

	index := policy.NewIndex(ctx)
	log := zap.S().Named("disk.store.readonly").With("root", policyDir)

	ros := &ReadOnlyStore{policyDir: policyDir, index: index, log: log, seen: make(map[uint64]string)}

	return ros, ros.init(ctx)
}

func checkValidDir(dir string) error {
	finfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", dir, err)
	}

	if !finfo.IsDir() {
		return fmt.Errorf("not a directory: %s", dir)
	}

	return nil
}

func (s *ReadOnlyStore) init(ctx context.Context) error {
	s.log.Info("Loading policies")
	if err := s.loadPoliciesFromDir(ctx, s.policyDir); err != nil {
		s.log.Errorw("Failed to load policies", "error", err)
		return err
	}

	return nil
}

func (s *ReadOnlyStore) loadPoliciesFromDir(ctx context.Context, dir string) error {
	tx := s.index.NewTxn()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !isSupportedFile(d) {
			return nil
		}

		s.log.Debugf("Attempting to load policy from %s", path)
		p, _, err := loadPolicy(path)
		if err != nil {
			s.log.Errorw("Failed to load policy", "path", path, "error", err)
			return err
		}

		if p.Disabled {
			s.log.Debugf("Skipping %s as it is disabled", path)
			return nil
		}

		modName := namer.ModuleName(p)
		modHash := hash(modName)

		if prev, clashes := s.seen[modHash]; clashes {
			s.log.Errorf("Policy at %s conflicts with policy at %s", path, prev)
			return fmt.Errorf("policy at %s conflicts with policy at %s", path, prev)
		}

		s.seen[modHash] = path

		return tx.Add(p)
	})

	if err != nil {
		return err
	}

	return s.index.Commit(ctx, tx)
}

func isSupportedFile(d fs.DirEntry) bool {
	ext := strings.ToLower(filepath.Ext(d.Name()))
	_, exists := supportedFileTypes[ext]

	return exists
}

func loadPolicy(path string) (*policyv1.Policy, policy.Checksum, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	defer f.Close()

	return policy.ReadPolicy(f)
}

func hash(v string) uint64 {
	return xxhash.Sum64String(v)
}

// GetIndex returns the underlying index.
func (s *ReadOnlyStore) GetIndex() *policy.Index {
	return s.index
}
