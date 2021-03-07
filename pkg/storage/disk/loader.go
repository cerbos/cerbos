package disk

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cespare/xxhash"
	"go.uber.org/zap"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/namer"
	"github.com/charithe/menshen/pkg/policy"
)

var supportedFileTypes = map[string]struct{}{".yaml": {}, ".yml": {}, ".json": {}}

type FileIndex map[uint64]string

func (fi FileIndex) Get(moduleName string) (string, bool) {
	v, ok := fi[fi.hash(moduleName)]
	return v, ok
}

func (fi FileIndex) Add(moduleName string, filePath string) {
	fi[fi.hash(moduleName)] = filePath
}

func (fi FileIndex) hash(v string) uint64 {
	return xxhash.Sum64String(v)
}

func LoadPoliciesFromDir(ctx context.Context, registry policy.Registry, dir string, log *zap.SugaredLogger) (FileIndex, error) {
	idx := make(FileIndex)
	tx := registry.NewTransaction()

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

		log.Debugw("Attempting to load policy", "path", path)
		p, _, err := loadPolicy(path)
		if err != nil {
			log.Errorw("Failed to load policy", "path", path, "error", err)
			return err
		}

		if p.Disabled {
			log.Debugw("Skipping policy as it is disabled", "path", path)
			return nil
		}

		modName := namer.ModuleName(p)

		if prev, clashes := idx.Get(modName); clashes {
			log.Errorf("Policy at %s conflicts with policy at %s", path, prev)
			return fmt.Errorf("policy at %s conflicts with policy at %s", path, prev)
		}

		idx.Add(modName, path)

		return tx.Add(p)
	})

	if err != nil {
		return nil, err
	}

	return idx, registry.Update(ctx, tx)
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
