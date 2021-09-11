// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"go.uber.org/zap"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
	"github.com/cerbos/cerbos/internal/util"
)

const DriverName = "git"

var _ storage.Store = (*Store)(nil)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context) (storage.Store, error) {
		conf := &Conf{}
		if err := config.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

type Store struct {
	log  *zap.SugaredLogger
	conf *Conf
	idx  index.Index
	repo *git.Repository
	*storage.SubscriptionManager
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	s := &Store{
		log:                 zap.S().Named("git.store").With("dir", conf.CheckoutDir),
		conf:                conf,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}

	if err := s.init(ctx); err != nil {
		s.log.Errorw("Failed to initialize git store", "error", err)
		return nil, err
	}

	return s, nil
}

func (s *Store) init(ctx context.Context) error {
	finfo, err := os.Stat(s.conf.CheckoutDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat %s: %w", s.conf.CheckoutDir, err)
	} else if finfo != nil && !finfo.IsDir() {
		return fmt.Errorf("not a directory: %s", s.conf.CheckoutDir)
	}

	loadAndStartPoller := func() error {
		if err := s.loadAll(ctx); err != nil {
			return err
		}

		go s.pollForUpdates(ctx)

		return nil
	}

	// if the directory does not exist, create it and clone the repo
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(s.conf.CheckoutDir, 0o744); err != nil { //nolint:gomnd
			return fmt.Errorf("failed to create directory %s: %w", s.conf.CheckoutDir, err)
		}

		if err := s.cloneRepo(ctx); err != nil {
			return err
		}

		return loadAndStartPoller()
	}

	// check whether the directory is empty
	empty, err := isEmptyDir(s.conf.CheckoutDir)
	if err != nil {
		return err
	}

	// if empty, clone the repo
	if empty {
		if err := s.cloneRepo(ctx); err != nil {
			return err
		}

		return loadAndStartPoller()
	}

	// if not empty, assume it is a git repo and try to pull the latest changes
	if _, err := s.pullAndCompare(ctx); err != nil {
		return err
	}

	return loadAndStartPoller()
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetCompilationUnits(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.idx.GetCompilationUnits(ids...)
}

func (s *Store) GetDependents(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.idx.GetDependents(ids...)
}

func (s *Store) GetPolicies(ctx context.Context) ([]*policy.Wrapper, error) {
	return s.idx.GetPolicies(ctx)
}

func isEmptyDir(dir string) (bool, error) {
	d, err := os.Open(dir)
	if err != nil {
		return false, fmt.Errorf("failed to open directory %s: %w", dir, err)
	}

	defer d.Close()

	_, err = d.ReadDir(1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return true, nil
		}

		return false, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	return false, nil
}

func (s *Store) cloneRepo(ctx context.Context) error {
	auth, err := s.conf.getAuth()
	if err != nil {
		return fmt.Errorf("failed to create git auth credentials: %w", err)
	}

	opts := &git.CloneOptions{
		URL:           s.conf.URL,
		Auth:          auth,
		ReferenceName: plumbing.NewBranchReferenceName(s.conf.getBranch()),
		SingleBranch:  true,
	}

	s.log.Infof("Cloning git repo from %s", s.conf.URL)

	ctx, cancelFunc := s.conf.getOpCtx(ctx)
	defer cancelFunc()

	if _, err := git.PlainCloneContext(ctx, s.conf.CheckoutDir, false, opts); err != nil {
		return fmt.Errorf("failed to clone from %s to %s: %w", s.conf.URL, s.conf.CheckoutDir, err)
	}

	return s.openRepo()
}

func (s *Store) loadAll(ctx context.Context) error {
	policyDir := "."
	if s.conf.SubDir != "" {
		policyDir = s.conf.SubDir
	}

	idx, err := index.Build(ctx, os.DirFS(s.conf.CheckoutDir), index.WithRootDir(policyDir), index.WithDiskCache(s.conf.ScratchDir))
	if err != nil {
		return err
	}

	s.idx = idx

	return nil
}

func (s *Store) pullAndCompare(ctx context.Context) (object.Changes, error) {
	// open the repo if it's not already open.
	if s.repo == nil {
		if err := s.openRepo(); err != nil {
			return nil, err
		}
	}

	// Make sure we are in the correct branch and get the current HEAD
	headHash, err := s.ensureCorrectBranch()
	if err != nil {
		return nil, err
	}

	wt, err := s.repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to get work tree: %w", err)
	}

	branch := s.conf.getBranch()

	s.log.Debugw("Pulling from remote", "branch", branch)
	auth, err := s.conf.getAuth()
	if err != nil {
		return nil, fmt.Errorf("failed to create git auth credentials: %w", err)
	}

	// Now pull from remote
	opts := &git.PullOptions{
		Auth: auth,
	}

	ctx, cancelFunc := s.conf.getOpCtx(ctx)
	defer cancelFunc()

	if err := wt.PullContext(ctx, opts); err != nil {
		if !errors.Is(err, git.NoErrAlreadyUpToDate) {
			s.log.Errorw("Failed to pull from remote", "error", err)
			return nil, fmt.Errorf("failed to pull from remote: %w", err)
		}

		// branch is already up-to-date: nothing to do.
		return nil, nil
	}

	// compare the head with the prev state.
	return s.compareWithHEAD(ctx, headHash)
}

func (s *Store) openRepo() error {
	s.log.Info("Opening git repo")
	repo, err := git.PlainOpen(s.conf.CheckoutDir)
	if err != nil {
		return fmt.Errorf("failed to open git repo at %s: %w", s.conf.CheckoutDir, err)
	}

	s.repo = repo

	return nil
}

func (s *Store) ensureCorrectBranch() (plumbing.Hash, error) {
	currHead, err := s.repo.Head()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to get repo HEAD: %w", err)
	}

	currBranch := currHead.Name().Short()
	s.log.Debugf("Current HEAD: %s", currHead)

	branch := s.conf.getBranch()

	if currBranch != branch {
		s.log.Debugf("Attempting to checkout %s", branch)

		wt, err := s.repo.Worktree()
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("failed to get work tree: %w", err)
		}

		opts := &git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(branch)}
		if err := wt.Checkout(opts); err != nil {
			return plumbing.ZeroHash, fmt.Errorf("failed to checkout branch %s: %w", branch, err)
		}

		currHead, err = s.repo.Head()
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("failed to get repo HEAD: %w", err)
		}
	}

	return currHead.Hash(), nil
}

func (s *Store) compareWithHEAD(ctx context.Context, prevHash plumbing.Hash) (object.Changes, error) {
	currHead, err := s.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get repo HEAD: %w", err)
	}

	currHash := currHead.Hash()

	currTree, err := s.getTreeForHash(currHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for hash %s: %w", currHash, err)
	}

	prevTree, err := s.getTreeForHash(prevHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for hash %s: %w", prevHash, err)
	}

	s.log.Debugf("Comparing commits %s...%s", prevHash, currHash)

	ctx, cancelFunc := s.conf.getOpCtx(ctx)
	defer cancelFunc()

	return prevTree.DiffContext(ctx, currTree)
}

func (s *Store) getTreeForHash(hash plumbing.Hash) (*object.Tree, error) {
	commit, err := s.repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit for hash %s: %w", hash, err)
	}

	return commit.Tree()
}

func (s *Store) updateIndex(ctx context.Context) error {
	s.log.Debug("Checking for new commits")

	changes, err := s.pullAndCompare(ctx)
	if err != nil {
		return err
	}

	if changes == nil {
		s.log.Debug("No new commits")
		return nil
	}

	s.log.Infow("Detected repository changes")

	for _, c := range changes {
		s.log.Debugw("Processing change", "change", c)
		switch {
		case c.From.Name == "" && s.inPolicyDir(c.To.Name): // File created
			if err := s.applyIndexUpdate(c.To, storage.EventAddOrUpdatePolicy); err != nil {
				return err
			}
		case c.To.Name == "" && s.inPolicyDir(c.From.Name): // File deleted
			if err := s.applyIndexUpdate(c.From, storage.EventDeletePolicy); err != nil {
				return err
			}
		case s.inPolicyDir(c.From.Name) && !s.inPolicyDir(c.To.Name): // File moved out of policy dir
			if err := s.applyIndexUpdate(c.From, storage.EventDeletePolicy); err != nil {
				return err
			}
		case s.inPolicyDir(c.To.Name): // file moved in or modified
			if err := s.applyIndexUpdate(c.To, storage.EventAddOrUpdatePolicy); err != nil {
				return err
			}
		default:
			s.log.Debugw("Ignoring change", "change", c)
		}
	}

	s.log.Info("Index updated")
	return nil
}

func (s *Store) applyIndexUpdate(ce object.ChangeEntry, eventKind storage.EventKind) error {
	if !util.IsSupportedFileType(ce.Name) {
		s.log.Infow("Ignoring unsupported file type", "path", ce.Name)
		return nil
	}

	idxFn := s.idx.Delete
	entry := index.Entry{File: ce.Name}

	if eventKind == storage.EventAddOrUpdatePolicy {
		s.log.Debugw("Reading policy", "path", ce.Name)
		p, err := s.readPolicyFromBlob(ce.TreeEntry.Hash)
		if err != nil {
			s.log.Errorw("Failed to read policy", "path", ce.Name, "error", err)
			return err
		}

		idxFn = s.idx.AddOrUpdate
		entry.Policy = policy.Wrap(p)
	}

	evt, err := idxFn(entry)
	if err != nil {
		return err
	}

	s.NotifySubscribers(evt)
	return nil
}

func (s *Store) inPolicyDir(filePath string) bool {
	if s.conf.SubDir == "" {
		return true
	}

	rel, err := filepath.Rel(s.conf.SubDir, filePath)
	if err != nil {
		s.log.Warnf("Failed to find the path of %s relative to %s: file will be ignored", filePath, s.conf.SubDir)
	}

	// if there are no double dots, the file is inside the policy dir.
	return !strings.Contains(rel, "..")
}

func (s *Store) readPolicyFromBlob(hash plumbing.Hash) (*policyv1.Policy, error) {
	blob, err := s.repo.BlobObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob for %s: %w", hash, err)
	}

	reader, err := blob.Reader()
	if err != nil {
		return nil, fmt.Errorf("failed to get reader for blob %s: %w", hash, err)
	}

	defer reader.Close()

	p, err := policy.ReadPolicy(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy from blob %s: %w", hash, err)
	}

	return p, nil
}

func (s *Store) pollForUpdates(ctx context.Context) {
	if s.conf.UpdatePollInterval <= 0 {
		s.log.Info("Polling disabled: new updates will not be pulled automatically")
		return
	}

	s.log.Infof("Polling for updates every %s", s.conf.UpdatePollInterval)

	ticker := time.NewTicker(s.conf.UpdatePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Stopped polling for updates")
			return
		case <-ticker.C:
			if err := s.updateIndex(ctx); err != nil {
				s.log.Errorw("Failed to check for updates", "error", err)
			}
		}
	}
}
