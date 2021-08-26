// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	namePrefix = "git"
	policyDir  = "policies"
	ignoredDir = "ignore"
)

// TODO (cell) Test HTTPS and SSH auth

func TestNewStore(t *testing.T) {
	tempDir := t.TempDir()
	sourceGitDir := filepath.Join(tempDir, "source")

	wantFiles := createGitRepo(t, sourceGitDir, 20)

	// the checkout directory does not exist so the remote repo will be cloned.
	t.Run("directory does not exist", func(t *testing.T) {
		checkoutDir := filepath.Join(t.TempDir(), "clone")
		conf := mkConf(t, sourceGitDir, checkoutDir)

		store, err := NewStore(context.Background(), conf)
		require.NoError(t, err)

		requireIndexContains(t, store, wantFiles)
	})

	// the checkout directory is empty so the remote repo will be cloned.
	t.Run("directory is empty", func(t *testing.T) {
		checkoutDir := t.TempDir()
		conf := mkConf(t, sourceGitDir, checkoutDir)

		store, err := NewStore(context.Background(), conf)
		require.NoError(t, err)

		requireIndexContains(t, store, wantFiles)
	})

	// the checkout directory already contains the git repo but checked out to the wrong branch.
	t.Run("directory is valid git repo", func(t *testing.T) {
		checkoutDir := t.TempDir()

		// checkout the master branch of the source git repo
		_, err := git.PlainClone(checkoutDir, false, &git.CloneOptions{
			URL: fmt.Sprintf("file://%s", sourceGitDir),
		})
		require.NoError(t, err, "Failed to clone repo")

		conf := mkConf(t, sourceGitDir, checkoutDir)

		store, err := NewStore(context.Background(), conf)
		require.NoError(t, err)

		requireIndexContains(t, store, wantFiles)
	})

	// the checkout directory is not empty and not a valid git repo.
	t.Run("directory is not empty", func(t *testing.T) {
		checkoutDir := t.TempDir()

		for i := 0; i < 10; i++ {
			file := filepath.Join(checkoutDir, fmt.Sprintf("file_%02d.txt", i))
			require.NoError(t, os.WriteFile(file, []byte("some data"), 0o600))
		}

		conf := mkConf(t, sourceGitDir, checkoutDir)

		store, err := NewStore(context.Background(), conf)
		require.Nil(t, store)
		require.ErrorIs(t, err, git.ErrRepositoryNotExists)
	})
}

func TestUpdateStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping git store tests")
	}

	tempDir := t.TempDir()
	sourceGitDir := filepath.Join(tempDir, "source")
	checkoutDir := filepath.Join(tempDir, "checkout")

	rng := rand.New(rand.NewSource(time.Now().Unix())) //nolint:gosec
	numPolicySets := 20
	deletedFilesetNumber := 0

	_ = createGitRepo(t, sourceGitDir, numPolicySets)

	conf := mkConf(t, sourceGitDir, checkoutDir)
	store, err := NewStore(context.Background(), conf)
	require.NoError(t, err)

	idx := store.idx

	setupMock := func() *mocks.Index {
		m := &mocks.Index{}
		store.idx = m
		return m
	}

	t.Run("no changes", func(t *testing.T) {
		mockIdx := setupMock()
		checkEvents := storage.TestSubscription(store)

		require.NoError(t, store.updateIndex(context.Background()))
		mockIdx.AssertExpectations(t)
		checkEvents(t)
	})

	t.Run("modify policy", func(t *testing.T) {
		mockIdx := setupMock()
		mockIdx.On("AddOrUpdate", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := idx.AddOrUpdate(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(store)
		pset := genPolicySet(rng.Intn(numPolicySets))

		require.NoError(t, commitToGitRepo(sourceGitDir, "Modify policy", func(wt *git.Worktree) error {
			for _, p := range pset {
				modifyPolicy(p)
			}

			return writePolicySet(filepath.Join(sourceGitDir, policyDir), pset)
		}))

		require.NoError(t, store.updateIndex(context.Background()))
		mockIdx.AssertExpectations(t)
		mockIdx.AssertNumberOfCalls(t, "AddOrUpdate", len(pset))

		wantEvents := make([]storage.Event, 0, len(pset))
		for _, p := range pset {
			wantEvents = append(wantEvents, storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: namer.GenModuleID(p)})
		}

		checkEvents(t, wantEvents...)
	})

	t.Run("add policy", func(t *testing.T) {
		mockIdx := setupMock()
		mockIdx.On("AddOrUpdate", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := idx.AddOrUpdate(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(store)
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Add policy", func(wt *git.Worktree) error {
			if err := writePolicySet(filepath.Join(sourceGitDir, policyDir), pset); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, store.updateIndex(context.Background()))

		mockIdx.AssertExpectations(t)
		mockIdx.AssertNumberOfCalls(t, "AddOrUpdate", len(pset))

		wantEvents := make([]storage.Event, 0, len(pset))
		for _, p := range pset {
			wantEvents = append(wantEvents, storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: namer.GenModuleID(p)})
		}

		checkEvents(t, wantEvents...)
	})

	t.Run("add policy to ignored dir", func(t *testing.T) {
		mockIdx := setupMock()
		checkEvents := storage.TestSubscription(store)
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Add ignored policy", func(wt *git.Worktree) error {
			if err := writePolicySet(filepath.Join(sourceGitDir, ignoredDir), pset); err != nil {
				return err
			}

			for f := range pset {
				if _, err := wt.Add(filepath.Join(ignoredDir, f)); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateIndex(context.Background()))
		mockIdx.AssertExpectations(t)
		mockIdx.AssertNotCalled(t, "AddOrUpdate", mock.MatchedBy(anyIndexEntry))
		checkEvents(t)
	})

	t.Run("delete policy", func(t *testing.T) {
		mockIdx := setupMock()
		mockIdx.On("Delete", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := idx.Delete(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(store)
		deletedFilesetNumber = rng.Intn(numPolicySets)
		pset := genPolicySet(deletedFilesetNumber)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Delete policy", func(wt *git.Worktree) error {
			for file := range pset {
				fp := filepath.Join(policyDir, file)
				if err := os.Remove(filepath.Join(sourceGitDir, fp)); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateIndex(context.Background()))
		mockIdx.AssertExpectations(t)
		mockIdx.AssertNumberOfCalls(t, "Delete", len(pset))

		wantEvents := make([]storage.Event, 0, len(pset))
		for _, p := range pset {
			wantEvents = append(wantEvents, storage.Event{Kind: storage.EventDeletePolicy, PolicyID: namer.GenModuleID(p)})
		}

		checkEvents(t, wantEvents...)
	})

	t.Run("move policy out of policy dir", func(t *testing.T) {
		mockIdx := setupMock()
		mockIdx.On("Delete", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := idx.Delete(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(store)
		moveFilesetNumber := rng.Intn(numPolicySets)
		for {
			if moveFilesetNumber != deletedFilesetNumber {
				break
			}
			moveFilesetNumber = rng.Intn(numPolicySets)
		}
		pset := genPolicySet(moveFilesetNumber)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Move policy out", func(wt *git.Worktree) error {
			for file := range pset {
				from := filepath.Join(sourceGitDir, filepath.Join(policyDir, file))
				to := filepath.Join(sourceGitDir, filepath.Join(ignoredDir, file))
				if err := os.Rename(from, to); err != nil {
					return err
				}
			}
			return nil
		}))

		require.NoError(t, store.updateIndex(context.Background()))
		mockIdx.AssertExpectations(t)
		mockIdx.AssertNumberOfCalls(t, "Delete", len(pset))

		wantEvents := make([]storage.Event, 0, len(pset))
		for _, p := range pset {
			wantEvents = append(wantEvents, storage.Event{Kind: storage.EventDeletePolicy, PolicyID: namer.GenModuleID(p)})
		}

		checkEvents(t, wantEvents...)
	})

	t.Run("ignore unsupported file", func(t *testing.T) {
		mockIdx := setupMock()
		checkEvents := storage.TestSubscription(store)
		require.NoError(t, commitToGitRepo(sourceGitDir, "Add unsupported file", func(wt *git.Worktree) error {
			fp := filepath.Join(sourceGitDir, policyDir, "file1.txt")
			if err := os.WriteFile(fp, []byte("something"), 0o600); err != nil {
				return err
			}

			_, err := wt.Add(filepath.Join(policyDir, "file1.txt"))

			return err
		}))

		require.NoError(t, store.updateIndex(context.Background()))
		mockIdx.AssertExpectations(t)
		mockIdx.AssertNotCalled(t, "Delete", mock.MatchedBy(anyIndexEntry))
		checkEvents(t)
	})
}

func anyIndexEntry(_ index.Entry) bool { return true }

func requireIndexContains(t *testing.T, store *Store, wantFiles []string) {
	t.Helper()

	haveFiles := store.idx.GetFiles()
	require.ElementsMatch(t, wantFiles, haveFiles)
}

func mkConf(t *testing.T, gitRepo, checkoutDir string) *Conf {
	t.Helper()

	return &Conf{
		Protocol:    "file",
		URL:         fmt.Sprintf("file://%s", gitRepo),
		CheckoutDir: checkoutDir,
		Branch:      "policies",
		SubDir:      "policies",
		ScratchDir:  t.TempDir(),
	}
}

func createGitRepo(t *testing.T, dir string, policyCount int) []string {
	t.Helper()

	fullPolicyDir := filepath.Join(dir, policyDir)
	require.NoError(t, os.MkdirAll(fullPolicyDir, 0o744), "Failed to create policy dir %s", fullPolicyDir)

	fullIgnoredDir := filepath.Join(dir, ignoredDir)
	require.NoError(t, os.MkdirAll(fullIgnoredDir, 0o744), "Failed to create ignored dir %s", fullIgnoredDir)

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err, "Failed to init Git repo")

	wt, err := repo.Worktree()
	require.NoError(t, err, "Failed to get worktree")

	_, err = wt.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Daffy Duck",
			Email: "daffy@mallard.dev",
			When:  time.Now(),
		},
	})
	require.NoError(t, err, "Failed to do initial commit")

	head, err := repo.Head()
	require.NoError(t, err, "Failed to get head")

	err = wt.Checkout(&git.CheckoutOptions{
		Hash:   head.Hash(),
		Branch: plumbing.NewBranchReferenceName("policies"),
		Create: true,
	})
	require.NoError(t, err, "Failed to checkout branch")

	var allFiles []string

	// write policies
	for i := 0; i < policyCount; i++ {
		pset := genPolicySet(i)

		require.NoError(t, writePolicySet(fullPolicyDir, pset), "Failed to write policies to policy dir")
		require.NoError(t, writePolicySet(fullIgnoredDir, pset), "Failed to write policies to ignored dir")

		for f := range pset {
			allFiles = append(allFiles, filepath.Join(policyDir, f))
		}
	}

	_, err = wt.Add(".")
	require.NoError(t, err, "Failed to add")

	_, err = wt.Commit("Add policies", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Daffy Duck",
			Email: "daffy@mallard.dev",
			When:  time.Now(),
		},
	})
	require.NoError(t, err, "Failed to commit")

	return allFiles
}

type policySet map[string]*policyv1.Policy

func genPolicySet(i int) policySet {
	suffix := fmt.Sprintf("%03d", i)

	policies := []*policyv1.Policy{
		test.GenResourcePolicy(test.PrefixAndSuffix(namePrefix, suffix)),
		test.GenPrincipalPolicy(test.PrefixAndSuffix(namePrefix, suffix)),
		test.GenDerivedRoles(test.PrefixAndSuffix(namePrefix, suffix)),
	}

	m := make(policySet, len(policies))
	for _, p := range policies {
		m[mkFileName(p)] = p
	}

	return m
}

func writePolicySet(dir string, pset policySet) error {
	for f, p := range pset {
		if err := writePolicy(filepath.Join(dir, f), p); err != nil {
			return err
		}
	}

	return nil
}

func writePolicy(path string, p *policyv1.Policy) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}

	defer f.Close()

	return policy.WritePolicy(f, p)
}

func mkFileName(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return fmt.Sprintf("%s.%s.yaml", pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
	case *policyv1.Policy_PrincipalPolicy:
		return fmt.Sprintf("%s.%s.yaml", pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
	case *policyv1.Policy_DerivedRoles:
		return fmt.Sprintf("%s.yaml", pt.DerivedRoles.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

func commitToGitRepo(dir, msg string, work func(*git.Worktree) error) error {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return fmt.Errorf("failed to open Git repo: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	if err := work(wt); err != nil {
		return fmt.Errorf("failed to do work: %w", err)
	}

	if _, err := wt.Commit(msg, &git.CommitOptions{
		All: true,
		Author: &object.Signature{
			Name:  "Daffy Duck",
			Email: "daffy@mallard.dev",
			When:  time.Now(),
		},
	}); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	return nil
}

func modifyPolicy(p *policyv1.Policy) *policyv1.Policy {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		pt.ResourcePolicy.Rules = append(pt.ResourcePolicy.Rules, &policyv1.ResourceRule{
			Actions: []string{"some_action"},
			Roles:   []string{"admin"},
			Effect:  effectv1.Effect_EFFECT_ALLOW,
		})

		return p
	case *policyv1.Policy_PrincipalPolicy:
		pt.PrincipalPolicy.Rules = append(pt.PrincipalPolicy.Rules, &policyv1.PrincipalRule{
			Resource: "some_resource",
			Actions: []*policyv1.PrincipalRule_Action{
				{
					Action: "*",
					Effect: effectv1.Effect_EFFECT_DENY,
				},
			},
		})

		return p
	case *policyv1.Policy_DerivedRoles:
		pt.DerivedRoles.Definitions = append(pt.DerivedRoles.Definitions, &policyv1.RoleDef{
			Name:        "some_role",
			ParentRoles: []string{"some_role", "another_role"},
		})

		return p
	default:
		return p
	}
}
