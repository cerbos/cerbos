// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/storage/internal"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/test/mocks"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	namePrefix   = "git"
	policyDir    = "policies"
	ignoredDir   = "ignore"
	schemaSubDir = "subdir"
	timeout      = 1 * time.Second
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

		store, err := NewStore(t.Context(), conf)
		require.NoError(t, err)

		requireIndexContains(t, store, wantFiles)
	})

	// the checkout directory is empty so the remote repo will be cloned.
	t.Run("directory is empty", func(t *testing.T) {
		checkoutDir := t.TempDir()
		conf := mkConf(t, sourceGitDir, checkoutDir)

		store, err := NewStore(t.Context(), conf)
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

		store, err := NewStore(t.Context(), conf)
		require.NoError(t, err)

		requireIndexContains(t, store, wantFiles)
	})

	// the checkout directory is not empty and not a valid git repo.
	t.Run("directory is not empty", func(t *testing.T) {
		checkoutDir := t.TempDir()

		for i := range 10 {
			file := filepath.Join(checkoutDir, fmt.Sprintf("file_%02d.txt", i))
			require.NoError(t, os.WriteFile(file, []byte("some data"), 0o600))
		}

		conf := mkConf(t, sourceGitDir, checkoutDir)

		store, err := NewStore(t.Context(), conf)
		require.Nil(t, store)
		require.ErrorIs(t, err, git.ErrRepositoryNotExists)
	})
}

type testParams struct {
	store        *Store
	idx          index.Index
	mockIdx      *mocks.Index
	sourceGitDir string
}

func setupUpdateStoreTest(t *testing.T, numPolicySets int) testParams {
	t.Helper()

	tempDir := t.TempDir()
	sourceGitDir := filepath.Join(tempDir, "source")
	checkoutDir := filepath.Join(tempDir, "checkout")

	_ = createGitRepo(t, sourceGitDir, numPolicySets)

	conf := mkConf(t, sourceGitDir, checkoutDir)
	store, err := NewStore(t.Context(), conf)
	require.NoError(t, err)

	mockIdx := &mocks.Index{}
	idx := store.idx
	store.idx = mockIdx

	return testParams{
		store:        store,
		idx:          idx,
		mockIdx:      mockIdx,
		sourceGitDir: sourceGitDir,
	}
}

func TestUpdateStore(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping git store tests")
	}

	numPolicySets := 10

	t.Run("no changes", func(t *testing.T) {
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		checkEvents(t, timeout)
	})

	t.Run("modify policy", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("AddOrUpdate", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.AddOrUpdate(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(rand.Intn(numPolicySets)) //nolint:gosec

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Modify policy", func(_ *git.Worktree) error {
			for _, p := range pset {
				modifyPolicy(p)
			}

			return writePolicySet(filepath.Join(param.sourceGitDir, policyDir), pset)
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "AddOrUpdate", len(pset))

		wantEvents := buildRequiredEventsWithDependents(t, []storage.EventKind{storage.EventAddOrUpdatePolicy}, pset)

		checkEvents(t, timeout, wantEvents...)
	})

	t.Run("modify policy version", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("AddOrUpdate", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.AddOrUpdate(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(rand.Intn(numPolicySets)) //nolint:gosec

		wantEvents := make([]storage.Event, len(pset))
		psetEventIdx := make(map[string]int, len(pset))
		idx := 0
		for k, p := range pset {
			policyID := namer.GenModuleID(p)
			evt := storage.Event{Kind: storage.EventAddOrUpdatePolicy, OldPolicyID: &policyID}

			wantEvents[idx] = evt
			psetEventIdx[k] = idx
			idx++
		}

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Modify policy version", func(_ *git.Worktree) error {
			for _, p := range pset {
				modifyPolicyVersion(p)
			}

			return writePolicySet(filepath.Join(param.sourceGitDir, policyDir), pset)
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "AddOrUpdate", len(pset))

		for k, i := range psetEventIdx {
			wantEvents[i].PolicyID = namer.GenModuleID(pset[k])
		}

		checkEvents(t, timeout, wantEvents...)
	})

	t.Run("add policy", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("AddOrUpdate", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.AddOrUpdate(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Add policy", func(wt *git.Worktree) error {
			if err := writePolicySet(filepath.Join(param.sourceGitDir, policyDir), pset); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))

		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "AddOrUpdate", len(pset))

		wantEvents := buildRequiredEventsWithDependents(t, []storage.EventKind{storage.EventAddOrUpdatePolicy}, pset)

		checkEvents(t, timeout, wantEvents...)
	})

	t.Run("add policy to ignored dir", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Add ignored policy", func(wt *git.Worktree) error {
			if err := writePolicySet(filepath.Join(param.sourceGitDir, ignoredDir), pset); err != nil {
				return err
			}

			for f := range pset {
				if _, err := wt.Add(filepath.Join(ignoredDir, f)); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNotCalled(t, "AddOrUpdate", mock.MatchedBy(anyIndexEntry))
		checkEvents(t, timeout)
	})

	t.Run("delete policy", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("Delete", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.Delete(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(rand.Intn(numPolicySets)) //nolint:gosec

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Delete policy", func(wt *git.Worktree) error {
			for file := range pset {
				fp := filepath.Join(policyDir, file)
				if err := os.Remove(filepath.Join(param.sourceGitDir, fp)); err != nil {
					return err
				}

				if _, err := wt.Remove(fp); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "Delete", len(pset))

		// dependents are deleted first (by coincidence) because of the ordering of `pset`, therefore we don't use the `buildRequiredEvents` method
		// to attach `Dependents`
		wantEvents := make([]storage.Event, 0, len(pset))
		for _, p := range pset {
			wantEvents = append(wantEvents, storage.Event{Kind: storage.EventDeleteOrDisablePolicy, PolicyID: namer.GenModuleID(p)})
		}

		checkEvents(t, timeout, wantEvents...)
	})

	t.Run("delete dependencies", func(t *testing.T) {
		// This test is a bit of a hack. We rely on the existence of dependent policies (resource and principal policies)
		// in order to generate the expected `Dependents` in `buildRequiredEventsWithDependents`, but we need to remove
		// them from the actual delete events as we're trying to simulate JUST the removal of the dependencies.

		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("Delete", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.Delete(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(1) //nolint:gosec

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Delete policy", func(wt *git.Worktree) error {
			for file, p := range pset {
				switch p.PolicyType.(type) {
				case *policyv1.Policy_PrincipalPolicy, *policyv1.Policy_ResourcePolicy, *policyv1.Policy_RolePolicy:
					continue
				}

				fp := filepath.Join(policyDir, file)
				if err := os.Remove(filepath.Join(param.sourceGitDir, fp)); err != nil {
					return err
				}

				if _, err := wt.Remove(fp); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "Delete", 3)

		wantEvents := buildRequiredEventsWithDependents(t, []storage.EventKind{storage.EventDeleteOrDisablePolicy}, pset)

		// remove delete events for dependents. We need them in `buildRequiredEventsWithDependents` but only want to test
		// what happens when we delete the dependencies (dependents should be returned in the events)
		dependencyWantEvents := []storage.Event{}
		for _, ev := range wantEvents {
			if len(ev.Dependents) > 0 {
				dependencyWantEvents = append(dependencyWantEvents, ev)
			}
		}

		checkEvents(t, timeout, dependencyWantEvents...)
	})

	t.Run("rename policy", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("AddOrUpdate", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.AddOrUpdate(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		param.mockIdx.On("Delete", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.Delete(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(rand.Intn(numPolicySets)) //nolint:gosec

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Rename policy", func(wt *git.Worktree) error {
			for file := range pset {
				from := filepath.Join(param.sourceGitDir, filepath.Join(policyDir, file))
				to := filepath.Join(param.sourceGitDir, filepath.Join(policyDir, strings.Replace(file, ".yaml", ".renamed.yaml", 1)))
				if err := os.Rename(from, to); err != nil {
					return err
				}

				if _, err := wt.Remove(filepath.Join(policyDir, file)); err != nil {
					return err
				}
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "AddOrUpdate", len(pset))
		param.mockIdx.AssertNumberOfCalls(t, "Delete", len(pset))

		wantEvents := buildRequiredEventsWithDependents(t, []storage.EventKind{storage.EventDeleteOrDisablePolicy, storage.EventAddOrUpdatePolicy}, pset)

		checkEvents(t, timeout, wantEvents...)
	})

	t.Run("move policy out of policy dir", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		param.mockIdx.On("Delete", mock.MatchedBy(anyIndexEntry)).Return(func(entry index.Entry) storage.Event {
			evt, err := param.idx.Delete(entry)
			if err != nil {
				panic(err)
			}

			return evt
		}, nil)

		checkEvents := storage.TestSubscription(param.store)
		pset := genPolicySet(rand.Intn(numPolicySets)) //nolint:gosec

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Move policy out", func(wt *git.Worktree) error {
			for file := range pset {
				from := filepath.Join(param.sourceGitDir, filepath.Join(policyDir, file))
				to := filepath.Join(param.sourceGitDir, filepath.Join(ignoredDir, file))
				if err := os.Rename(from, to); err != nil {
					return err
				}

				if _, err := wt.Remove(filepath.Join(policyDir, file)); err != nil {
					return err
				}
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNumberOfCalls(t, "Delete", len(pset))

		wantEvents := make([]storage.Event, 0, len(pset))
		for _, p := range pset {
			wantEvents = append(wantEvents, storage.Event{Kind: storage.EventDeleteOrDisablePolicy, PolicyID: namer.GenModuleID(p)})
		}

		checkEvents(t, timeout, wantEvents...)
	})

	t.Run("ignore unsupported file", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)
		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Add unsupported file", func(wt *git.Worktree) error {
			fp := filepath.Join(param.sourceGitDir, policyDir, "file1.txt")
			if err := os.WriteFile(fp, []byte("something"), 0o600); err != nil {
				return err
			}

			_, err := wt.Add(filepath.Join(policyDir, "file1.txt"))

			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNotCalled(t, "Delete", mock.MatchedBy(anyIndexEntry))
		checkEvents(t, timeout)
	})

	t.Run("ignore test", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)
		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Add test", func(wt *git.Worktree) error {
			fp := filepath.Join(param.sourceGitDir, policyDir, "policy_test.yaml")
			if err := os.WriteFile(fp, []byte("name: Test suite\n"), 0o600); err != nil {
				return err
			}

			_, err := wt.Add(filepath.Join(policyDir, "policy_test.yaml"))

			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)
		param.mockIdx.AssertNotCalled(t, "Delete", mock.MatchedBy(anyIndexEntry))
		checkEvents(t, timeout)
	})

	t.Run("add schema", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Add schema", func(wt *git.Worktree) error {
			fp := filepath.Join(param.sourceGitDir, policyDir, schema.Directory, "test_policy1.json")
			if err := os.WriteFile(fp, []byte("{}"), 0o600); err != nil {
				return err
			}

			fp = filepath.Join(param.sourceGitDir, policyDir, schema.Directory, schemaSubDir, "test_policy2.json")
			if err := os.WriteFile(fp, []byte("{}"), 0o600); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)

		checkEvents(t, timeout,
			storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, "test_policy1.json"),
			storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, filepath.Join(schemaSubDir, "test_policy2.json")))
	})

	t.Run("delete schema", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)

		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Delete schema", func(wt *git.Worktree) error {
			fp := filepath.Join(param.sourceGitDir, policyDir, schema.Directory, "customer_absolute.json")
			if err := os.Remove(fp); err != nil {
				return err
			}
			if _, err := wt.Remove(filepath.Join(policyDir, schema.Directory, "customer_absolute.json")); err != nil {
				return err
			}

			fp = filepath.Join(param.sourceGitDir, policyDir, schema.Directory, schemaSubDir, "customer_absolute.json")
			if err := os.Remove(fp); err != nil {
				return err
			}
			if _, err := wt.Remove(filepath.Join(policyDir, schema.Directory, schemaSubDir, "customer_absolute.json")); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)

		checkEvents(t, timeout,
			storage.NewSchemaEvent(storage.EventDeleteSchema, "customer_absolute.json"),
			storage.NewSchemaEvent(storage.EventDeleteSchema, filepath.Join(schemaSubDir, "customer_absolute.json")))
	})

	t.Run("move schema out", func(t *testing.T) {
		t.Parallel()
		param := setupUpdateStoreTest(t, numPolicySets)
		checkEvents := storage.TestSubscription(param.store)
		require.NoError(t, commitToGitRepo(param.sourceGitDir, "Move schema out", func(wt *git.Worktree) error {
			from := filepath.Join(param.sourceGitDir, policyDir, schema.Directory, "invalid.json")
			to := filepath.Join(param.sourceGitDir, ignoredDir, "invalid.json")
			if err := os.Rename(from, to); err != nil {
				return err
			}
			if _, err := wt.Remove(filepath.Join(policyDir, schema.Directory, "invalid.json")); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, param.store.updateIndex(t.Context()))
		param.mockIdx.AssertExpectations(t)

		checkEvents(t, timeout, storage.NewSchemaEvent(storage.EventDeleteSchema, "invalid.json"))
	})
}

func buildRequiredEventsWithDependents(t *testing.T, eventKinds []storage.EventKind, pset policySet) []storage.Event {
	t.Helper()

	wantEvents := make([]storage.Event, 0, len(pset)*len(eventKinds))
	dependents := make(map[string]map[namer.ModuleID]struct{})

	for _, p := range pset {
		modID := namer.GenModuleID(p)
		depFQNs, _ := policy.Dependencies(p)
		for _, d := range depFQNs {
			if _, ok := dependents[d]; !ok {
				dependents[d] = make(map[namer.ModuleID]struct{})
			}
			dependents[d][modID] = struct{}{}
		}
	}

	for _, p := range pset {
		modID := namer.GenModuleID(p)
		for _, k := range eventKinds {
			ev := storage.Event{Kind: k, PolicyID: modID}

			if deps, ok := dependents[namer.FQN(p)]; ok {
				ev.Dependents = make([]namer.ModuleID, 0, len(deps))
				for d := range deps {
					ev.Dependents = append(ev.Dependents, d)
				}
			}

			wantEvents = append(wantEvents, ev)
		}
	}

	return wantEvents
}

func TestReloadable(t *testing.T) {
	ps := genPolicySet(1)
	sourceGitDir := t.TempDir()
	checkoutDir := t.TempDir()
	store := mkEmptyStoreAndRepo(t, sourceGitDir, checkoutDir)

	internal.TestSuiteReloadable(store, mkInitFn(t, sourceGitDir), mkAddFn(t, sourceGitDir, ps), mkDeleteFn(t, sourceGitDir))(t)
}

func TestNormalizePath(t *testing.T) {
	testCases := []struct {
		subDir       string
		path         string
		wantPath     string
		wantFileType util.IndexedFileType
	}{
		{
			subDir:       ".",
			path:         "foo.yaml",
			wantPath:     "foo.yaml",
			wantFileType: util.FileTypePolicy,
		},
		{
			subDir:       ".",
			path:         "foo.json",
			wantPath:     "foo.json",
			wantFileType: util.FileTypePolicy,
		},
		{
			subDir:       ".",
			path:         "foo/bar.yaml",
			wantPath:     "foo/bar.yaml",
			wantFileType: util.FileTypePolicy,
		},
		{
			subDir:       "foo",
			path:         "foo/bar.yaml",
			wantPath:     "bar.yaml",
			wantFileType: util.FileTypePolicy,
		},
		{
			subDir:       "foo",
			path:         "foo/bar/baz.yaml",
			wantPath:     "bar/baz.yaml",
			wantFileType: util.FileTypePolicy,
		},
		{
			subDir:       ".",
			path:         "_schemas/foo.json",
			wantPath:     "foo.json",
			wantFileType: util.FileTypeSchema,
		},
		{
			subDir:       ".",
			path:         "_schemas/foo/bar.json",
			wantPath:     "foo/bar.json",
			wantFileType: util.FileTypeSchema,
		},
		{
			subDir:       "foo",
			path:         "foo/_schemas/bar.json",
			wantPath:     "bar.json",
			wantFileType: util.FileTypeSchema,
		},
		{
			subDir:       "foo",
			path:         "foo/_schemas/bar/baz.json",
			wantPath:     "bar/baz.json",
			wantFileType: util.FileTypeSchema,
		},
		{
			subDir:       ".",
			path:         "",
			wantPath:     "",
			wantFileType: util.FileTypeNotIndexed,
		},
		{
			subDir:       ".",
			path:         "foo.txt",
			wantPath:     "foo.txt",
			wantFileType: util.FileTypeNotIndexed,
		},
		{
			subDir:       ".",
			path:         "_schemas/foo.yaml",
			wantPath:     "_schemas/foo.yaml",
			wantFileType: util.FileTypeNotIndexed,
		},
		{
			subDir:       "foo",
			path:         "bar.yaml",
			wantPath:     "bar.yaml",
			wantFileType: util.FileTypeNotIndexed,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("subDir=%s,path=%s", tc.subDir, tc.path), func(t *testing.T) {
			store := &Store{subDir: tc.subDir}

			havePath, haveFileType := store.normalizePath(tc.path)

			assert.Equal(t, tc.wantPath, havePath, "Unexpected path")
			assert.Equal(t, tc.wantFileType, haveFileType, "Unexpected file type")
		})
	}
}

func mkInitFn(t *testing.T, sourceGitDir string) internal.MutateStoreFn {
	t.Helper()

	relDir := filepath.Join("..", "testdata")
	testdataDir, err := filepath.Abs(relDir)
	require.NoError(t, err)

	p := test.LoadPolicy(t, filepath.Join(testdataDir, "policy.yaml"))
	return func() error {
		err := commitToGitRepo(sourceGitDir, "Add initial policy", func(wt *git.Worktree) error {
			if err := writePolicy(filepath.Join(sourceGitDir, policyDir, "policy.yaml"), p); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		})
		if err != nil {
			return err
		}

		return nil
	}
}

func mkDeleteFn(t *testing.T, sourceGitDir string) internal.MutateStoreFn {
	t.Helper()

	return func() error {
		err := commitToGitRepo(sourceGitDir, "Delete all", func(wt *git.Worktree) error {
			if err := filepath.WalkDir(sourceGitDir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.Name() == ".git" {
					return fs.SkipDir
				}

				if d.IsDir() {
					return nil
				}

				if d.Name() == "policy.yaml" {
					return nil
				}

				if err := os.Remove(path); err != nil {
					return fmt.Errorf("failed to remove while deleting from the store: %w", err)
				}

				return nil
			}); err != nil {
				return fmt.Errorf("failed to walk git directory: %w", err)
			}

			_, err := wt.Add(".")
			return err
		})
		if err != nil {
			return err
		}

		return nil
	}
}

func mkAddFn(t *testing.T, sourceGitDir string, ps policySet) internal.MutateStoreFn {
	t.Helper()

	return func() error {
		err := commitToGitRepo(sourceGitDir, "Add policy", func(wt *git.Worktree) error {
			if err := writePolicySet(filepath.Join(sourceGitDir, policyDir), ps); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		})
		if err != nil {
			return err
		}

		return nil
	}
}

func mkEmptyStoreAndRepo(t *testing.T, sourceGitDir, checkoutDir string) *Store {
	t.Helper()

	_ = createGitRepo(t, sourceGitDir, 0)
	store, err := NewStore(t.Context(), mkConf(t, sourceGitDir, checkoutDir))
	require.NoError(t, err)

	return store
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
	}
}

func createGitRepo(t *testing.T, dir string, policyCount int) []string {
	t.Helper()

	fullPolicyDir := filepath.Join(dir, policyDir)
	require.NoError(t, os.MkdirAll(fullPolicyDir, 0o744), "Failed to create policy dir %s", fullPolicyDir)

	fullSchemaDir := filepath.Join(dir, policyDir, schema.Directory, schemaSubDir)
	require.NoError(t, os.MkdirAll(fullSchemaDir, 0o744), "Failed to create schema dir %s", fullSchemaDir)

	fullIgnoredDir := filepath.Join(dir, ignoredDir)
	require.NoError(t, os.MkdirAll(fullIgnoredDir, 0o744), "Failed to create ignored dir %s", fullIgnoredDir)

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err, "Failed to init Git repo")

	wt, err := repo.Worktree()
	require.NoError(t, err, "Failed to get worktree")

	_, err = wt.Commit("Initial commit", &git.CommitOptions{
		AllowEmptyCommits: true,
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
	for i := range policyCount {
		pset := genPolicySet(i)

		require.NoError(t, writePolicySet(fullPolicyDir, pset), "Failed to write policies to policy dir")
		require.NoError(t, writePolicySet(fullIgnoredDir, pset), "Failed to write policies to ignored dir")

		for f := range pset {
			allFiles = append(allFiles, filepath.Join(policyDir, f))
		}
	}

	// write schemas
	copySchemas(t, fullPolicyDir)

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
		test.GenExportConstants(test.PrefixAndSuffix(namePrefix, suffix)),
		test.GenExportVariables(test.PrefixAndSuffix(namePrefix, suffix)),
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
	case *policyv1.Policy_ExportConstants:
		return fmt.Sprintf("%s.yaml", pt.ExportConstants.Name)
	case *policyv1.Policy_ExportVariables:
		return fmt.Sprintf("%s.yaml", pt.ExportVariables.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", p.PolicyType))
	}
}

func copySchemas(t *testing.T, dir string) {
	t.Helper()

	src := test.PathToDir(t, filepath.Join("schema", "fs", "_schemas"))
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		in, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", path, err)
		}
		defer in.Close()

		outFile := filepath.Join(dir, schema.Directory, relPath)
		if err := os.MkdirAll(filepath.Dir(outFile), 0o744); err != nil {
			return err
		}

		out, err := os.Create(outFile)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", outFile, err)
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})

	require.NoError(t, err)
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
		All:               true,
		AllowEmptyCommits: true,
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

	case *policyv1.Policy_DerivedRoles:
		pt.DerivedRoles.Definitions = append(pt.DerivedRoles.Definitions, &policyv1.RoleDef{
			Name:        "some_role",
			ParentRoles: []string{"some_role", "another_role"},
		})

	case *policyv1.Policy_ExportConstants:
		pt.ExportConstants.Definitions["some_constant"] = structpb.NewStringValue("some_value")

	case *policyv1.Policy_ExportVariables:
		pt.ExportVariables.Definitions["some_variable"] = "some_expression"
	}

	return p
}

func modifyPolicyVersion(p *policyv1.Policy) *policyv1.Policy {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		pt.ResourcePolicy.Version = "changed"
	case *policyv1.Policy_PrincipalPolicy:
		pt.PrincipalPolicy.Version = "changed"
	case *policyv1.Policy_DerivedRoles:
		pt.DerivedRoles.Name = "changed"
	case *policyv1.Policy_ExportConstants:
		pt.ExportConstants.Name = "changed"
	case *policyv1.Policy_ExportVariables:
		pt.ExportVariables.Name = "changed"
	}

	return p
}
