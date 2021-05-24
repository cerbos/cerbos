// Copyright 2021 Zenauth Ltd.

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

	"github.com/cerbos/cerbos/internal/compile"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
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
		conf := mkConf(sourceGitDir, checkoutDir)

		store, err := NewStore(context.Background(), conf)
		require.NoError(t, err)

		requireIndexContains(t, store, wantFiles)
	})

	// the checkout directory is empty so the remote repo will be cloned.
	t.Run("directory is empty", func(t *testing.T) {
		checkoutDir := t.TempDir()
		conf := mkConf(sourceGitDir, checkoutDir)

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

		conf := mkConf(sourceGitDir, checkoutDir)

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

		conf := mkConf(sourceGitDir, checkoutDir)

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

	_ = createGitRepo(t, sourceGitDir, numPolicySets)

	conf := mkConf(sourceGitDir, checkoutDir)
	store, err := NewStore(context.Background(), conf)
	require.NoError(t, err)

	index := store.index

	setupMock := func() *mockIndex {
		m := newMockIndex(index)
		store.index = m
		return m
	}

	notificationChan := make(chan compile.Notification, 1)
	store.SetNotificationChannel(notificationChan)

	t.Run("no changes", func(t *testing.T) {
		mockIdx := setupMock()
		require.NoError(t, store.updateIndex(context.Background()))
		require.Len(t, mockIdx.calls, 0)
	})

	t.Run("modify policy", func(t *testing.T) {
		mockIdx := setupMock()
		pset := genPolicySet(rng.Intn(numPolicySets))

		require.NoError(t, commitToGitRepo(sourceGitDir, "Modify policy", func(wt *git.Worktree) error {
			for _, p := range pset {
				modifyPolicy(p)
			}

			return writePolicySet(filepath.Join(sourceGitDir, policyDir), pset)
		}))

		require.NoError(t, store.updateIndex(context.Background()))

		require.True(t, mockIdx.Called("Apply", mock.Anything))
		require.Len(t, mockIdx.calls, 1)

		notice := getNotification(t, notificationChan)
		require.NotNil(t, notice)
		require.Len(t, notice.AddOrUpdate, 3)
		require.Len(t, notice.Remove, 0)
	})

	t.Run("add policy", func(t *testing.T) {
		mockIdx := setupMock()
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Add policy", func(wt *git.Worktree) error {
			if err := writePolicySet(filepath.Join(sourceGitDir, policyDir), pset); err != nil {
				return err
			}

			_, err := wt.Add(".")
			return err
		}))

		require.NoError(t, store.updateIndex(context.Background()))

		require.True(t, mockIdx.Called("Apply", mock.Anything))
		require.Len(t, mockIdx.calls, 1)

		notice := getNotification(t, notificationChan)
		require.NotNil(t, notice)
		require.Len(t, notice.AddOrUpdate, 3)
		require.Len(t, notice.Remove, 0)
	})

	t.Run("add policy to ignored dir", func(t *testing.T) {
		mockIdx := setupMock()
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
		require.Len(t, mockIdx.calls, 0)
	})

	t.Run("delete policy", func(t *testing.T) {
		mockIdx := setupMock()
		pset := genPolicySet(rng.Intn(numPolicySets))

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

		require.True(t, mockIdx.Called("Apply", mock.Anything))
		require.Len(t, mockIdx.calls, 1)

		notice := getNotification(t, notificationChan)
		require.NotNil(t, notice)
		require.Len(t, notice.AddOrUpdate, 0)
		require.Len(t, notice.Remove, 3)
	})

	t.Run("move policy out of policy dir", func(t *testing.T) {
		mockIdx := setupMock()
		pset := genPolicySet(rng.Intn(numPolicySets))

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

		require.True(t, mockIdx.Called("Apply", mock.Anything))
		require.Len(t, mockIdx.calls, 1)

		notice := getNotification(t, notificationChan)
		require.NotNil(t, notice)
		require.Len(t, notice.AddOrUpdate, 0)
		require.Len(t, notice.Remove, 3)
	})

	t.Run("ignore unsupported file", func(t *testing.T) {
		mockIdx := setupMock()
		require.NoError(t, commitToGitRepo(sourceGitDir, "Add unsupported file", func(wt *git.Worktree) error {
			fp := filepath.Join(sourceGitDir, policyDir, "file1.txt")
			if err := os.WriteFile(fp, []byte("something"), 0o600); err != nil {
				return err
			}

			_, err := wt.Add(filepath.Join(policyDir, "file1.txt"))

			return err
		}))

		require.NoError(t, store.updateIndex(context.Background()))
		require.Len(t, mockIdx.calls, 0)
	})
}

func requireIndexContains(t *testing.T, store *Store, wantFiles []string) {
	t.Helper()

	var haveFiles []string
	for p := range store.GetAllPolicies(context.Background()) {
		require.NoError(t, p.Err, "Policy returned by the store has an error")
		for _, f := range p.ModToFile {
			haveFiles = append(haveFiles, f)
		}
	}

	require.ElementsMatch(t, wantFiles, haveFiles)
}

func getNotification(t *testing.T, notificationChan <-chan compile.Notification) *compile.Incremental {
	t.Helper()

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	select {
	case c := <-notificationChan:
		return c.Payload
	case <-timer.C:
		return nil
	}
}

func mkConf(gitRepo, checkoutDir string) *Conf {
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
			Effect:  sharedv1.Effect_EFFECT_ALLOW,
		})

		return p
	case *policyv1.Policy_PrincipalPolicy:
		pt.PrincipalPolicy.Rules = append(pt.PrincipalPolicy.Rules, &policyv1.PrincipalRule{
			Resource: "some_resource",
			Actions: []*policyv1.PrincipalRule_Action{
				{
					Action: "*",
					Effect: sharedv1.Effect_EFFECT_DENY,
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

type mockIndex struct {
	index disk.Index
	calls []mock.Call
}

func newMockIndex(index disk.Index) *mockIndex {
	return &mockIndex{index: index}
}

func (m *mockIndex) Reload(ctx context.Context) error {
	m.calls = append(m.calls, mock.Call{Method: "Reload", Arguments: mock.Arguments{ctx}})
	return m.index.Reload(ctx)
}

func (m *mockIndex) Add(file string, p *policyv1.Policy) (*compile.Incremental, error) {
	m.calls = append(m.calls, mock.Call{Method: "Add", Arguments: mock.Arguments{file, p}})
	return m.index.Add(file, p)
}

func (m *mockIndex) Remove(file string) (*compile.Incremental, error) {
	m.calls = append(m.calls, mock.Call{Method: "Remove", Arguments: mock.Arguments{file}})
	return m.index.Remove(file)
}

func (m *mockIndex) RemoveIfSafe(file string) (*compile.Incremental, error) {
	m.calls = append(m.calls, mock.Call{Method: "RemoveIfSafe", Arguments: mock.Arguments{file}})
	return m.index.RemoveIfSafe(file)
}

func (m *mockIndex) FilenameFor(p *policyv1.Policy) string {
	m.calls = append(m.calls, mock.Call{Method: "FilenameFor", Arguments: mock.Arguments{p}})
	return m.index.FilenameFor(p)
}

func (m *mockIndex) GetAllPolicies(ctx context.Context) <-chan *compile.Unit {
	m.calls = append(m.calls, mock.Call{Method: "GetAllPolicies", Arguments: mock.Arguments{ctx}})
	return m.index.GetAllPolicies(ctx)
}

func (m *mockIndex) Apply(updates *disk.IndexUpdate) (*compile.Incremental, error) {
	m.calls = append(m.calls, mock.Call{Method: "Apply", Arguments: mock.Arguments{updates}})
	return m.index.Apply(updates)
}

func (m *mockIndex) Called(methodName string, expected ...interface{}) bool {
	for _, call := range m.calls {
		if call.Method == methodName {
			_, differences := mock.Arguments(expected).Diff(call.Arguments)
			if differences == 0 {
				return true
			}
		}
	}

	return false
}
