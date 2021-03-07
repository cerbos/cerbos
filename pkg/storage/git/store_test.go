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

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/test"
	"github.com/charithe/menshen/pkg/test/mocks"
)

const namePrefix = "git"

// TODO (cell) Test HTTPS and SSH auth

func TestNewStore(t *testing.T) {
	tempDir := t.TempDir()
	sourceGitDir := filepath.Join(tempDir, "source")

	require.NoError(t, createGitRepo(sourceGitDir, 20))

	setupMocks := func() (*mocks.Registry, *mocks.Transaction) {
		txn := new(mocks.Transaction)
		txn.On("Add", mock.MatchedBy(test.AnyPolicy)).Return(nil)
		txn.On("Remove", mock.MatchedBy(test.AnyPolicy)).Return(nil)

		reg := new(mocks.Registry)
		reg.On("NewTransaction").Return(txn).Once()
		reg.On("Update", mock.MatchedBy(test.AnyContext), txn).Return(nil).Once()

		return reg, txn
	}

	// the checkout directory does not exist so the remote repo will be cloned.
	t.Run("directory does not exist", func(t *testing.T) {
		checkoutDir := filepath.Join(t.TempDir(), "clone")
		conf := mkConf(sourceGitDir, checkoutDir)

		reg, txn := setupMocks()

		_, err := NewStore(context.Background(), reg, conf)
		require.NoError(t, err)
		txn.AssertNumberOfCalls(t, "Add", 60)
		reg.AssertNumberOfCalls(t, "Update", 1)
	})

	// the checkout directory is empty so the remote repo will be cloned.
	t.Run("directory is empty", func(t *testing.T) {
		checkoutDir := t.TempDir()
		conf := mkConf(sourceGitDir, checkoutDir)

		reg, txn := setupMocks()

		_, err := NewStore(context.Background(), reg, conf)
		require.NoError(t, err)
		txn.AssertNumberOfCalls(t, "Add", 60)
		reg.AssertNumberOfCalls(t, "Update", 1)
	})

	// the checkout directory already contains the git repo but checked out to the wrong branch.
	t.Run("directory is valid git repo", func(t *testing.T) {
		checkoutDir := t.TempDir()

		// checkout the master branch of the source git repo
		_, err := git.PlainClone(checkoutDir, false, &git.CloneOptions{
			URL:   fmt.Sprintf("file://%s", sourceGitDir),
			Depth: 1,
		})
		require.NoError(t, err, "Failed to clone repo")

		conf := mkConf(sourceGitDir, checkoutDir)

		reg, txn := setupMocks()

		_, err = NewStore(context.Background(), reg, conf)
		require.NoError(t, err)
		txn.AssertNumberOfCalls(t, "Add", 60)
		reg.AssertNumberOfCalls(t, "Update", 1)
	})

	// the checkout directory is not empty and not a valid git repo.
	t.Run("directory is not empty", func(t *testing.T) {
		checkoutDir := t.TempDir()

		for i := 0; i < 10; i++ {
			file := filepath.Join(checkoutDir, fmt.Sprintf("file_%02d.txt", i))
			require.NoError(t, os.WriteFile(file, []byte("some data"), 0644))
		}

		conf := mkConf(sourceGitDir, checkoutDir)

		reg, txn := setupMocks()

		_, err := NewStore(context.Background(), reg, conf)
		require.ErrorIs(t, err, git.ErrRepositoryNotExists)
		txn.AssertNumberOfCalls(t, "Add", 0)
		reg.AssertNumberOfCalls(t, "Update", 0)
	})
}

func TestUpdateRegistry(t *testing.T) {
	tempDir := t.TempDir()
	sourceGitDir := filepath.Join(tempDir, "source")
	checkoutDir := filepath.Join(tempDir, "checkout")

	rng := rand.New(rand.NewSource(time.Now().Unix()))
	numPolicySets := 20

	require.NoError(t, createGitRepo(sourceGitDir, numPolicySets))

	txnHelper := &mockTxnHelper{}

	setup := func(t *testing.T) (*Store, *mocks.Registry) {
		t.Helper()

		reg := new(mocks.Registry)
		reg.On("NewTransaction").Return(func() policy.Transaction { return txnHelper.newTxn() })
		reg.On("Update", mock.Anything, mock.Anything).Return(nil)

		conf := mkConf(sourceGitDir, checkoutDir)

		store, err := NewStore(context.Background(), reg, conf)
		require.NoError(t, err)
		txnHelper.last().AssertNumberOfCalls(t, "Add", numPolicySets*3)
		reg.AssertNumberOfCalls(t, "Update", 1)

		return store, reg
	}

	store, reg := setup(t)

	t.Run("no changes", func(t *testing.T) {
		// because the mock registry is shared, only way to ensure that it wasn't called is to
		// check the call count before and after the function call.
		reg.AssertNumberOfCalls(t, "Update", 1)
		require.NoError(t, store.updateRegistry(context.Background()))
		reg.AssertNumberOfCalls(t, "Update", 1)
	})

	t.Run("modify policy", func(t *testing.T) {
		pset := genPolicySet(rng.Intn(numPolicySets))

		require.NoError(t, commitToGitRepo(sourceGitDir, "Modify policy", func(wt *git.Worktree) error {
			for _, p := range pset {
				modifyPolicy(p)
				if err := writePolicies(filepath.Join(sourceGitDir, "policies"), p); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateRegistry(context.Background()))

		txn := txnHelper.last()
		require.NotNil(t, txn)

		txn.AssertNumberOfCalls(t, "Add", 3)
		txn.AssertNotCalled(t, "Remove", mock.MatchedBy(test.AnyPolicy))
		reg.AssertCalled(t, "Update", mock.MatchedBy(test.AnyContext), txn)
	})

	t.Run("add policy", func(t *testing.T) {
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Add policy", func(wt *git.Worktree) error {
			for _, p := range pset {
				if err := writePolicies(filepath.Join(sourceGitDir, "policies"), p); err != nil {
					return err
				}

				if _, err := wt.Add(mkFilePath("policies", p)); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateRegistry(context.Background()))

		txn := txnHelper.last()
		require.NotNil(t, txn)

		txn.AssertNumberOfCalls(t, "Add", 3)
		txn.AssertNotCalled(t, "Remove", mock.MatchedBy(test.AnyPolicy))
		reg.AssertCalled(t, "Update", mock.MatchedBy(test.AnyContext), txn)
	})

	t.Run("add policy to ignored dir", func(t *testing.T) {
		pset := genPolicySet(numPolicySets)

		require.NoError(t, commitToGitRepo(sourceGitDir, "Add ignored policy", func(wt *git.Worktree) error {
			for _, p := range pset {
				if err := writePolicies(filepath.Join(sourceGitDir, "ignored"), p); err != nil {
					return err
				}

				if _, err := wt.Add(mkFilePath("ignored", p)); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateRegistry(context.Background()))

		txn := txnHelper.last()
		require.NotNil(t, txn)

		txn.AssertNotCalled(t, "Add", mock.MatchedBy(test.AnyPolicy))
		txn.AssertNotCalled(t, "Remove", mock.MatchedBy(test.AnyPolicy))
	})

	t.Run("delete policy", func(t *testing.T) {
		pset := genPolicySet(rng.Intn(numPolicySets))

		require.NoError(t, commitToGitRepo(sourceGitDir, "Delete policy", func(wt *git.Worktree) error {
			for _, p := range pset {
				fp := mkFilePath("policies", p)
				if err := os.Remove(filepath.Join(sourceGitDir, fp)); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateRegistry(context.Background()))

		txn := txnHelper.last()
		require.NotNil(t, txn)

		txn.AssertNumberOfCalls(t, "Remove", 3)
		txn.AssertNotCalled(t, "Add", mock.MatchedBy(test.AnyPolicy))
		reg.AssertCalled(t, "Update", mock.MatchedBy(test.AnyContext), txn)
	})

	t.Run("move policy out of policy dir", func(t *testing.T) {
		pset := genPolicySet(rng.Intn(numPolicySets))

		require.NoError(t, commitToGitRepo(sourceGitDir, "Move policy out", func(wt *git.Worktree) error {
			for _, p := range pset {
				from := filepath.Join(sourceGitDir, mkFilePath("policies", p))
				to := filepath.Join(sourceGitDir, mkFilePath("ignored", p))
				if err := os.Rename(from, to); err != nil {
					return err
				}
			}

			return nil
		}))

		require.NoError(t, store.updateRegistry(context.Background()))

		txn := txnHelper.last()
		require.NotNil(t, txn)

		txn.AssertNumberOfCalls(t, "Remove", 3)
		txn.AssertNotCalled(t, "Add", mock.MatchedBy(test.AnyPolicy))
		reg.AssertCalled(t, "Update", mock.MatchedBy(test.AnyContext), txn)
	})
}

type mockTxnHelper struct {
	txns []*mocks.Transaction
}

func (m *mockTxnHelper) newTxn() *mocks.Transaction {
	txn := new(mocks.Transaction)
	txn.On("Add", mock.Anything).Return(nil)
	txn.On("Remove", mock.Anything).Return(nil)

	m.txns = append(m.txns, txn)

	return txn
}

func (m *mockTxnHelper) last() *mocks.Transaction {
	if len(m.txns) == 0 {
		return nil
	}

	return m.txns[len(m.txns)-1]
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

func createGitRepo(dir string, policyCount int) error {
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0744); err != nil {
		return fmt.Errorf("failed to create policy dir %s: %w", policyDir, err)
	}

	ignoredDir := filepath.Join(dir, "ignored")
	if err := os.MkdirAll(ignoredDir, 0744); err != nil {
		return fmt.Errorf("failed to create ignored dir %s: %w", ignoredDir, err)
	}

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		return fmt.Errorf("failed to init Git repo: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	if _, err := wt.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Daffy Duck",
			Email: "daffy@mallard.dev",
			When:  time.Now(),
		},
	}); err != nil {
		return fmt.Errorf("failed to do initial commit: %w", err)
	}

	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get head: %w", err)
	}

	if err := wt.Checkout(&git.CheckoutOptions{
		Hash:   head.Hash(),
		Branch: plumbing.NewBranchReferenceName("policies"),
		Create: true,
	}); err != nil {
		return fmt.Errorf("failed to checkout branch: %w", err)
	}

	// write policies
	for i := 0; i < policyCount; i++ {
		pset := genPolicySet(i)

		if err := writePolicies(policyDir, pset[:]...); err != nil {
			return fmt.Errorf("failed to write policies to policy dir: %w", err)
		}

		if err := writePolicies(ignoredDir, pset[:]...); err != nil {
			return fmt.Errorf("failed to write policies to ignored dir: %w", err)
		}
	}

	if _, err := wt.Add("."); err != nil {
		return fmt.Errorf("failed to add: %w", err)
	}

	if _, err := wt.Commit("Add policies", &git.CommitOptions{
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

func genPolicySet(i int) [3]*policyv1.Policy {
	suffix := fmt.Sprintf("%03d", i)

	rp := test.GenResourcePolicy(test.PrefixAndSuffix(namePrefix, suffix))
	pp := test.GenPrincipalPolicy(test.PrefixAndSuffix(namePrefix, suffix))
	dr := test.GenDerivedRoles(test.PrefixAndSuffix(namePrefix, suffix))

	return [...]*policyv1.Policy{rp, pp, dr}
}

func writePolicies(dir string, policies ...*policyv1.Policy) error {
	for _, p := range policies {
		if err := writePolicy(dir, p); err != nil {
			return err
		}
	}

	return nil
}

func writePolicy(dir string, p *policyv1.Policy) error {
	fpath := mkFilePath(dir, p)
	f, err := os.Create(fpath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", fpath, err)
	}

	defer f.Close()

	_, err = policy.WritePolicy(f, p)

	return err
}

func mkFilePath(dir string, p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return filepath.Join(dir, fmt.Sprintf("%s.%s.yaml", pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version))
	case *policyv1.Policy_PrincipalPolicy:
		return filepath.Join(dir, fmt.Sprintf("%s.%s.yaml", pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version))
	case *policyv1.Policy_DerivedRoles:
		return filepath.Join(dir, fmt.Sprintf("%s.yaml", pt.DerivedRoles.Name))
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

func commitToGitRepo(dir string, msg string, work func(*git.Worktree) error) error {
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
			Action: "some_action",
			Roles:  []string{"admin"},
			Effect: sharedv1.Effect_EFFECT_ALLOW,
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
