// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/cerbos/cerbos/internal/util"
)

const uploadGitHelp = `
The following exit codes have a special meaning.
	- 6: The version condition supplied using --version-must-eq wasn't satisfied

# Apply the file changes recorded in the git repo between commit 55a4248 and HEAD

cerbosctl hub store upload-git 55a4248
cerbosctl hub store upload-git 55a4248 --path path/to/git/repository

# Apply the file changes recorded in the git repo between commit 55a4248 to e746228

cerbosctl hub store upload-git 55a4248 e746228
cerbosctl hub store upload-git 55a4248 e746228 --path path/to/git/repository
`

type UploadGitCmd struct {
	diffToApply   *diff
	From          string `arg:"" help:"Git revision to start from when generating the diff"`
	To            string `arg:"" help:"Git revision to end when generating the diff (The resolved reference must be the ancestor of the from argument)" default:"HEAD"`
	Path          string `help:"Path to the git repository" default:"."`
	Subdirectory  string `help:"Subdirectory under the given path to check and upload changes from" aliases:"subdir" default:"."`
	Output        `embed:""`
	ChangeDetails `embed:""`
	VersionMustEq int64 `help:"Require that the store is at this version before committing the change" optional:""`
}

func (*UploadGitCmd) Help() string {
	return uploadGitHelp
}

func (ugc *UploadGitCmd) Validate() error {
	r, err := git.PlainOpen(ugc.Path)
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	from, err := r.ResolveRevision(plumbing.Revision(ugc.From))
	if err != nil {
		return fmt.Errorf("failed to resolve revision %q: %w", ugc.From, err)
	}

	to, err := r.ResolveRevision(plumbing.Revision(ugc.To))
	if err != nil {
		return fmt.Errorf("failed to resolve revision %q: %w", ugc.To, err)
	}

	if ugc.diffToApply, err = ugc.diff(r, *from, *to); err != nil {
		return fmt.Errorf("failed to get diff between revision %q to %q: %w", ugc.From, ugc.To, err)
	}

	return nil
}

func (ugc *UploadGitCmd) Run(k *kong.Kong, cmd *Cmd) error {
	repository, err := git.PlainOpen(ugc.Path)
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	client, err := cmd.storeClient()
	if err != nil {
		return ugc.toCommandError(k.Stderr, err)
	}

	version := ugc.VersionMustEq
	for batch, err := range ugc.batch() {
		if err != nil {
			return ugc.toCommandError(k.Stderr, err)
		}

		gitChangeDetails, err := changeDetailsFromHash(repository, ugc.diffToApply.hash)
		if err != nil {
			return ugc.toCommandError(k.Stderr, fmt.Errorf("failed to get change details for %q: %w", ugc.diffToApply.hash.String(), err))
		}

		changeDetails, message, err := ugc.ChangeDetails.ChangeDetails(gitChangeDetails)
		if err != nil {
			return ugc.toCommandError(k.Stderr, fmt.Errorf("failed to get change details: %w", err))
		}

		req := hub.
			NewModifyFilesRequest(cmd.StoreID, message).
			WithChangeDetails(changeDetails).
			AddOps(batch...)
		if version > 0 {
			req.OnlyIfVersionEquals(version)
		}

		resp, err := client.ModifyFilesLenient(context.Background(), req)
		if err != nil {
			return ugc.toCommandError(k.Stderr, err)
		}

		if resp != nil {
			version = resp.GetNewStoreVersion()
		}
	}

	ugc.printNewVersion(k.Stdout, version)
	return nil
}

func (ugc *UploadGitCmd) batch() iter.Seq2[[]*storev1.FileOp, error] {
	return func(yield func([]*storev1.FileOp, error) bool) {
		batch := make([]*storev1.FileOp, 0, modifyFilesBatchSize)
		batchCounter := 0

		for _, change := range ugc.diffToApply.changes {
			switch change.operation {
			case OpAddOrUpdate:
				contents, err := os.ReadFile(change.path)
				if err != nil {
					yield(nil, fmt.Errorf("failed to read %s: %w", change.path, err))
					return
				}

				batch = append(batch, &storev1.FileOp{
					Op: &storev1.FileOp_AddOrUpdate{
						AddOrUpdate: &storev1.File{
							Path:     change.name,
							Contents: contents,
						},
					},
				})
			case OpDelete:
				batch = append(batch, &storev1.FileOp{
					Op: &storev1.FileOp_Delete{
						Delete: change.name,
					},
				})
			default:
				yield(nil, fmt.Errorf("unexpected operation %s", change.operation))
			}

			batchCounter++
			if batchCounter == modifyFilesBatchSize {
				if !yield(batch, nil) {
					return
				}

				batch = make([]*storev1.FileOp, 0, modifyFilesBatchSize)
				batchCounter = 0
			}
		}

		if batchCounter > 0 {
			yield(batch, nil)
		}
	}
}

func (ugc *UploadGitCmd) diff(r *git.Repository, from, to plumbing.Hash) (*diff, error) {
	fromCommit, err := r.CommitObject(from)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object for commit %q: %w", from.String(), err)
	}

	toCommit, err := r.CommitObject(to)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object for commit %q: %w", to.String(), err)
	}

	isAncestor, err := fromCommit.IsAncestor(toCommit)
	if err != nil {
		return nil, fmt.Errorf("failed to check if ancestor: %w", err)
	}

	if !isAncestor {
		return nil, fmt.Errorf("commit %q is not ancestor of commit %q", to.String(), from.String())
	}

	fromTree, err := fromCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree of commit %q: %w", from.String(), err)
	}

	toTree, err := toCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree of commit %q: %w", to.String(), err)
	}

	objectChanges, err := object.DiffTree(fromTree, toTree)
	if err != nil {
		return nil, fmt.Errorf("failed to get diff tree: %w", err)
	}

	changes, err := ugc.changes(objectChanges)
	if err != nil {
		return nil, fmt.Errorf("failed to get changes: %w", err)
	}

	return &diff{hash: to, changes: changes}, nil
}

func (ugc *UploadGitCmd) changes(objectChanges object.Changes) ([]*change, error) {
	pathToRepo, err := filepath.Abs(ugc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path to repository: %w", err)
	}

	changes := make([]*change, 0, len(objectChanges))
	for _, objectChange := range objectChanges {
		from, to, err := objectChange.Files()
		if err != nil {
			return nil, fmt.Errorf("failed to get file from change: %w", err)
		}

		var nameOfToBeDeleted string
		var name string
		var operation op
		switch {
		case from != nil && to != nil:
			if objectChange.From.Name == objectChange.To.Name {
				name = objectChange.To.Name
				operation = OpAddOrUpdate
			} else {
				name = objectChange.To.Name
				operation = OpAddOrUpdate
				nameOfToBeDeleted = objectChange.From.Name
			}
		case from == nil && to != nil:
			name = objectChange.To.Name
			operation = OpAddOrUpdate
		case from != nil:
			name = objectChange.From.Name
			operation = OpDelete
		}

		normalizedName, skipped := ugc.normalize(name)
		if skipped {
			continue
		}

		path := filepath.Clean(filepath.Join(pathToRepo, name))
		if path == "" || util.PathIsHidden(path) || !util.IsSupportedFileType(path) {
			return nil, fmt.Errorf("invalid file %q: must not be hidden and must be a YAML or JSON file", path)
		}

		if operation != OpDelete {
			stat, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("failed to stat file at %q: %w", path, err)
			}

			if stat.Size() > maxFileSize {
				return nil, fmt.Errorf("file too large: %s", path)
			}
		}

		changes = append(changes, &change{
			name:      normalizedName,
			path:      path,
			operation: operation,
		})
		if nameOfToBeDeleted != "" {
			changes = append(changes, &change{
				name:      normalizedName,
				path:      path,
				operation: OpDelete,
			})
		}
	}

	return changes, nil
}

func (ugc *UploadGitCmd) normalize(name string) (normalized string, skipped bool) {
	normalized = name
	if ugc.Subdirectory != "." {
		if n, ok := strings.CutPrefix(name, ugc.Subdirectory+"/"); ok {
			normalized = n
		} else {
			skipped = true
		}

		return
	}

	return
}

type diff struct {
	changes []*change
	hash    plumbing.Hash
}

type change struct {
	name      string
	path      string
	operation op
}

type op string

const (
	OpUnspecified op = "UNSPECIFIED"
	OpAddOrUpdate op = "ADD_OR_UPDATE"
	OpDelete      op = "DELETE"
)
