// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/util"
)

const uploadGitHelp = `
The following exit codes have a special meaning.
	- 6: The version condition supplied using --version-must-eq wasn't satisfied

# Add, delete or update files from git repository

cerbosctl hub store upload-git

# Add, delete or update files from git repository in path/to/git/repository

cerbosctl hub store upload-git path/to/git/repository
`

type UploadGitCmd struct {
	Output       `embed:""`
	Path         string `arg:"" help:"Path to the git repository" default:"."`
	diffsToApply []*diff
}

func (*UploadGitCmd) Help() string {
	return uploadGitHelp
}

func (ugc *UploadGitCmd) Validate() error {
	repository, err := git.PlainOpen(ugc.Path)
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	if ugc.diffsToApply, err = ugc.diffs(repository); err != nil {
		return fmt.Errorf("failed to get diffs: %w", err)
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

	var version int64
	for _, diff := range ugc.diffsToApply {
		for batch, err := range ugc.batch(diff) {
			if err != nil {
				return ugc.toCommandError(k.Stderr, err)
			}

			changeDetails, err := changeDetailsFromHash(repository, diff.hash)
			if err != nil {
				return ugc.toCommandError(k.Stderr, fmt.Errorf("failed to get change details for %q: %w", diff.hash.String(), err))
			}

			req := hub.
				NewModifyFilesRequest(cmd.StoreID, changeDetails.message).
				WithChangeDetails(
					hub.NewChangeDetails(changeDetails.message).
						WithOriginGitDetails(changeDetails.origin).
						WithUploaderDetails(changeDetails.uploader),
				).
				AddOps(batch...)

			reqBytes, err := protojson.Marshal(req.Proto())
			if err != nil {
				return ugc.toCommandError(k.Stderr, err)
			}

			fmt.Fprintf(k.Stdout, "%s\n\n", string(reqBytes))

			resp, err := client.ModifyFilesLenient(context.Background(), req)
			if err != nil {
				return ugc.toCommandError(k.Stderr, err)
			}

			if resp != nil {
				version = resp.GetNewStoreVersion()
			}
		}
	}

	ugc.printNewVersion(k.Stdout, version)
	return nil
}

func (ugc *UploadGitCmd) batch(diff *diff) iter.Seq2[[]*storev1.FileOp, error] {
	return func(yield func([]*storev1.FileOp, error) bool) {
		batch := make([]*storev1.FileOp, 0, modifyFilesBatchSize)
		batchCounter := 0

		for _, change := range diff.changes {
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

func (ugc *UploadGitCmd) diffs(r *git.Repository) ([]*diff, error) {
	head, err := r.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	iter, err := r.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit iterator: %w", err)
	}

	headCommit, err := iter.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD commit: %w", err)
	}

	parentCommit, err := iter.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get parent commit: %w", err)
	}

	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for HEAD commit: %w", err)
	}

	parentTree, err := parentCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for parent commit: %w", err)
	}

	objectChanges, err := object.DiffTree(parentTree, headTree)
	if err != nil {
		return nil, fmt.Errorf("failed to get diff tree: %w", err)
	}

	changes, err := ugc.changes(objectChanges)
	if err != nil {
		return nil, fmt.Errorf("failed to get changes: %w", err)
	}

	return []*diff{{hash: head.Hash(), changes: changes}}, nil
}

func (ugc *UploadGitCmd) changes(objectChanges object.Changes) ([]*change, error) {
	pathToRepo, err := filepath.Abs(ugc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path to repository: %w", err)
	}

	changes := make([]*change, 0, len(ugc.diffsToApply))
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

		path := filepath.Clean(filepath.Join(pathToRepo, name))
		if path == "" || util.PathIsHidden(path) || !util.IsSupportedFileType(path) {
			return nil, fmt.Errorf("invalid file %q: must not be hidden and must be a YAML or JSON file", path)
		}

		stat, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to stat file at %q: %w", path, err)
		}

		if stat.Size() > maxFileSize {
			return nil, fmt.Errorf("file too large: %s", path)
		}

		changes = append(changes, &change{
			name:      name,
			path:      path,
			operation: operation,
		})
		if nameOfToBeDeleted != "" {
			changes = append(changes, &change{
				name:      name,
				path:      path,
				operation: OpDelete,
			})
		}
	}

	return changes, nil
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
