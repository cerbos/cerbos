// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package blob

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.uber.org/multierr"
	"go.uber.org/zap"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/util"
)

type Cloner struct {
	bucket *blob.Bucket
	fs     FS
	log    *zap.SugaredLogger
	state  map[string][]string
}

func NewCloner(bucket *blob.Bucket, dir string) (*Cloner, error) {
	if err := createOrValidateDir(dir); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &Cloner{
		bucket: bucket,
		log:    zap.S().Named("blob.cloner"),
		fs:     newBlobFS(dir),
		state:  make(map[string][]string),
	}, nil
}

type info struct {
	etag string
	file string
}

type CloneResult struct {
	all            map[string][]string
	addedOrUpdated []info
	deleted        []info
}

func (cr *CloneResult) isEmpty() bool {
	return cr == nil || (len(cr.addedOrUpdated) == 0 && len(cr.deleted) == 0)
}

func (c *Cloner) Clone(ctx context.Context) (*CloneResult, error) {
	iter := c.bucket.List(nil)

	all := make(map[string][]string)
	var addedOrUpdated []info
	for {
		obj, err := iter.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			c.log.Errorw("Failed to get next item", "error", err)
			return nil, fmt.Errorf("failed to get next object in the bucket: %w", err)
		}

		file := strings.TrimPrefix(obj.Key, "/")
		if util.FileType(file) == util.FileTypeNotIndexed {
			continue
		}

		if obj.MD5 == nil {
			return nil, fmt.Errorf("blob object doesn't have md5 specified: %w", err)
		}

		if !util.IsSupportedFileType(file) {
			c.log.Debugw("Unsupported file is ignored", "file", file)
			continue
		}

		etag := hex.EncodeToString(obj.MD5)
		all[etag] = append(all[etag], file)

		if existingFiles, ok := c.state[etag]; ok {
			if !slices.Contains(existingFiles, file) {
				addedOrUpdated = append(addedOrUpdated, info{
					etag: etag,
					file: file,
				})
			}

			continue
		}

		if _, err := c.fs.Stat(etag); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to check if file %s with etag %s exists: %w", file, etag, err)
		} else if errors.Is(err, os.ErrNotExist) {
			if err := c.downloadToFile(ctx, obj.Key, etag); err != nil {
				return nil, fmt.Errorf("failed to download file %s with etag %s: %w", file, etag, err)
			}
		}

		addedOrUpdated = append(addedOrUpdated, info{
			etag: etag,
			file: file,
		})
	}

	var deleted []info
	for etag, existingFiles := range c.state {
		for _, existingFile := range existingFiles {
			if files, ok := all[etag]; !ok {
				deleted = append(deleted, info{
					etag: etag,
					file: existingFile,
				})
			} else if !slices.Contains(files, existingFile) {
				deleted = append(deleted, info{
					etag: etag,
					file: existingFile,
				})
			}
		}
	}

	c.state = all
	return &CloneResult{
		all:            all,
		addedOrUpdated: addedOrUpdated,
		deleted:        deleted,
	}, nil
}

func (c *Cloner) downloadToFile(ctx context.Context, key, file string) (err error) {
	dir := filepath.Dir(file)
	if err := c.fs.MkdirAll(dir, perm775); err != nil { //nolint:mnd
		return fmt.Errorf("failed to make dir %s: %w", dir, err)
	}

	fd, err := c.fs.Create(file)
	if err != nil {
		return fmt.Errorf("failed to create a file %s: %w", file, err)
	}
	defer multierr.AppendInvoke(&err, multierr.Close(fd))

	r, err := c.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return fmt.Errorf("failed to create a reader for the object %s: %w", key, err)
	}
	// defer multierr.AppendInvoke(&err, multierr.Close(r))
	defer r.Close()

	if _, err = io.Copy(fd, r); err != nil {
		return fmt.Errorf("failed to read the object %s: %w", key, err)
	}

	return nil
}

func (c *Cloner) Clean() error {
	var removeErrors error
	if err := fs.WalkDir(c.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if _, ok := c.state[path]; !ok {
			c.log.Debugw("Removing dangling etag file", "etag", path)
			if err := c.fs.Remove(path); err != nil {
				removeErrors = errors.Join(removeErrors, fmt.Errorf("failed to remove dangling etag file %s: %w", path, err))
			}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk dir: %w", errors.Join(err, removeErrors))
	}

	return nil
}
