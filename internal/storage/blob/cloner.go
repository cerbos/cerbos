// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"go.uber.org/multierr"
	"go.uber.org/zap"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/util"
)

// clonerFS represents file system interface that used by the Cloner.
type clonerFS interface {
	fs.FS
	Remove(name string) error
	Create(name string) (io.WriteCloser, error)
	MkdirAll(path string, perm fs.FileMode) error
}

type Cloner struct {
	bucket        *blob.Bucket
	fsys          clonerFS
	log           *zap.SugaredLogger
	state         map[string][]string
	danglingEtags []string
}

func NewCloner(bucket *blob.Bucket, fsys clonerFS) *Cloner {
	return &Cloner{
		bucket: bucket,
		log:    zap.S().Named("blob.cloner"),
		fsys:   fsys,
		state:  make(map[string][]string),
	}
}

type info struct {
	etag string
	file string
}

type CloneResult struct {
	all            map[string][]string
	addedOrUpdated []info
	deleted        []info
	failuresCount  int
}

func (cr *CloneResult) isEmpty() bool {
	return cr == nil || (len(cr.addedOrUpdated) == 0 && len(cr.deleted) == 0)
}

func (c *Cloner) Clone(ctx context.Context) (*CloneResult, error) {
	iter := c.bucket.List(nil)

	all := make(map[string][]string)
	var addedOrUpdated []info
	var failuresCount int
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

		etag := fmt.Sprintf("%x", obj.MD5)
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

		if err = c.downloadToFile(ctx, obj.Key, etag); err != nil {
			c.log.Errorw("Failed to download file", "error", err, "etag", etag, "file", file)
			failuresCount++
		} else {
			addedOrUpdated = append(addedOrUpdated, info{
				etag: etag,
				file: file,
			})
		}
	}

	var danglingEtags []string
	var deleted []info
	for etag, existingFiles := range c.state {
		for _, existingFile := range existingFiles {
			if files, ok := all[etag]; !ok {
				deleted = append(deleted, info{
					etag: etag,
					file: existingFile,
				})

				// This etag is not referenced from any file, we should get rid of it later.
				danglingEtags = append(danglingEtags, etag)
			} else if !slices.Contains(files, existingFile) {
				deleted = append(deleted, info{
					etag: etag,
					file: existingFile,
				})
			}
		}
	}

	c.danglingEtags = danglingEtags
	c.state = all
	return &CloneResult{
		all:            all,
		addedOrUpdated: addedOrUpdated,
		deleted:        deleted,
		failuresCount:  failuresCount,
	}, nil
}

func (c *Cloner) downloadToFile(ctx context.Context, key, file string) error {
	dir := filepath.Dir(file)
	if err := c.fsys.MkdirAll(dir, 0o775); err != nil { //nolint:mnd
		return fmt.Errorf("failed to make dir %q: %w", dir, err)
	}

	fd, err := c.fsys.Create(file)
	if err != nil {
		return fmt.Errorf("failed to create a file %q: %w", file, err)
	}
	defer multierr.AppendInvoke(&err, multierr.Close(fd))

	r, err := c.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return fmt.Errorf("failed to create a reader for the object %q: %w", key, err)
	}
	// defer multierr.AppendInvoke(&err, multierr.Close(r))
	defer r.Close()

	if _, err = io.Copy(fd, r); err != nil {
		return fmt.Errorf("failed to read the object %q: %w", key, err)
	}

	return nil
}

func (c *Cloner) Clean() error {
	var errs error
	for _, etag := range c.danglingEtags {
		c.log.Debugw("Removing dangling etag file", "etag", etag)
		if err := c.fsys.Remove(etag); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove dangling etag file %s: %w", etag, err))
		}
	}

	c.danglingEtags = nil
	return errs
}
