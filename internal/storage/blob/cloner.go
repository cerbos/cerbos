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
	"strings"

	"go.uber.org/multierr"
	"go.uber.org/zap"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/util"
)

type clonerFS interface {
	fs.FS
	Remove(name string) error
	Create(name string) (io.WriteCloser, error)
	MkdirAll(path string, perm fs.FileMode) error
}

type (
	etagType      string
	fileNameType  string
	fileToETagMap map[fileNameType]etagType
)

type Cloner struct {
	bucket *blob.Bucket
	fsys   clonerFS
	log    *zap.SugaredLogger
	state  fileToETagMap
}

type CloneResult struct {
	all            fileToETagMap
	addedOrUpdated fileToETagMap
	deleted        fileToETagMap
	failuresCount  int
}

func (cr *CloneResult) isEmpty() bool {
	if cr == nil || (len(cr.addedOrUpdated) == 0 && len(cr.deleted) == 0) {
		return true
	}

	return false
}

func NewCloner(bucket *blob.Bucket, fsys clonerFS) (*Cloner, error) {
	c := &Cloner{
		bucket: bucket,
		log:    zap.S().Named("blob.cloner"),
		fsys:   fsys,
		state:  make(fileToETagMap),
	}

	return c, nil
}

func (c *Cloner) Clone(ctx context.Context) (*CloneResult, error) {
	iter := c.bucket.List(nil)
	addedOrUpdated := make(fileToETagMap)
	all := make(fileToETagMap)
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

		etag := etagType(fmt.Sprintf("%x", obj.MD5))
		all[fileNameType(file)] = etag

		if et, ok := c.state[fileNameType(file)]; ok && et == etag {
			continue
		}

		if err = c.downloadToFile(ctx, obj.Key, string(etag)); err != nil {
			c.log.Errorw("Failed to download file", "error", err, "etag", etag, "file", file)
			failuresCount++
		} else {
			addedOrUpdated[fileNameType(file)] = etag
		}
	}

	deleted := make(fileToETagMap)
	for file, etag := range c.state {
		if _, ok := all[file]; !ok {
			deleted[file] = etag
		}
	}

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
