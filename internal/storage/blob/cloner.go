// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"bytes"
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

// clonerFS represents file system interface that used by the Cloner.
type clonerFS interface {
	fs.FS
	Remove(name string) error
	Create(name string) (io.WriteCloser, error)
	MkdirAll(path string, perm fs.FileMode) error
}

type infoType map[string][]byte

type Cloner struct {
	log    *zap.SugaredLogger
	bucket *blob.Bucket
	fsys   clonerFS
	info   infoType // map[path]eTag
}

// NewCloner creates an object to clone the bucket and saves
// supported files in the fsys.
func NewCloner(bucket *blob.Bucket, fsys clonerFS) (*Cloner, error) {
	c := &Cloner{
		bucket: bucket,
		log:    zap.S().Named("blob.cloner"),
		fsys:   fsys,
	}

	info, err := c.calculateInfo()
	c.log.Debugf("Checkout dir contains (%d) files", len(info))
	if err != nil {
		return nil, err
	}
	c.info = info
	return c, nil
}

type fileInfo struct {
	file string
	etag []byte
}

type CloneResult struct {
	updateOrAdd   []fileInfo
	delete        []string
	failuresCount int
}

func (cr *CloneResult) isEmpty() bool {
	return cr == nil || (len(cr.updateOrAdd) == 0 && len(cr.delete) == 0)
}

func (cr *CloneResult) failures() int {
	if cr == nil {
		return 0
	}

	return cr.failuresCount
}

func (c *Cloner) Clone(ctx context.Context) (*CloneResult, error) {
	iter := c.bucket.List(nil)
	info := make(infoType, len(c.info))
	cr := new(CloneResult)
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
		eTag := obj.MD5
		if util.FileType(file) == util.FileTypeNotIndexed {
			continue
		}
		info[file] = eTag
		if eTag != nil && bytes.Equal(eTag, c.info[file]) {
			continue
		}
		if err = c.downloadToFile(ctx, obj.Key, file); err != nil {
			c.log.Errorw("Failed to download file", "error", err, "file", file)
			cr.failuresCount++
		} else {
			cr.updateOrAdd = append(cr.updateOrAdd, fileInfo{file: file, etag: eTag})
		}
	}

	for key := range c.info {
		if _, ok := info[key]; !ok {
			c.log.Debugw("Removing file", "file", key)
			err := c.fsys.Remove(key)
			if err != nil {
				return nil, err
			}
			cr.delete = append(cr.delete, key)
		}
	}
	c.info = info
	return cr, nil
}

func (c *Cloner) downloadToFile(ctx context.Context, key, file string) (err error) {
	// Create the directories in the path
	dir := filepath.Dir(file)
	if err = c.fsys.MkdirAll(dir, 0o775); err != nil { //nolint:mnd
		return fmt.Errorf("failed to make dir %q: %w", dir, err)
	}

	// Set up the local file
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

func (c *Cloner) calculateInfo() (infoType, error) {
	result := make(infoType)
	err := fs.WalkDir(c.fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !util.IsSupportedFileType(path) {
			return nil
		}
		result[path] = nil
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}
