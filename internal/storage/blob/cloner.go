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

// clonerFS represents file system interface that used by the Cloner.
type clonerFS interface {
	fs.FS
	Remove(name string) error
	Create(name string) (io.WriteCloser, error)
	MkdirAll(path string, perm fs.FileMode) error
}

type symlinkToFileType map[string]string

type Cloner struct {
	log           *zap.SugaredLogger
	bucket        *blob.Bucket
	fsys          clonerFS
	symlinkToFile symlinkToFileType
}

// NewCloner creates an object to clone the bucket and saves
// supported files in the fsys.
func NewCloner(bucket *blob.Bucket, fsys clonerFS) (*Cloner, error) {
	c := &Cloner{
		bucket: bucket,
		log:    zap.S().Named("blob.cloner"),
		fsys:   fsys,
	}

	symlinkToFile, err := c.calculateSymlinkToFile()
	c.log.Debugf("Checkout dir contains (%d) files", len(symlinkToFile))
	if err != nil {
		return nil, err
	}
	c.symlinkToFile = symlinkToFile
	return c, nil
}

type deleteInfo struct {
	file    string
	symlink string
}

type fileInfo struct {
	file string
	etag []byte
}

type CloneResult struct {
	delete        map[string]deleteInfo
	fileToSymlink map[string]string
	updateOrAdd   []fileInfo
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
	cr := &CloneResult{
		delete: make(map[string]deleteInfo),
	}
	fileToSymlink := make(map[string]string)
	symlinkToFile := make(symlinkToFileType)
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

		if eTag == nil {
			return nil, fmt.Errorf("eTag for the blob object is not available: %w", err)
		}

		symlink := fmt.Sprintf("%x%s", eTag, filepath.Ext(file))
		fileToSymlink[file] = symlink
		symlinkToFile[symlink] = file
		if _, ok := c.symlinkToFile[symlink]; ok {
			continue
		}

		if err = c.downloadToFile(ctx, obj.Key, symlink); err != nil {
			c.log.Errorw("Failed to download file", "error", err, "key", obj.Key, "file", symlink)
			cr.failuresCount++
		} else {
			cr.updateOrAdd = append(cr.updateOrAdd, fileInfo{file: file, etag: eTag})
		}
	}

	for symlink, file := range c.symlinkToFile {
		if _, ok := symlinkToFile[symlink]; !ok {
			cr.delete[file] = deleteInfo{
				file:    file,
				symlink: symlink,
			}
		}
	}

	cr.fileToSymlink = fileToSymlink
	c.symlinkToFile = symlinkToFile
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

func (c *Cloner) calculateSymlinkToFile() (symlinkToFileType, error) {
	result := make(symlinkToFileType)
	err := fs.WalkDir(c.fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !util.IsSupportedFileType(path) {
			return nil
		}
		result[path] = ""
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}
