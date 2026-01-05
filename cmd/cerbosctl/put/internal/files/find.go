// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cerbos/cerbos/internal/util"
)

type callback func(file Found) error

func Find(paths []string, recursive bool, fileType util.IndexedFileType, callback callback) error {
	for _, path := range paths {
		if err := find(path, recursive, fileType, callback); err != nil {
			return fmt.Errorf("failed to find: %w", err)
		}
	}

	return nil
}

func find(path string, recursive bool, fileType util.IndexedFileType, callback callback) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	switch {
	case fileInfo.IsDir() || util.IsArchiveFile(path):
		fsys, err := util.OpenDirectoryFS(path)
		if err != nil {
			return err
		}
		if err := doFind(fsys, fileType, recursive, callback); err != nil {
			return fmt.Errorf("failed to find files %s: %w", path, err)
		}
	default:
		fis := foundInFs{
			path: filepath.Base(path),
			id:   filepath.Base(path),
			fsys: os.DirFS(filepath.Dir(path)),
		}

		if id, ok := util.RelativeSchemaPath(path); fileType == util.FileTypeSchema && ok {
			fis.id = id
		}

		err = callback(fis)
		if err != nil {
			return err
		}
	}

	return nil
}

func doFind(fsys fs.FS, fileType util.IndexedFileType, recursive bool, callback callback) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if !recursive ||
				util.IsHidden(d.Name()) ||
				(fileType == util.FileTypePolicy && d.Name() == util.TestDataDirectory) {
				return fs.SkipDir
			}

			return nil
		}

		fis := foundInFs{
			fsys: fsys,
			id:   filepath.ToSlash(path),
			path: filepath.ToSlash(path),
		}

		if id, ok := util.RelativeSchemaPath(path); fileType == util.FileTypePolicy && ok {
			return nil
		} else if fileType == util.FileTypeSchema && ok {
			fis.id = id
		}

		if isSupportedFile(d.Name(), fileType) {
			return callback(fis)
		}

		return nil
	})
}

func isSupportedFile(fileName string, fileType util.IndexedFileType) bool {
	if util.IsHidden(fileName) {
		return false
	}

	switch fileType {
	case util.FileTypePolicy:
		return util.IsSupportedFileType(fileName) && !util.IsSupportedTestFile(fileName)

	case util.FileTypeSchema:
		return util.IsJSONFileTypeExt(fileName)

	default:
		return false
	}
}
