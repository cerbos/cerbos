// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/util"
)

type callback func(file Found) error

func Find(paths []string, recursive bool, fileType util.IndexedFileType, callback callback) error {
	for _, path := range paths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return err
		}

		switch {
		case util.IsZip(path):
			err = fromZip(path, fileType, callback)
			if err != nil {
				return err
			}
		case fileInfo.IsDir():
			err := filepath.WalkDir(path, func(walkPath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					if (walkPath != path && !recursive) ||
						util.IsHidden(d.Name()) ||
						(fileType == util.FileTypePolicy && d.Name() == util.TestDataDirectory) {
						return fs.SkipDir
					}

					return nil
				}

				if isSupportedFile(d.Name(), fileType) {
					relativePath, err := filepath.Rel(path, walkPath)
					if err != nil {
						return err
					}

					return callback(foundFileImpl{
						absolutePath: walkPath,
						relativePath: filepath.ToSlash(relativePath),
					})
				}

				return nil
			})
			if err != nil {
				return err
			}
		default:
			err = callback(foundFileImpl{
				absolutePath: path,
				relativePath: filepath.Base(path),
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func fromZip(path string, fileType util.IndexedFileType, callback callback) error {
	zipFile, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", path, err)
	}
	defer zipFile.Close()

	var errs error
	for _, f := range zipFile.File {
		if f.FileInfo().IsDir() {
			continue
		}

		if !isSupportedFile(filepath.Base(f.Name), fileType) {
			continue
		}

		if isInHiddenDir(f.Name) {
			continue
		}

		if _, ok := util.RelativeSchemaPath(f.Name); fileType == util.FileTypePolicy && ok {
			continue
		}

		if err := callback(foundZipImpl{
			relativePath: f.Name,
			zipFile:      zipFile,
		}); err != nil {
			errs = multierr.Append(errs, err)
		}
	}

	return errs
}

func isInHiddenDir(path string) bool {
	for _, part := range strings.Split(filepath.Dir(path), string(filepath.Separator)) {
		if util.IsHidden(part) {
			return true
		}
	}

	return false
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
