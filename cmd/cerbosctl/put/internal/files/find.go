// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cerbos/cerbos/internal/util"
)

type Found struct {
	AbsolutePath string
	RelativePath string
}

func Find(paths []string, recursive bool, fileType util.IndexedFileType, callback func(file Found) error) error {
	for _, path := range paths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return err
		}

		//nolint:nestif
		if fileInfo.IsDir() {
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

					return callback(Found{
						AbsolutePath: walkPath,
						RelativePath: filepath.ToSlash(relativePath),
					})
				}

				return nil
			})
			if err != nil {
				return err
			}
		} else {
			err = callback(Found{
				AbsolutePath: path,
				RelativePath: filepath.Base(path),
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
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
