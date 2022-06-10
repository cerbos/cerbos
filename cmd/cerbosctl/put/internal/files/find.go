// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cerbos/cerbos/internal/util"
)

func Find(paths []string, recursive bool, fileType util.IndexedFileType, callback func(filePath string) error) error {
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
					return callback(walkPath)
				}

				return nil
			})
			if err != nil {
				return err
			}
		} else {
			err = callback(path)
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
