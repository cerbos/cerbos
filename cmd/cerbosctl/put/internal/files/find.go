// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"io/fs"
	"os"
	"path/filepath"
)

func Find(paths []string, recursive bool, callback func(filePath string) error, checkFileType func(fileName string) bool) error {
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
					switch {
					case recursive:
						return nil
					case walkPath != path:
						return fs.SkipDir
					}
				}

				if !checkFileType(d.Name()) {
					return nil
				}

				err = callback(walkPath)
				if err != nil {
					return err
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
