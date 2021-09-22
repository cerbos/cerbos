// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"
)

var supportedFileTypes = map[string]struct{}{".yaml": {}, ".yml": {}, ".json": {}}

// TestDataDirectory is the name of the special directory containing test fixtures. It is defined here to avoid an import loop.
const TestDataDirectory = "testdata"

// IsSupportedTestFile return true if the given file is a supported test file name, i.e. "*_test.{yaml,yml,json}".
func IsSupportedTestFile(fileName string) bool {
	if ext, ok := IsSupportedFileTypeExt(fileName); ok {
		f := strings.ToLower(fileName)
		return strings.HasSuffix(f[:len(f)-len(ext)], "_test")
	}
	return false
}

// IsSupportedFileTypeExt returns true and a file extension if the given file has a supported file extension.
func IsSupportedFileTypeExt(fileName string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(fileName))
	_, exists := supportedFileTypes[ext]

	return ext, exists
}

// IsSupportedFileType returns true if the given file has a supported file extension.
func IsSupportedFileType(fileName string) bool {
	_, ok := IsSupportedFileTypeExt(fileName)
	return ok
}

// LoadFromJSONOrYAML reads a JSON or YAML encoded protobuf from the given path.
func LoadFromJSONOrYAML(fsys fs.FS, path string, dest proto.Message) error {
	f, err := fsys.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}

	defer f.Close()

	return ReadJSONOrYAML(f, dest)
}

// OpenOneOfSupportedFiles attempts to open a fileName adding supported extensions.
func OpenOneOfSupportedFiles(fsys fs.FS, fileName string) (fs.File, error) {
	matches, err := fs.Glob(fsys, fileName+".*")
	if err != nil {
		return nil, err
	}
	var filepath string
	for _, match := range matches {
		if IsSupportedFileType(match) {
			filepath = match
			break
		}
	}
	if filepath == "" {
		return nil, nil
	}

	file, err := fsys.Open(filepath)
	if err != nil {
		return nil, err
	}

	return file, nil
}
