// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"go.uber.org/multierr"
)

var supportedFileTypes = map[string]struct{}{".yaml": {}, ".yml": {}, ".json": {}}

var ErrNoMatchingFiles = errors.New("no matching files")

// SchemasDirectory is the name of the special directory containing schemas. It is defined here to avoid an import loop.
const SchemasDirectory = "_schemas"

// TestDataDirectory is the name of the special directory containing test fixtures. It is defined here to avoid an import loop.
const TestDataDirectory = "testdata"

const PathSeparator = string(filepath.Separator)

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

// IsJSONFileTypeExt returns true if the given file has a json file extension.
func IsJSONFileTypeExt(fileName string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	return ext == ".json"
}

// IsSupportedFileType returns true if the given file has a supported file extension.
func IsSupportedFileType(fileName string) bool {
	_, ok := IsSupportedFileTypeExt(fileName)
	return ok
}

func IsHidden(fileName string) bool {
	switch fileName {
	case ".", "..":
		return false
	default:
		return strings.HasPrefix(fileName, ".")
	}
}

func PathIsHidden(path string) bool {
	tmpPath := path
	for {
		dir, file := filepath.Split(tmpPath)
		if strings.HasPrefix(file, ".") || strings.HasPrefix(dir, ".") {
			return true
		}

		dir = strings.TrimSuffix(dir, PathSeparator)
		if dir == "" {
			return false
		}

		tmpPath = dir
	}
}

func IsZip(fileName string) bool {
	return strings.HasSuffix(fileName, ".zip")
}

func IsTar(fileName string) bool {
	return strings.HasSuffix(fileName, ".tar")
}

func IsGzip(fileName string) bool {
	return strings.HasSuffix(fileName, ".tar.gz") || strings.HasSuffix(fileName, ".tgz")
}

func IsArchiveFile(fileName string) bool {
	return IsZip(fileName) || IsTar(fileName) || IsGzip(fileName)
}

type ClosableFS struct {
	fs.FS
	io.Closer
	closers []io.Closer
}

func (cfs ClosableFS) Close() (outErr error) {
	for _, c := range cfs.closers {
		outErr = multierr.Append(outErr, c.Close())
	}

	return outErr
}

// GetOneOfSupportedFileNames attempts to retrieve a fileName adding supported extensions.
func GetOneOfSupportedFileNames(fsys fs.FS, fileName string) (string, error) {
	matches, err := fs.Glob(fsys, fileName+".*")
	if err != nil {
		return "", err
	}

	for _, match := range matches {
		if IsSupportedFileType(match) {
			return match, nil
		}
	}

	return "", ErrNoMatchingFiles
}

type IndexedFileType uint8

const (
	FileTypeNotIndexed IndexedFileType = iota
	FileTypePolicy
	FileTypeSchema
)

// FileType categorizes the given path according to how it will be treated by the index.
// The path must be "/"-separated and relative to the root policies directory.
func FileType(path string) IndexedFileType {
	segments := strings.Split(path, "/")
	fileName := segments[len(segments)-1]

	inSchemas := segments[0] == SchemasDirectory

	for _, segment := range segments {
		if IsHidden(segment) || (segment == TestDataDirectory && !inSchemas) {
			return FileTypeNotIndexed
		}
	}

	if inSchemas {
		if IsJSONFileTypeExt(fileName) {
			return FileTypeSchema
		}

		return FileTypeNotIndexed
	}

	if IsSupportedFileType(fileName) && !IsSupportedTestFile(fileName) {
		return FileTypePolicy
	}

	return FileTypeNotIndexed
}

// RelativeSchemaPath returns the given path within the top-level schemas directory,
// and a flag to indicate whether the path was actually contained in that directory.
// The path must be "/"-separated and relative to the root policies directory.
func RelativeSchemaPath(path string) (string, bool) {
	schemaPath, ok := strings.CutPrefix(path, SchemasDirectory+"/")
	if !ok {
		schemaPath = ""
	}

	return schemaPath, ok
}
