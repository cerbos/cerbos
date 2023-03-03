// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nlepage/go-tarfs"
	"google.golang.org/protobuf/proto"
)

var supportedFileTypes = map[string]struct{}{".yaml": {}, ".yml": {}, ".json": {}}

var ErrNoMatchingFiles = errors.New("no matching files")

// SchemasDirectory is the name of the special directory containing schemas. It is defined here to avoid an import loop.
const SchemasDirectory = "_schemas"

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

func getFsFromTar(r io.Reader) (fs.FS, error) {
	tfs, err := tarfs.New(r)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	return tfs, nil
}

// OpenDirectoryFS attempts to open a directory FS at the given location. It'll initially check if the target file is an archive,
// and if so, will return the appropriate type which implements the fs.FS interface.
func OpenDirectoryFS(path string) (fs.FS, error) {
	// We don't use `switch filepath.Ext(path)` here because it only suffixes from the final `.`, so `.tar.gz` won't be
	// correctly handled
	switch {
	case IsZip(path):
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open zip file: %w", err)
		}
		return zr, nil
	case IsTar(path):
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open tar file: %w", err)
		}
		defer f.Close()

		return getFsFromTar(f)
	case IsGzip(path):
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open gzip file: %w", err)
		}
		defer f.Close()

		gzr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("failed to open gzip file: %w", err)
		}
		defer gzr.Close()

		return getFsFromTar(gzr)
	}

	return os.DirFS(path), nil
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
		return nil, ErrNoMatchingFiles
	}

	file, err := fsys.Open(filepath)
	if err != nil {
		return nil, err
	}

	return file, nil
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
	schemaPath := strings.TrimPrefix(path, SchemasDirectory+"/")
	if schemaPath == path {
		return "", false
	}

	return schemaPath, true
}
