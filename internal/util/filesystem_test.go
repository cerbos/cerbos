// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util_test

import (
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSupportedTestFile(t *testing.T) {
	tests := []struct {
		fileName string
		want     bool
	}{
		{"e_test.yml", true},
		{"e_test.yaml", true},
		{"e_test.json", true},
		{"_test.json", true},
		// Unsupported files
		{"e_test.yl", false},
		{"e_test", false},
		{"e_bar.yaml", false},
		{".yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			if got := util.IsSupportedTestFile(tt.fileName); got != tt.want {
				t.Errorf("IsSupportedTestFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOneOfSupportedFileNames(t *testing.T) {
	fsys := make(fstest.MapFS)
	file := &fstest.MapFile{Data: []byte{}}
	fsys["testdata/a.json"] = file
	fsys["testdata/b.yml"] = file
	fsys["testdata/c.yaml"] = file
	fsys["testdata/d.csv"] = file

	tests := []struct {
		fileName, expectedNewFileName string
		wantErr                       bool
	}{
		{"a", "testdata/a.json", false},
		{"b", "testdata/b.yml", false},
		{"c", "testdata/c.yaml", false},
		{"d", "", true},
		{"not_exist", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			is := require.New(t)
			newName, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join("testdata", tt.fileName))
			if tt.wantErr {
				is.Error(err)
			} else {
				is.NoError(err)
				is.Equal(tt.expectedNewFileName, newName)
			}
		})
	}
}

func TestIsJSONFileTypeExt(t *testing.T) {
	tests := []struct {
		fileName string
		want     bool
	}{
		{"e_test.json", true},
		{"_test.json", true},
		// Unsupported files
		{"e_test.yml", false},
		{"e_test.yaml", false},
		{"e_test.yl", false},
		{"e_test", false},
		{"e_bar.yaml", false},
		{".yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			if got := util.IsJSONFileTypeExt(tt.fileName); got != tt.want {
				t.Errorf("IsJSONFileTypeExt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileType(t *testing.T) {
	tests := map[util.IndexedFileType][]string{
		util.FileTypePolicy: {
			"foo/bar.json",
			"foo/bar.yaml",
			"foo/bar.yml",
			"foo/_schemas/bar.yaml",
		},
		util.FileTypeSchema: {
			"_schemas/foo/bar.json",
			"_schemas/foo/testdata/bar.json",
		},
		util.FileTypeNotIndexed: {
			".foo/bar.json",          // in hidden directory
			"foo/.bar.yaml",          // hidden file
			"foo/bar_test.yml",       // test file
			"foo/testdata/bar.yaml",  // in testdata directory
			"foo/bar.yam",            // unsupported policy extension
			"_schemas/.foo/bar.json", // in hidden directory
			"_schemas/foo/.bar.json", // hidden file
			"_schemas/foo/bar.yaml",  // unsupported schema extension
		},
	}

	for want, paths := range tests {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				assert.Equal(t, want, util.FileType(path))
			})
		}
	}
}

func TestRelativeSchemaPath(t *testing.T) {
	tests := []struct {
		path       string
		wantResult string
		wantOK     bool
	}{
		{"_schemas/foo/bar.json", "foo/bar.json", true},
		{"foo/bar.yaml", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result, ok := util.RelativeSchemaPath(tt.path)
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestIsArchiveFile(t *testing.T) {
	tests := []struct {
		fileName string
		want     bool
	}{
		{"foo.zip", true},
		{"foo.tar", true},
		{"foo.tgz", true},
		{"foo.tar.gz", true},
		// Unsupported files
		{"foo/", false},
		{"foo.yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			if got := util.IsArchiveFile(tt.fileName); got != tt.want {
				t.Errorf("IsArchiveFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
