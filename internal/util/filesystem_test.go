// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"path/filepath"
	"testing"
	"testing/fstest"

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
			if got := IsSupportedTestFile(tt.fileName); got != tt.want {
				t.Errorf("IsSupportedTestFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenOneOfSupportedFiles(t *testing.T) {
	fsys := make(fstest.MapFS)
	file := &fstest.MapFile{Data: []byte{}}
	fsys["testdata/a.json"] = file
	fsys["testdata/b.yml"] = file
	fsys["testdata/c.yaml"] = file
	fsys["testdata/d.csv"] = file

	tests := []struct {
		fileName string
		wantErr  bool
		notExist bool
	}{
		{"a", false, false},
		{"b", false, false},
		{"c", false, false},
		{"d", false, true},
		{"not_exist", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			is := require.New(t)
			file, err := OpenOneOfSupportedFiles(fsys, filepath.Join("testdata", tt.fileName))
			if err == nil && file != nil {
				file.Close()
			}
			if tt.wantErr {
				is.Error(err)
				is.Nil(file)
			} else {
				is.NoError(err)
			}
			if tt.notExist {
				is.Nil(file)
			} else {
				is.NotNil(file)
			}
		})
	}
}
