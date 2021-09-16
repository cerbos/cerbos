// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"testing/fstest"
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
	}{
		{"a", false},
		{"b", false},
		{"c", false},
		{"d", true},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			file, err := OpenOneOfSupportedFiles(fsys, filepath.Join("testdata", tt.fileName))
			if err == nil {
				file.Close()
			}
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
