package util

import (
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestIsSupportedTestFile(t *testing.T) {
	tests := []struct {
		fileName string
		want bool
	}{
		{"e_test.yml", true},
		{"e_test.yaml", true},
		{"e_test.json", true},
		// Unsupported files
		{"e_test.yl", false},
		{"e_test", false},
		{"e_bar.yaml", false},
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
		fileName    string
		wantErr bool
	}{
		{"a", false},
		{"b", false},
		{"c", false},
		{"d", true},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			file, err := OpenOneOfSupportedFiles(fsys, filepath.Join("testdata", tt.fileName))
			if (err != nil) != tt.wantErr {
				t.Errorf("OpenOneOfSupportedFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				file.Close()
			}
		})
	}
}