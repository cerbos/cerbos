// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal_test

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/cmd/cerbosctl/store/export/internal"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

var archiveFormats = [3]string{"tar.gz", "tar", "zip"}

func TestExporter(t *testing.T) {
	testCases := []struct {
		testFile string
	}{
		{
			"single_policy.txt",
		},
		{
			"single_schema.txt",
		},
		{
			"scope.txt",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testFile, func(t *testing.T) {
			dir := t.TempDir()
			test.ExtractTxtArchiveToDir(t, filepath.Join("testdata", testCase.testFile), dir)
			files := walkDir(t, dir)

			exportDir := t.TempDir()
			e, err := internal.NewExporter(exportDir)

			t.Run("dir", func(t *testing.T) {
				require.NoError(t, err)

				for path, file := range files {
					exportFile(t, e, path, file)
				}

				for path, expected := range files {
					actual, err := os.ReadFile(filepath.Join(exportDir, path))
					require.NoError(t, err)

					require.YAMLEq(t, string(expected), string(actual))
				}
			})

			for _, archiveFormat := range archiveFormats {
				exportArchive := filepath.Join(t.TempDir(), fmt.Sprint("archive", archiveFormat))
				e, err := internal.NewExporter(exportArchive)
				require.NoError(t, err)

				t.Run(archiveFormat, func(t *testing.T) {
					for path, file := range files {
						exportFile(t, e, path, file)
					}

					archiveFS, err := util.OpenDirectoryFS(exportArchive)
					require.NoError(t, err)

					for path, expected := range files {
						actual, err := archiveFS.Open(path)
						require.NoError(t, err)

						actualBytes, err := io.ReadAll(actual)
						require.NoError(t, err)

						require.YAMLEq(t, string(expected), string(actualBytes))
					}
				})
			}
		})
	}
}

func exportFile(t *testing.T, e internal.Exporter, path string, file []byte) {
	t.Helper()

	if strings.HasPrefix(path, util.SchemasDirectory) {
		err := e.WriteJSON(path, file)
		require.NoError(t, err)
	} else {
		err := e.WriteYAML(path, file)
		require.NoError(t, err)
	}
}

func walkDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()

	fsys := os.DirFS(dir)
	files := make(map[string][]byte)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)

		if d.IsDir() {
			return nil
		}

		if _, ok := util.IsSupportedFileTypeExt(d.Name()); !ok {
			t.Errorf("Unsupported file: %s", d.Name())
		}

		f, err := fs.ReadFile(fsys, path)
		require.NoError(t, err)

		files[path] = f
		return nil
	})
	require.NoError(t, err)

	return files
}
