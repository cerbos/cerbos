// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"io/fs"
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/txtar"
	"github.com/stretchr/testify/require"
)

func ExtractTxtArchiveToFS(t *testing.T, path string) fs.FS {
	t.Helper()

	dir := t.TempDir()
	ExtractTxtArchiveToDir(t, path, dir)
	return os.DirFS(dir)
}

func ExtractTxtArchiveToDir(t *testing.T, path, out string) {
	t.Helper()

	archive, err := txtar.ParseFile(path)
	require.NoError(t, err)

	require.NoError(t, txtar.Write(archive, out), "Failed to extract txtar")
}
