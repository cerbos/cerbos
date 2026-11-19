// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package conditions_test

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/conditions"
)

var updateGolden = flag.Bool("updateGolden", false, "Update the golden values for the tests")

// TestStdEnvSurface pins the functions and macros available in policy conditions.
// A cel-go upgrade can add functions to unversioned extension libraries, which makes them
// available to policy authors and query plans. This test makes such changes visible.
// To update the golden file after reviewing the change, run
// `go test -tags=tests ./internal/conditions/... -run TestStdEnvSurface --args -updateGolden`.
func TestStdEnvSurface(t *testing.T) {
	goldenFile := filepath.Join("testdata", "stdenv_surface.golden")

	var have []string
	for name, fn := range conditions.StdEnv.Functions() {
		for _, o := range fn.OverloadDecls() {
			have = append(have, "function "+name+" "+o.ID())
		}
	}
	for _, m := range conditions.StdEnv.Macros() {
		have = append(have, "macro "+m.MacroKey())
	}
	slices.Sort(have)
	got := strings.Join(have, "\n") + "\n"

	if *updateGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenFile), 0o755))
		require.NoError(t, os.WriteFile(goldenFile, []byte(got), 0o600))
		return
	}

	want, err := os.ReadFile(goldenFile)
	require.NoError(t, err, "Run with -updateGolden to create the golden file")
	require.Equal(t, string(want), got, "Functions or macros changed. Review, update the docs and changelog, then run with -updateGolden")
}
