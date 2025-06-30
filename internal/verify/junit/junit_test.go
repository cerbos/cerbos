// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package junit_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rogpeppe/go-internal/txtar"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/cerbos/cerbos/internal/verify/junit"
)

const (
	listIndent = 2
	verbose    = true
)

var updateGolden = flag.Bool("updateGolden", false, "Update the golden values for the tests")

func TestJUnit(t *testing.T) {
	testCases := test.LoadTestCases(t, filepath.Join("verify_junit", "cases"))
	eng := mkEngine(t)

	// go test -v -tags=tests ./internal/verify/junit... --args -updateGolden
	if *updateGolden {
		updateGoldenFiles(t, eng, testCases)
		// reload to populate with new golden values
		testCases = test.LoadTestCases(t, filepath.Join("verify_junit", "cases"))
	}

	for _, tcase := range testCases {
		tc := readTestCase(t, tcase)
		t.Run(tcase.Name, func(t *testing.T) {
			results, err := runPolicyTests(t, eng, tc.archive)
			require.NoError(t, err)
			result, err := junit.Build(results, verbose)
			require.NoError(t, err, "Test suite failed")
			have := marshalTestSuites(t, result)

			require.NoError(t, err)
			require.Empty(t, cmp.Diff(tc.want, have))
		})
	}
}

func marshalTestSuites(t *testing.T, testSuites *junit.TestSuites) string {
	t.Helper()

	m, err := xml.MarshalIndent(testSuites, "", strings.Repeat(" ", listIndent))
	require.NoError(t, err)

	return string(m)
}

func updateGoldenFiles(t *testing.T, eng *engine.Engine, testCases []test.Case) {
	t.Helper()

	for _, tcase := range testCases {
		tc := readTestCase(t, tcase)
		if tc.WantErr {
			continue
		}

		results, err := runPolicyTests(t, eng, tc.archive)
		require.NoError(t, err)

		result, err := junit.Build(results, verbose)
		require.NoError(t, err)

		writeGoldenFile(t, tcase.SourceFile+".golden", result)
	}
}

func writeGoldenFile(t *testing.T, path string, result *junit.TestSuites) {
	t.Helper()

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	output := marshalTestSuites(t, result)
	_, err = f.WriteString(output)
	require.NoError(t, err)
}

func readTestCase(t *testing.T, tcase test.Case) *TestCase {
	t.Helper()

	outTC := &TestCase{
		VerifyTestCase: &privatev1.VerifyTestCase{},
	}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(tcase.Input), outTC.VerifyTestCase), "Failed to read verify test case")

	if golden, ok := tcase.Want["golden"]; ok {
		var ts junit.TestSuites
		err := xml.Unmarshal(golden, &ts)
		require.NoError(t, err)
		outTC.want = string(golden)
	}

	if input, ok := tcase.Want["input"]; ok {
		outTC.archive = txtar.Parse(input)
	}

	return outTC
}

func mkEngine(t *testing.T) *engine.Engine {
	t.Helper()

	dir := test.PathToDir(t, filepath.Join("verify_junit", "store"))

	ctx, cancelFunc := context.WithCancel(t.Context())
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	schemaMgr, err := schema.New(ctx, store)
	require.NoError(t, err)

	mgr, err := compile.NewManager(ctx, store, schemaMgr)
	require.NoError(t, err)

	rt := ruletable.NewRuletable()
	require.NoError(t, ruletable.LoadFromPolicyLoader(ctx, rt, mgr))

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, mgr, schemaMgr)
	require.NoError(t, err)

	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader:      mgr,
		RuleTableManager:  ruletableMgr,
		SchemaMgr:         schemaMgr,
		AuditLog:          audit.NewNopLog(),
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})
	require.NoError(t, err)

	return eng
}

func runPolicyTests(t *testing.T, eng *engine.Engine, archive *txtar.Archive) (*policyv1.TestResults, error) {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, txtar.Write(archive, dir), "Failed to expand archive")

	return verify.Verify(t.Context(), os.DirFS(dir), eng, verify.Config{
		Trace: verbose,
	})
}

type TestCase struct {
	*privatev1.VerifyTestCase
	archive *txtar.Archive
	want    string
}
