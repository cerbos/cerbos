// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"text/template"

	"github.com/google/go-cmp/cmp"
	"github.com/rogpeppe/go-internal/txtar"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

var updateGolden = flag.Bool("updateGolden", false, "Update the golden values for the tests")

type TestCase struct {
	*privatev1.VerifyTestCase
	archive *txtar.Archive
	want    *policyv1.TestResults
}

func TestVerify(t *testing.T) {
	testCases := test.LoadTestCases(t, filepath.Join("verify", "cases"))

	eng := mkEngine(t)

	// go test -v -tags=tests ./internal/verify/... --args -updateGolden
	if *updateGolden {
		updateGoldenFiles(t, eng, testCases)
		// reload to populate with new golden values
		testCases = test.LoadTestCases(t, filepath.Join("verify", "cases"))
	}

	for _, tcase := range testCases {
		tc := readVerifyTestCase(t, tcase)
		t.Run(tcase.Name, func(t *testing.T) {
			have, err := runPolicyTests(t, eng, tc)
			t.Log(protojson.Format(have))
			if tc.WantErr {
				require.Error(t, err, "Expected error")
				return
			}

			require.NoError(t, err, "Test suite failed")
			require.Empty(t, cmp.Diff(tc.want, have,
				protocmp.Transform(),
				protocmp.SortRepeated(func(a, b *policyv1.TestResults_Suite) bool {
					return a.File > b.File
				}),
				cmp.Comparer(func(s1, s2 string) bool {
					return strings.ReplaceAll(s1, "\u00a0", " ") == strings.ReplaceAll(s2, "\u00a0", " ")
				}),
			))
		})
	}
}

func updateGoldenFiles(t *testing.T, eng *engine.Engine, testCases []test.Case) {
	t.Helper()

	for _, tcase := range testCases {
		tc := readVerifyTestCase(t, tcase)
		if tc.WantErr {
			continue
		}

		result, err := runPolicyTests(t, eng, tc)
		require.NoError(t, err, "Failed to produce golden file for %q due to error from test run: %v", tcase.SourceFile, err)

		test.WriteGoldenFile(t, tcase.SourceFile+".golden", result)
	}
}

func readVerifyTestCase(t *testing.T, tcase test.Case) *TestCase {
	t.Helper()

	outTC := &TestCase{VerifyTestCase: &privatev1.VerifyTestCase{}}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(tcase.Input), outTC.VerifyTestCase), "Failed to read verify test case")

	if golden, ok := tcase.Want["golden"]; ok {
		outTC.want = &policyv1.TestResults{}
		require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(golden), outTC.want), "Failed to read golden result")
	}

	if input, ok := tcase.Want["input"]; ok {
		outTC.archive = txtar.Parse(input)
	}

	return outTC
}

func runPolicyTests(t *testing.T, eng *engine.Engine, tc *TestCase) (*policyv1.TestResults, error) {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, txtar.Write(tc.archive, dir), "Failed to expand archive")

	config := tc.GetConfig()

	return Verify(t.Context(), os.DirFS(dir), eng, Config{
		ExcludedResourcePolicyFQNs:  util.ToStringSet(config.GetExcludedResourcePolicyFqns()),
		ExcludedPrincipalPolicyFQNs: util.ToStringSet(config.GetExcludedPrincipalPolicyFqns()),
		IncludedTestNamesRegexp:     config.GetIncludedTestNamesRegexp(),
	})
}

const (
	fauxPrincipals = `{"principals":{"harry":{"id":"harry","roles":["user"]}}}`
	principals     = `
---
principals:
  harry:
    id: harry
    policyVersion: '0210210'
    roles:
      - employee
    attr: &harry_attr
      department: marketing
      geography: GB
      team: design
  maggie:
    id: maggie
    policyVersion: '0210210'
    roles:
      - employee
      - manager
    attr:
      << : *harry_attr
      managed_geographies: "GB"
`
	fauxResources = `{"resources":{"draft_leave_request":{"id": "xx11", "kind": "leave_request"}}}`
	resources     = `
---
resources:
  draft_leave_request: &leave_request
    id: xx125
    kind: leave_request
    policyVersion: '20210210'
    attr: &leave_request_attr
      department: marketing
      geography: GB
      id: XX125
      owner: harry
      status: DRAFT
      team: design
  pending_leave_request:
    << : *leave_request
    attr:
      << : *leave_request_attr
      status: PENDING_APPROVAL
`
	testSuiteTemplate = `
---
name: TestSuite
description: Tests for verifying something
tests:
  - name: Harry's draft leave request
    input: &input
      actions:
        - create
        - "view:public"
        - approve
      resources:
        - draft_leave_request
      principals:
        - harry
        - maggie
    expected:
      - principal: harry
        resource: draft_leave_request
        actions:
          create: EFFECT_ALLOW
          "view:public": EFFECT_ALLOW
          approve: EFFECT_DENY
      - principal: maggie
        resource: draft_leave_request
        actions:
          create: EFFECT_DENY
          "view:public": EFFECT_ALLOW
          approve: EFFECT_DENY
  - name: Harry's pending leave request
    input:
      << : *input
      resources:
        - pending_leave_request
    expected:
      - principal: harry
        resource: pending_leave_request
        actions:
          create: EFFECT_ALLOW
          "view:public": EFFECT_ALLOW
          approve: EFFECT_DENY
      - principal: maggie
        resource: pending_leave_request
        actions:
          create: EFFECT_DENY
          "view:public": EFFECT_ALLOW
          approve: EFFECT_ALLOW
{{.Principals}}
{{.Resources}}
`
)

var (
	ts           *template.Template
	initTemplate sync.Once
)

func genTable(t *testing.T, embedResources, embedPrincipals bool) string {
	t.Helper()
	trimSpaceYAML := func(s string) string { // Removes all lines until a first root-level key
		lines := strings.Split(s, "\n")
		i := 0
		for ; i < len(lines); i++ {
			s := strings.TrimSpace(lines[i])
			if s != "" && s != "---" {
				break
			}
		}
		return strings.Join(lines[i:], "\n")
	}

	initTemplate.Do(func() {
		var err error
		ts, err = template.New("suite").Parse(testSuiteTemplate)
		require.NoError(t, err)
	})
	require.NotNil(t, ts)

	data := struct{ Principals, Resources string }{}
	if embedPrincipals {
		data.Principals = trimSpaceYAML(principals)
	}
	if embedResources {
		data.Resources = trimSpaceYAML(resources)
	}

	var sb strings.Builder
	err := ts.Execute(&sb, data)
	require.NoError(t, err)
	return sb.String()
}

func newMapFile(s string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(s)}
}

func Test_doVerify(t *testing.T) {
	eng := mkEngine(t)
	const (
		embedded = iota
		external
		mixed
	)
	options := []int{embedded, external, mixed}
	optionTitles := map[int]string{embedded: "EMBEDDED", external: "EXTERNAL", mixed: "MIXED"}
	for _, optionPrincipals := range options {
		for _, optionResources := range options {
			t.Run(fmt.Sprintf("principals = %v, resources = %v", optionTitles[optionPrincipals], optionTitles[optionResources]), func(t *testing.T) {
				fsys := make(fstest.MapFS)
				switch optionResources {
				case external:
					fsys[filepath.Join(util.TestDataDirectory, resourcesFileName)+".yaml"] = newMapFile(resources)
				case mixed:
					fsys[filepath.Join(util.TestDataDirectory, resourcesFileName)+".json"] = newMapFile(fauxResources)
				}
				switch optionPrincipals {
				case external:
					fsys[filepath.Join(util.TestDataDirectory, principalsFileName)+".yaml"] = newMapFile(principals)
				case mixed:
					fsys[filepath.Join(util.TestDataDirectory, principalsFileName)+".json"] = newMapFile(fauxPrincipals)
				}
				table := genTable(t, optionResources != external, optionPrincipals != external)
				fsys["leave_request_test.yaml"] = newMapFile(table)
				result, err := Verify(t.Context(), fsys, eng, Config{})
				is := require.New(t)
				is.NoError(err)
				is.Len(result.Suites, 1)
				is.Equal(policyv1.TestResults_RESULT_PASSED, result.Suites[0].Summary.OverallResult)
				is.Equal(policyv1.TestResults_RESULT_PASSED, result.Summary.OverallResult)
			})
		}
	}
	t.Run("Should fail for faux principals", func(t *testing.T) {
		fsys := make(fstest.MapFS)
		fsys[filepath.Join(util.TestDataDirectory, resourcesFileName)+".yaml"] = newMapFile(resources)
		fsys[filepath.Join(util.TestDataDirectory, principalsFileName)+".json"] = newMapFile(fauxPrincipals)

		table := genTable(t, false, false)
		fsys["leave_request_test.yaml"] = newMapFile(table)
		result, err := Verify(t.Context(), fsys, eng, Config{})
		is := require.New(t)
		is.NoError(err)
		is.Len(result.Suites, 1)
		is.Equal(policyv1.TestResults_RESULT_ERRORED, result.Suites[0].Summary.OverallResult)
		is.Equal(policyv1.TestResults_RESULT_ERRORED, result.Summary.OverallResult)
	})
	t.Run("Should fail for faux resources", func(t *testing.T) {
		fsys := make(fstest.MapFS)
		fsys[filepath.Join(util.TestDataDirectory, resourcesFileName)+".json"] = newMapFile(fauxResources)
		fsys[filepath.Join(util.TestDataDirectory, principalsFileName)+".yaml"] = newMapFile(principals)

		table := genTable(t, false, false)
		fsys["leave_request_test.yaml"] = newMapFile(table)
		result, err := Verify(t.Context(), fsys, eng, Config{})
		is := require.New(t)
		is.NoError(err)
		is.Len(result.Suites, 1)
		is.Equal(policyv1.TestResults_RESULT_ERRORED, result.Suites[0].Summary.OverallResult)
		is.Equal(policyv1.TestResults_RESULT_ERRORED, result.Summary.OverallResult)
	})
	t.Run("Several subdirectories with test fixtures", func(t *testing.T) {
		fsys := make(fstest.MapFS)
		ts := genTable(t, false, false)
		for _, dir := range []string{"a", "b", "c"} {
			d := filepath.Join(dir, util.TestDataDirectory)
			fsys[d+"/principals.yaml"] = newMapFile(principals)
			fsys[d+"/resources.yaml"] = newMapFile(resources)
			fsys[dir+"/leave_request_test.yaml"] = newMapFile(ts)
		}

		result, err := Verify(t.Context(), fsys, eng, Config{})
		is := require.New(t)
		is.NoError(err)
		is.Len(result.Suites, 3)
		for i := range result.Suites {
			is.Len(result.Suites[i].TestCases, 2)
			is.Len(result.Suites[i].TestCases[0].Principals, 2)
			is.Len(result.Suites[i].TestCases[0].Principals[0].Resources, 1)
		}
		is.Equal(policyv1.TestResults_RESULT_PASSED, result.Summary.OverallResult)
	})
	t.Run("Simple test", func(t *testing.T) {
		fsys := make(fstest.MapFS)
		ts := genTable(t, false, false)
		fsys[filepath.Join(util.TestDataDirectory, resourcesFileName)+".yaml"] = newMapFile(resources)
		fsys[filepath.Join(util.TestDataDirectory, principalsFileName)+".yaml"] = newMapFile(principals)
		fsys["leave_request_test.yaml"] = newMapFile(ts)

		result, err := Verify(t.Context(), fsys, eng, Config{})
		is := require.New(t)
		is.NoError(err)
		is.Len(result.Suites, 1)
		is.Equal(policyv1.TestResults_RESULT_PASSED, result.Suites[0].Summary.OverallResult)
		is.Equal(policyv1.TestResults_RESULT_PASSED, result.Summary.OverallResult)
	})
}

func mkEngine(t *testing.T) *engine.Engine {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(t.Context())
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	mgr, err := compile.NewManager(ctx, store)
	require.NoError(t, err)

	protoRT := ruletable.NewProtoRuletable()
	require.NoError(t, ruletable.LoadPolicies(ctx, protoRT, mgr))

	ruleTable, err := ruletable.NewRuleTable(index.NewMem(), protoRT)
	require.NoError(t, err)

	schemaMgr, err := schema.New(ctx, store)
	require.NoError(t, err)

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, mgr, schemaMgr)
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
