// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"text/template"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestVerify(t *testing.T) {
	eng := mkEngine(t)

	conf := Config{
		TestsDir: test.PathToDir(t, "verify"),
	}

	// TODO: (cell) add more test cases
	result, err := Verify(context.Background(), eng, conf)
	is := require.New(t)
	is.NoError(err)
	is.NotZero(len(result.Results), "test results")
	is.False(result.Results[0].Skipped)
	is.False(result.Failed)
}

const principals = `
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

const resources = `
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

const testSuiteTemplate = `
---
name: TestSuite
description: Tests for verifying something
tests:
  - name: Harry's draft leave request
    input: &input
      requestId: "test"
      actions:
        - create
        - "view:public"
        - approve
      resource: draft_leave_request
    expected:
      -
        principal: harry
        actions:
          create: EFFECT_ALLOW
          "view:public": EFFECT_ALLOW
          approve: EFFECT_DENY
      -
        principal: maggie
        actions:
          create: EFFECT_DENY
          "view:public": EFFECT_ALLOW
          approve: EFFECT_DENY
  - name: Harry's pending leave request
    input:
      << : *input
      resource: pending_leave_request
    expected:
      -
        principal: harry
        actions:
          create: EFFECT_ALLOW
          "view:public": EFFECT_ALLOW
          approve: EFFECT_DENY
      -
        principal: maggie
        actions:
          create: EFFECT_DENY
          "view:public": EFFECT_ALLOW
          approve: EFFECT_ALLOW
{{.Principals}}
{{.Resources}}
`

func genTable(t *testing.T, embedResources, embedPrincipals bool) string {
	t.Helper()
	trimSpaceYAML := func (s string) string { // Removes all lines until a first root-level key
		lines := strings.Split(s, "\n")
		i := 0
		for ;i < len(lines); i++ {
			s := strings.TrimSpace(lines[i])
			if 	s != "" && s != "---" {
				break
			}
		}
		return strings.Join(lines[i:], "\n")
	}
	ts, err := template.New("table").Parse(testSuiteTemplate)
	require.NoError(t, err)

	data := struct{Principals, Resources string}{}
	if embedPrincipals {
		data.Principals = trimSpaceYAML(principals)
	}
	if embedResources {
		data.Resources = trimSpaceYAML(resources)
	}

	var sb strings.Builder
	ts.Execute(&sb, data)
	return sb.String()
}

func newMapFile (s string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(s)}
}

func Test_doVerify(t *testing.T) {
	eng := mkEngine(t)
	for _, embedPrincipals := range []bool{true, false} {
		for _, embedResources := range []bool{true, false} {
			t.Run(fmt.Sprintf("ebedded principals = %v, embedded resources = %v", embedPrincipals, embedResources), func(t *testing.T) {
				fsys := make(fstest.MapFS)
				if !embedResources {
					fsys[filepath.Join(TestDataDirectory, ResourcesFileName) + ".yaml"] = newMapFile(resources)
				}
				if !embedPrincipals {
					fsys[filepath.Join(TestDataDirectory, PrincipalsFileName) + ".yaml"] = newMapFile(principals)
				}
				table := genTable(t, embedResources, embedPrincipals)
				fsys["leave_request_test.yaml"] = newMapFile(table)
				result, err := doVerify(context.Background(), fsys, eng, Config{})
				is := require.New(t)
				is.NoError(err)
				is.Len(result.Results, 1)
				is.False(result.Results[0].Skipped)
				is.False(result.Failed, "%+v", result.Results)
			})
		}
	}
	t.Run("Several subdirectories with test fixtures", func(t *testing.T) {
		fsys := make(fstest.MapFS)
		ts := genTable(t, false, false)
		for _, dir := range []string{"a", "b", "c"} {
			d := filepath.Join(dir, TestDataDirectory)
			fsys[d + "/principals.yaml"] = &fstest.MapFile{Data: []byte(principals)}
			fsys[d + "/resources.yaml"] = &fstest.MapFile{Data: []byte(resources)}
			fsys[dir + "/leave_request_test.yaml"] = &fstest.MapFile{Data: []byte(ts)}
		}

		result, err := doVerify(context.Background(), fsys, eng, Config{})
		is := require.New(t)
		is.NoError(err)
		is.Len(result.Results, 3)
		for i := 0; i < len(result.Results); i++ {
			is.Len(result.Results[i].Tests, 2*2) // 2 principals * 2 resources
		}
		is.False(result.Failed, "%+v", result.Results)
	})
}

func mkEngine(t *testing.T) *engine.Engine {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir, ScratchDir: t.TempDir()})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), audit.NewNopLog())
	require.NoError(t, err)

	return eng
}
