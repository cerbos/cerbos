// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"testing"
	"testing/fstest"

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

const verifyPrinciples = `
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
const tables = `
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

`
func Test_doVerify(t *testing.T) {
	eng := mkEngine(t)

	fsys := make(fstest.MapFS)
	fsys["testdata/principals.yaml"] = &fstest.MapFile{Data: []byte(verifyPrinciples)}
	fsys["testdata/resources.yaml"] = &fstest.MapFile{Data: []byte(resources)}
	fsys["leave_request_test.yaml"] = &fstest.MapFile{Data: []byte(tables)}

	result, err := doVerify(context.Background(), fsys, eng, Config{})
	is := require.New(t)
	is.NoError(err)
	is.NotZero(result.Results)
	is.False(result.Failed, "%+v", result.Results)
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
