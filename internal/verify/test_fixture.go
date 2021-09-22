// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/go-cmp/cmp"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/util"
)

type testFixture struct {
	principals map[string]*v1.Principal
	resources  map[string]*v1.Resource
}

const (
	PrincipalsFileName = "principals"
	ResourcesFileName  = "resources"
)

func loadTestFixture(fsys fs.FS, path string) (tf *testFixture, err error) {
	tf = new(testFixture)
	tf.principals, err = loadPrincipals(fsys, path)
	if err != nil {
		return nil, err
	}
	tf.resources, err = loadResources(fsys, path)
	if err != nil {
		return nil, err
	}
	return tf, nil
}

func loadResources(fsys fs.FS, path string) (map[string]*v1.Resource, error) {
	pb := &policyv1.TestFixture_Resources{}
	file, err := util.OpenOneOfSupportedFiles(fsys, filepath.Join(path, ResourcesFileName))
	if err != nil || file == nil {
		return nil, err
	}
	defer file.Close()
	err = util.ReadJSONOrYAML(file, pb)
	if err != nil {
		return nil, err
	}
	return pb.Resources, nil
}

func loadPrincipals(fsys fs.FS, path string) (map[string]*v1.Principal, error) {
	pb := &policyv1.TestFixture_Principals{}
	file, err := util.OpenOneOfSupportedFiles(fsys, filepath.Join(path, PrincipalsFileName))
	if err != nil || file == nil {
		return nil, err
	}
	defer file.Close()
	err = util.ReadJSONOrYAML(file, pb)
	if err != nil {
		return nil, err
	}
	return pb.Principals, nil
}

func (tf *testFixture) runTestSuite(ctx context.Context, eng *engine.Engine, shouldRun func(string) bool, file string, ts *policyv1.TestSuite) (SuiteResult, bool) {
	failed := false

	sr := SuiteResult{File: file, Suite: ts.Name}
	if ts.Skip {
		sr.Skipped = true
		return sr, failed
	}
	tests, err := tf.getTests(ts)
	if err != nil {
		failed = true
		sr.Tests = []TestResult{{
			Name:    TestName{TableTestName: "Failed to load the test suite"},
			Skipped: false,
			Failed:  true,
			Error:   err.Error(),
		}}
		return sr, failed
	}
	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return sr, failed
		}

		testResult := TestResult{Name: TestName{TableTestName: test.Name.TestTableName, PrincipalKey: test.Name.PrincipalKey}}
		if test.Skip || !shouldRun(fmt.Sprintf("%s/%s", ts.Name, test.Name.String())) {
			testResult.Skipped = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		actual, err := eng.Check(ctx, []*v1.CheckInput{test.Input})
		if err != nil {
			testResult.Failed = true
			testResult.Error = err.Error()
			failed = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		if len(actual) == 0 {
			testResult.Failed = true
			testResult.Error = "Empty response from server"
			failed = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		// EffectsMatch is a type created to make the diff output nicer.
		type EffectsMatch map[string]effectv1.Effect
		expectedResult := EffectsMatch(test.Expected)

		actualResult := make(EffectsMatch, len(actual[0].Actions))
		for key, actionEffect := range actual[0].Actions {
			actualResult[key] = actionEffect.Effect
		}

		if diff := cmp.Diff(expectedResult, actualResult); diff != "" {
			testResult.Failed = true
			testResult.Error = diff
			failed = true
		}

		sr.Tests = append(sr.Tests, testResult)
	}

	return sr, failed
}

var (
	ErrPrincipalNotFound = errors.New("principal not found")
	ErrResourceNotFound  = errors.New("resource not found")
)

func (tf *testFixture) lookupResource(k string) (*v1.Resource, bool) {
	if tf == nil {
		return nil, false
	}
	v, ok := tf.resources[k]
	return v, ok
}

func (tf *testFixture) lookupPrincipal(k string) (*v1.Principal, bool) {
	if tf == nil {
		return nil, false
	}
	v, ok := tf.principals[k]
	return v, ok
}

func (tf *testFixture) getTests(ts *policyv1.TestSuite) (tests []*policyv1.Test, err error) {
	for _, table := range ts.Tests {
		for _, expected := range table.Expected {
			principal, ok := ts.Principals[expected.Principal]
			if !ok {
				principal, ok = tf.lookupPrincipal(expected.Principal)
				if !ok {
					return nil, fmt.Errorf("%w:%q", ErrPrincipalNotFound, expected.Principal)
				}
			}
			resource, ok := ts.Resources[table.Input.Resource]
			if !ok {
				resource, ok = tf.lookupResource(table.Input.Resource)
				if !ok {
					return nil, fmt.Errorf("%w:%q", ErrResourceNotFound, table.Input.Resource)
				}
			}
			test := &policyv1.Test{
				Name:        &policyv1.Test_TestName{TestTableName: table.Name, PrincipalKey: expected.Principal},
				Description: table.Description,
				Skip:        table.Skip,
				SkipReason:  table.SkipReason,
				Input: &v1.CheckInput{
					RequestId: table.Input.RequestId,
					Resource:  resource,
					Principal: principal,
					Actions:   table.Input.Actions,
				},
				Expected: expected.Actions,
			}
			tests = append(tests, test)
		}
	}

	return tests, nil
}
