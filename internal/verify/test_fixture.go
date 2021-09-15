package verify

import (
	"context"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/go-cmp/cmp"
	"io/fs"
	"path/filepath"
)

type testFixture struct {
	principals map[string]*v1.Principal
	resources  map[string]*v1.Resource
}

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
	file, err := util.OpenOneOfSupportedFiles(fsys, filepath.Join(path, "resources"))
	if err != nil {
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
	file, err := util.OpenOneOfSupportedFiles(fsys, filepath.Join(path, "principals"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = util.ReadJSONOrYAML(file, pb)
	if err != nil {
		return nil, err
	}
	return pb.Principals, nil
}

func (t *testFixture) runTestSuite(ctx context.Context, eng *engine.Engine, shouldRun func(string) bool, file string, ts *policyv1.TestSuite) (SuiteResult, bool) {
	failed := false

	sr := SuiteResult{File: file, Suite: ts.Name}
	if ts.Skip || !shouldRun(ts.Name) {
		sr.Skipped = true
		return sr, failed
	}
	tests := t.getTests(ts)
	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return sr, failed
		}

		testResult := TestResult{Name: test.Name}
		if test.Skip || !shouldRun(test.Name) {
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

func (t *testFixture) getTests(ts *policyv1.TestSuite) []*policyv1.Test {
	panic("not implemented")
}
