// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/util"
)

type testFixture struct {
	principals map[string]*enginev1.Principal
	resources  map[string]*enginev1.Resource
	auxData    map[string]*enginev1.AuxData
}

const (
	principalsFileName = "principals"
	resourcesFileName  = "resources"
)

var auxDataFileNames = []string{"auxdata", "auxData", "aux_data"}

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

	tf.auxData, err = loadAuxData(fsys, path)
	if err != nil {
		return nil, err
	}

	return tf, nil
}

func loadResources(fsys fs.FS, path string) (map[string]*enginev1.Resource, error) {
	pb := &policyv1.TestFixture_Resources{}
	fp := filepath.Join(path, resourcesFileName)
	if err := loadFixtureElement(fsys, fp, pb); err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	return pb.Resources, nil
}

func loadPrincipals(fsys fs.FS, path string) (map[string]*enginev1.Principal, error) {
	pb := &policyv1.TestFixture_Principals{}
	fp := filepath.Join(path, principalsFileName)
	if err := loadFixtureElement(fsys, fp, pb); err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	return pb.Principals, nil
}

func loadAuxData(fsys fs.FS, path string) (map[string]*enginev1.AuxData, error) {
	pb := &policyv1.TestFixture_AuxData{}
	for _, fn := range auxDataFileNames {
		fp := filepath.Join(path, fn)
		if err := loadFixtureElement(fsys, fp, pb); err != nil {
			if errors.Is(err, util.ErrNoMatchingFiles) {
				continue
			}
			return nil, err
		}

		return pb.AuxData, nil
	}

	return nil, nil
}

func loadFixtureElement(fsys fs.FS, path string, pb proto.Message) error {
	file, err := util.OpenOneOfSupportedFiles(fsys, path)
	if err != nil || file == nil {
		return err
	}

	defer file.Close()
	return util.ReadJSONOrYAML(file, pb)
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

		testResult := TestResult{Name: TestName{TableTestName: test.Name.TestTableName, PrincipalKey: test.Name.PrincipalKey, ResourceKey: test.Name.ResourceKey}}
		if test.Skip || !shouldRun(fmt.Sprintf("%s/%s", ts.Name, test.Name.String())) {
			testResult.Skipped = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		traceBuf := new(bytes.Buffer)
		actual, err := eng.Check(ctx, []*enginev1.CheckInput{test.Input}, engine.WithWriterTraceSink(traceBuf))
		if err != nil {
			testResult.Failed = true
			testResult.Error = err.Error()
			testResult.EngineTrace = traceBuf.String()
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
			testResult.EngineTrace = traceBuf.String()
			failed = true
		}

		sr.Tests = append(sr.Tests, testResult)
	}

	return sr, failed
}

func (tf *testFixture) getTests(suite *policyv1.TestSuite) ([]*policyv1.Test, error) {
	var allTests []*policyv1.Test

	for _, table := range suite.Tests {
		tests, err := tf.buildTests(suite, table)
		if err != nil {
			return nil, fmt.Errorf("invalid test %q: %w", table.Name, err)
		}

		allTests = append(allTests, tests...)
	}

	return allTests, nil
}

func (tf *testFixture) buildTests(suite *policyv1.TestSuite, table *policyv1.TestTable) ([]*policyv1.Test, error) {
	matrix, err := buildTestMatrix(table)
	if err != nil {
		return nil, err
	}

	tests := make([]*policyv1.Test, len(matrix))

	for i, element := range matrix {
		tests[i], err = tf.buildTest(suite, table, element)
		if err != nil {
			return nil, err
		}
	}

	return tests, nil
}

func (tf *testFixture) buildTest(suite *policyv1.TestSuite, table *policyv1.TestTable, matrixElement testMatrixElement) (*policyv1.Test, error) {
	name := &policyv1.Test_TestName{
		TestTableName: table.Name,
		PrincipalKey:  matrixElement.Principal,
		ResourceKey:   matrixElement.Resource,
	}

	principal, err := tf.lookupPrincipal(suite, matrixElement.Principal)
	if err != nil {
		return nil, err
	}

	resource, err := tf.lookupResource(suite, matrixElement.Resource)
	if err != nil {
		return nil, err
	}

	auxData, err := tf.lookupAuxData(suite, table.Input.AuxData)
	if err != nil {
		return nil, err
	}

	return &policyv1.Test{
		Name:        name,
		Description: table.Description,
		Skip:        table.Skip,
		SkipReason:  table.SkipReason,
		Input: &enginev1.CheckInput{
			Principal: principal,
			Resource:  resource,
			Actions:   table.Input.Actions,
			AuxData:   auxData,
		},
		Expected: matrixElement.Expected,
	}, nil
}

func (tf *testFixture) lookupPrincipal(ts *policyv1.TestSuite, k string) (*enginev1.Principal, error) {
	if v, ok := ts.Principals[k]; ok {
		return v, nil
	}

	if tf != nil {
		if v, ok := tf.principals[k]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("principal %q not found", k)
}

func (tf *testFixture) lookupResource(ts *policyv1.TestSuite, k string) (*enginev1.Resource, error) {
	if v, ok := ts.Resources[k]; ok {
		return v, nil
	}

	if tf != nil {
		if v, ok := tf.resources[k]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("resource %q not found", k)
}

func (tf *testFixture) lookupAuxData(ts *policyv1.TestSuite, k string) (*enginev1.AuxData, error) {
	if k == "" {
		return nil, nil
	}

	if v, ok := ts.AuxData[k]; ok {
		return v, nil
	}

	if tf != nil {
		if v, ok := tf.auxData[k]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("auxData %q not found", k)
}
