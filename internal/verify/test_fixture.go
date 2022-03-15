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

	"google.golang.org/protobuf/proto"

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

type validatableMessage interface {
	proto.Message
	Validate() error
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

func loadFixtureElement(fsys fs.FS, path string, pb validatableMessage) error {
	file, err := util.OpenOneOfSupportedFiles(fsys, path)
	if err != nil || file == nil {
		return err
	}

	defer file.Close()
	err = util.ReadJSONOrYAML(file, pb)
	if err != nil {
		return err
	}

	return pb.Validate()
}

func (tf *testFixture) runTestSuite(ctx context.Context, eng *engine.Engine, shouldRun func(string) bool, file string, ts *policyv1.TestSuite) (SuiteNode, bool) {
	failed := false

	sn := SuiteNode{
		File: file,
		Name: ts.Name,
	}
	if ts.Skip {
		sn.Skipped = true
		return sn, failed
	}

	tests, err := tf.getTests(ts)
	if err != nil {
		failed = true

		sn.Name = suiteNameWithErrors
		sn.Status = fmt.Sprintf("Failed to load the test suite: %s", err.Error())
		sn.Failed = true

		return sn, failed
	}

	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return sn, failed
		}

		skipped := false
		for _, action := range test.Input.Actions {
			testData := sn.Add(test.Name.PrincipalKey, test.Name.ResourceKey, action).Details

			if test.Skip || !shouldRun(fmt.Sprintf("%s/%s", ts.Name, test.Name.String())) {
				testData.Skipped = true
				skipped = true
				continue
			}

			inputs := []*enginev1.CheckInput{{RequestId: test.Input.RequestId, Resource: test.Input.Resource, Principal: test.Input.Principal, Actions: []string{action}, AuxData: test.Input.AuxData}}

			traceBuf := new(bytes.Buffer)
			actual, err := eng.Check(ctx, inputs, engine.WithWriterTraceSink(traceBuf))
			if err != nil {
				testData.Failed = true
				testData.Error = err.Error()
				testData.EngineTrace = traceBuf.String()
				failed = true
				continue
			}

			if len(actual) == 0 {
				testData.Failed = true
				testData.Error = "Empty response from server"
				failed = true
				continue
			}

			if test.Expected[action].String() != actual[0].Actions[action].Effect.String() {
				testData.Failed = true
				testData.Error = map[string]string{"expected": test.Expected[action].String(), "actual": actual[0].Actions[action].Effect.String()}
				testData.EngineTrace = traceBuf.String()
				failed = true
			}
		}

		if skipped {
			continue
		}
	}

	return sn, failed
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
