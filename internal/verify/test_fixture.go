// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/tracer"
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

func (tf *testFixture) runTestSuite(ctx context.Context, eng Checker, shouldRun func(string) bool, file string, suite *policyv1.TestSuite, trace bool) *policyv1.TestResults_Suite {
	suiteResult := &policyv1.TestResults_Suite{
		File:    file,
		Name:    suite.Name,
		Summary: &policyv1.TestResults_Summary{},
	}

	if suite.Skip {
		suiteResult.Summary.OverallResult = policyv1.TestResults_RESULT_SKIPPED
		return suiteResult
	}

	tests, err := tf.getTests(suite)
	if err != nil {
		suiteResult.Summary.OverallResult = policyv1.TestResults_RESULT_ERRORED
		suiteResult.Error = fmt.Sprintf("Failed to load the test suite: %s", err.Error())
		return suiteResult
	}

	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return suiteResult
		}

		for _, action := range test.Input.Actions {
			testResult := runTest(ctx, eng, test, action, shouldRun, suite, trace)
			addTestResult(suiteResult, test.Name.PrincipalKey, test.Name.ResourceKey, action, testResult)
		}
	}

	return suiteResult
}

func runTest(ctx context.Context, eng Checker, test *policyv1.Test, action string, shouldRun func(string) bool, suite *policyv1.TestSuite, trace bool) *policyv1.TestResults_Details {
	details := &policyv1.TestResults_Details{}

	if test.Skip || !shouldRun(fmt.Sprintf("%s/%s", suite.Name, test.Name.String())) {
		details.Result = policyv1.TestResults_RESULT_SKIPPED
		return details
	}

	inputs := []*enginev1.CheckInput{{
		RequestId: test.Input.RequestId,
		Resource:  test.Input.Resource,
		Principal: test.Input.Principal,
		Actions:   []string{action},
		AuxData:   test.Input.AuxData,
	}}

	nowFunc := time.Now
	if test.Options != nil && test.Options.Now != nil {
		ts := test.Options.Now.AsTime()
		nowFunc = func() time.Time { return ts }
	}

	actual, traces, err := performCheck(ctx, eng, inputs, trace, nowFunc)
	details.EngineTrace = traces

	if err != nil {
		details.Result = policyv1.TestResults_RESULT_ERRORED
		details.Outcome = &policyv1.TestResults_Details_Error{Error: err.Error()}
		return details
	}

	if len(actual) == 0 {
		details.Result = policyv1.TestResults_RESULT_ERRORED
		details.Outcome = &policyv1.TestResults_Details_Error{Error: "Empty response from server"}
		return details
	}

	if test.Expected[action] != actual[0].Actions[action].Effect {
		details.Result = policyv1.TestResults_RESULT_FAILED
		details.Outcome = &policyv1.TestResults_Details_Failure{
			Failure: &policyv1.TestResults_Failure{
				Expected: test.Expected[action],
				Actual:   actual[0].Actions[action].Effect,
			},
		}
		return details
	}

	details.Result = policyv1.TestResults_RESULT_PASSED
	return details
}

func performCheck(ctx context.Context, eng Checker, inputs []*enginev1.CheckInput, trace bool, nowFunc func() time.Time) ([]*enginev1.CheckOutput, []*enginev1.Trace, error) {
	if !trace {
		output, err := eng.Check(ctx, inputs, engine.WithNowFunc(nowFunc))
		return output, nil, err
	}

	traceCollector := tracer.NewCollector()
	output, err := eng.Check(ctx, inputs, engine.WithTraceSink(traceCollector), engine.WithNowFunc(nowFunc))
	return output, traceCollector.Traces(), err
}

func addTestResult(suite *policyv1.TestResults_Suite, principal, resource, action string, details *policyv1.TestResults_Details) {
	addAction(addResource(addPrincipal(suite, principal), resource), action).Details = details

	suite.Summary.TestsCount++
	incrementTally(suite.Summary, details.Result, 1)

	if details.Result > suite.Summary.OverallResult {
		suite.Summary.OverallResult = details.Result
	}
}

func addPrincipal(suite *policyv1.TestResults_Suite, name string) *policyv1.TestResults_Principal {
	for _, principal := range suite.Principals {
		if principal.Name == name {
			return principal
		}
	}

	principal := &policyv1.TestResults_Principal{Name: name}
	suite.Principals = append(suite.Principals, principal)
	return principal
}

func addResource(principal *policyv1.TestResults_Principal, name string) *policyv1.TestResults_Resource {
	for _, resource := range principal.Resources {
		if resource.Name == name {
			return resource
		}
	}

	resource := &policyv1.TestResults_Resource{Name: name}
	principal.Resources = append(principal.Resources, resource)
	return resource
}

func addAction(resource *policyv1.TestResults_Resource, name string) *policyv1.TestResults_Action {
	for _, action := range resource.Actions {
		if action.Name == name {
			return action
		}
	}

	action := &policyv1.TestResults_Action{Name: name, Details: &policyv1.TestResults_Details{}}
	resource.Actions = append(resource.Actions, action)
	return action
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

	options := table.Options
	if options == nil {
		options = suite.Options
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
		Options:  options,
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
