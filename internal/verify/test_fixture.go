// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/validator"
)

type Principals struct {
	LoadError error
	Fixtures  map[string]*enginev1.Principal
	FilePath  string
}

type Resources struct {
	LoadError error
	Fixtures  map[string]*enginev1.Resource
	FilePath  string
}

type AuxData struct {
	LoadError error
	Fixtures  map[string]*enginev1.AuxData
	FilePath  string
}

type TestFixture struct {
	Principals *Principals
	Resources  *Resources
	AuxData    *AuxData
}

const (
	principalsFileName = "principals"
	resourcesFileName  = "resources"
)

var auxDataFileNames = []string{"auxdata", "auxData", "aux_data"}

func LoadTestFixture(fsys fs.FS, path string, continueOnError bool) (tf *TestFixture, err error) {
	tf = new(TestFixture)
	tf.Principals, err = loadPrincipals(fsys, path)
	if err != nil && !continueOnError {
		return nil, err
	}

	tf.Resources, err = loadResources(fsys, path)
	if err != nil && !continueOnError {
		return nil, err
	}

	tf.AuxData, err = loadAuxData(fsys, path)
	if err != nil && !continueOnError {
		return nil, err
	}

	return tf, nil
}

func loadResources(fsys fs.FS, path string) (*Resources, error) {
	fp, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join(path, resourcesFileName))
	if err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	resources := &Resources{
		FilePath: fp,
	}

	pb := &policyv1.TestFixture_Resources{}
	if err := loadFixtureElement(fsys, fp, pb); err != nil {
		resources.LoadError = err
		return resources, err
	}

	resources.Fixtures = pb.Resources
	return resources, nil
}

func loadPrincipals(fsys fs.FS, path string) (*Principals, error) {
	fp, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join(path, principalsFileName))
	if err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	principals := &Principals{
		FilePath: fp,
	}

	pb := &policyv1.TestFixture_Principals{}
	if err := loadFixtureElement(fsys, fp, pb); err != nil {
		principals.LoadError = err
		return principals, err
	}

	principals.Fixtures = pb.Principals
	return principals, nil
}

func loadAuxData(fsys fs.FS, path string) (*AuxData, error) {
	for _, fn := range auxDataFileNames {
		fp, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join(path, fn))
		if err != nil {
			if errors.Is(err, util.ErrNoMatchingFiles) {
				continue
			}
			return nil, err
		}

		auxData := &AuxData{
			FilePath: fp,
		}

		pb := &policyv1.TestFixture_AuxData{}
		if err := loadFixtureElement(fsys, fp, pb); err != nil {
			auxData.LoadError = err
			return auxData, err
		}

		auxData.Fixtures = pb.AuxData
		return auxData, nil
	}

	return nil, nil
}

func loadFixtureElement(fsys fs.FS, path string, pb proto.Message) error {
	file, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	err = util.ReadJSONOrYAML(file, pb)
	if err != nil {
		return err
	}

	return validator.Validate(pb)
}

func (tf *TestFixture) checkDupes(suite *policyv1.TestSuite) error {
	dupes := make(map[string]struct{})
	var errs error
	for _, t := range suite.Tests {
		if _, ok := dupes[t.Name]; ok {
			errs = multierr.Append(errs, fmt.Errorf("another test named %s already exists", t.Name))
		}
		dupes[t.Name] = struct{}{}
	}

	return errs
}

func (tf *TestFixture) runTestSuite(ctx context.Context, eng Checker, filter *testFilter, file string, suite *policyv1.TestSuite, trace bool) *policyv1.TestResults_Suite {
	suiteResult := &policyv1.TestResults_Suite{
		File:        file,
		Name:        suite.Name,
		Description: suite.Description,
		Summary:     &policyv1.TestResults_Summary{},
	}

	if suite.Skip {
		suiteResult.Summary.OverallResult = policyv1.TestResults_RESULT_SKIPPED
		return suiteResult
	}

	if err := tf.checkDupes(suite); err != nil {
		suiteResult.Summary.OverallResult = policyv1.TestResults_RESULT_ERRORED
		suiteResult.Error = fmt.Sprintf("Invalid test suite: %v", err)
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

		if !filter.ShouldRunResource(test.Input.Resource) &&
			!filter.ShouldRunPrincipal(test.Input.Principal) {
			testResult := &policyv1.TestResults_Details{
				Result: policyv1.TestResults_RESULT_SKIPPED,
			}
			for _, action := range test.Input.Actions {
				addTestResult(suiteResult, test.Name.PrincipalKey, test.Name.ResourceKey, action, test.Name.TestTableName, testResult)
			}
			continue
		}
		for _, action := range test.Input.Actions {
			testResult := runTest(ctx, eng, test, action, filter, suite, trace)
			addTestResult(suiteResult, test.Name.PrincipalKey, test.Name.ResourceKey, action, test.Name.TestTableName, testResult)
		}
	}

	return suiteResult
}

func runTest(ctx context.Context, eng Checker, test *policyv1.Test, action string, filter *testFilter, suite *policyv1.TestSuite, trace bool) *policyv1.TestResults_Details {
	details := &policyv1.TestResults_Details{}

	if test.Skip || !filter.ShouldRun(fmt.Sprintf("%s/%s", suite.Name, test.Name.String())) {
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

	opts := checkOptions{
		nowFunc: time.Now,
		trace:   trace,
	}

	if test.Options != nil {
		opts.lenientScopeSearch = test.Options.LenientScopeSearch

		if test.Options.Now != nil {
			ts := test.Options.Now.AsTime()
			opts.nowFunc = func() time.Time { return ts }
		}

		if len(test.Options.Globals) > 0 {
			opts.globals = make(map[string]any, len(test.Options.Globals))
			for k, v := range test.Options.Globals {
				opts.globals[k] = v.AsInterface()
			}
		}
	}

	actual, traces, err := performCheck(ctx, eng, inputs, opts)
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

	expectedEffect := test.Expected[action]
	if expectedEffect == effectv1.Effect_EFFECT_UNSPECIFIED {
		expectedEffect = effectv1.Effect_EFFECT_DENY
	}

	if expectedEffect != actual[0].Actions[action].Effect {
		details.Result = policyv1.TestResults_RESULT_FAILED
		details.Outcome = &policyv1.TestResults_Details_Failure{
			Failure: &policyv1.TestResults_Failure{
				Expected: expectedEffect,
				Actual:   actual[0].Actions[action].Effect,
			},
		}
		return details
	}

	if expectedOutputs, ok := test.ExpectedOutputs[action]; ok {
		actualOutputs := make(map[string]*structpb.Value, len(actual[0].Outputs))
		for _, output := range actual[0].Outputs {
			actualOutputs[output.Src] = output.Val
		}

		var failures []*policyv1.TestResults_OutputFailure
		for wantKey, wantValue := range expectedOutputs.Entries {
			haveValue, ok := actualOutputs[wantKey]
			if !ok {
				failures = append(failures, &policyv1.TestResults_OutputFailure{
					Src: wantKey,
					Outcome: &policyv1.TestResults_OutputFailure_Missing{
						Missing: &policyv1.TestResults_OutputFailure_MissingValue{
							Expected: wantValue,
						},
					},
				})
				continue
			}

			if !cmp.Equal(wantValue, haveValue, protocmp.Transform()) {
				failures = append(failures, &policyv1.TestResults_OutputFailure{
					Src: wantKey,
					Outcome: &policyv1.TestResults_OutputFailure_Mismatched{
						Mismatched: &policyv1.TestResults_OutputFailure_MismatchedValue{
							Actual:   haveValue,
							Expected: wantValue,
						},
					},
				})
			}
		}

		if len(failures) > 0 {
			details.Result = policyv1.TestResults_RESULT_FAILED
			details.Outcome = &policyv1.TestResults_Details_Failure{
				Failure: &policyv1.TestResults_Failure{
					Expected: expectedEffect,
					Actual:   actual[0].Actions[action].Effect,
					Outputs:  failures,
				},
			}
			return details
		}
	}

	details.Result = policyv1.TestResults_RESULT_PASSED
	details.Outcome = &policyv1.TestResults_Details_Success{
		Success: &policyv1.TestResults_Success{
			Effect:  actual[0].Actions[action].Effect,
			Outputs: actual[0].Outputs,
		},
	}
	return details
}

type checkOptions struct {
	nowFunc            func() time.Time
	globals            map[string]any
	trace              bool
	lenientScopeSearch bool
}

func performCheck(ctx context.Context, eng Checker, inputs []*enginev1.CheckInput, opts checkOptions) ([]*enginev1.CheckOutput, []*enginev1.Trace, error) {
	checkOpts := []engine.CheckOpt{engine.WithNowFunc(opts.nowFunc), engine.WithGlobals(opts.globals)}
	if opts.lenientScopeSearch {
		checkOpts = append(checkOpts, engine.WithLenientScopeSearch())
	}

	if !opts.trace {
		output, err := eng.Check(ctx, inputs, checkOpts...)
		return output, nil, err
	}

	traceCollector := tracer.NewCollector()
	checkOpts = append(checkOpts, engine.WithTraceSink(traceCollector))
	output, err := eng.Check(ctx, inputs, checkOpts...)
	return output, traceCollector.Traces(), err
}

func addTestResult(suite *policyv1.TestResults_Suite, principal, resource, action, testName string, details *policyv1.TestResults_Details) {
	addAction(addResource(addPrincipal(addTestCase(suite, testName), principal), resource), action).Details = details
	suite.Summary.TestsCount++
	incrementTally(suite.Summary, details.Result, 1)

	if details.Result > suite.Summary.OverallResult {
		suite.Summary.OverallResult = details.Result
	}
}

func addTestCase(suite *policyv1.TestResults_Suite, name string) *policyv1.TestResults_TestCase {
	for _, tc := range suite.TestCases {
		if tc.Name == name {
			return tc
		}
	}

	tc := &policyv1.TestResults_TestCase{Name: name}
	suite.TestCases = append(suite.TestCases, tc)
	return tc
}

func addPrincipal(testCaseResult *policyv1.TestResults_TestCase, name string) *policyv1.TestResults_Principal {
	for _, principal := range testCaseResult.Principals {
		if principal.Name == name {
			return principal
		}
	}

	principal := &policyv1.TestResults_Principal{Name: name}
	testCaseResult.Principals = append(testCaseResult.Principals, principal)
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

func (tf *TestFixture) getTests(suite *policyv1.TestSuite) ([]*policyv1.Test, error) {
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

func (tf *TestFixture) buildTests(suite *policyv1.TestSuite, table *policyv1.TestTable) ([]*policyv1.Test, error) {
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

func (tf *TestFixture) buildTest(suite *policyv1.TestSuite, table *policyv1.TestTable, matrixElement testMatrixElement) (*policyv1.Test, error) {
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
		Expected:        matrixElement.Expected.actions,
		ExpectedOutputs: matrixElement.Expected.outputs,
		Options:         options,
	}, nil
}

func (tf *TestFixture) lookupPrincipal(ts *policyv1.TestSuite, k string) (*enginev1.Principal, error) {
	if v, ok := ts.Principals[k]; ok {
		return v, nil
	}

	if tf != nil && tf.Principals != nil {
		if v, ok := tf.Principals.Fixtures[k]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("principal %q not found", k)
}

func (tf *TestFixture) lookupResource(ts *policyv1.TestSuite, k string) (*enginev1.Resource, error) {
	if v, ok := ts.Resources[k]; ok {
		return v, nil
	}

	if tf != nil && tf.Resources != nil {
		if v, ok := tf.Resources.Fixtures[k]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("resource %q not found", k)
}

func (tf *TestFixture) lookupAuxData(ts *policyv1.TestSuite, k string) (*enginev1.AuxData, error) {
	if k == "" {
		return nil, nil
	}

	if v, ok := ts.AuxData[k]; ok {
		return v, nil
	}

	if tf != nil && tf.AuxData != nil {
		if v, ok := tf.AuxData.Fixtures[k]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("auxData %q not found", k)
}
