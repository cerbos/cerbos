// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"time"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func runTestSuite(ctx context.Context, eng Checker, filter *testFilter, file string, suite *policyv1.TestSuite, fixture *TestFixture, trace bool) *policyv1.TestResults_Suite {
	summary := &policyv1.TestResults_Summary{}
	results := &policyv1.TestResults_Suite{
		File:        file,
		Name:        suite.Name,
		Description: suite.Description,
		Summary:     summary,
	}

	run := &testSuiteRun{
		Suite:   suite,
		Fixture: fixture,
	}

	var err error
	run.PrincipalGroups, err = checkGroupDefinitions(suite.PrincipalGroups, principalGroupMembers, existsFromLookup(run.lookupPrincipal))
	if err != nil {
		summary.OverallResult = policyv1.TestResults_RESULT_ERRORED
		results.Error = fmt.Sprintf("Invalid principal groups in test suite: %v", err)
		return results
	}

	run.ResourceGroups, err = checkGroupDefinitions(suite.ResourceGroups, resourceGroupMembers, existsFromLookup(run.lookupResource))
	if err != nil {
		summary.OverallResult = policyv1.TestResults_RESULT_ERRORED
		results.Error = fmt.Sprintf("Invalid resource groups in test suite: %v", err)
		return results
	}

	if suite.Skip {
		summary.OverallResult = policyv1.TestResults_RESULT_SKIPPED
		return results
	}

	if err := run.checkUniqueTestNames(); err != nil {
		results.Summary.OverallResult = policyv1.TestResults_RESULT_ERRORED
		results.Error = fmt.Sprintf("Invalid test suite: %v", err)
		return results
	}

	tests, err := run.getTests()
	if err != nil {
		results.Summary.OverallResult = policyv1.TestResults_RESULT_ERRORED
		results.Error = fmt.Sprintf("Failed to load the test suite: %s", err.Error())
		return results
	}

	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return results
		}

		if !filter.ShouldRunResource(test.Input.Resource) &&
			!filter.ShouldRunPrincipal(test.Input.Principal) {
			testResult := &policyv1.TestResults_Details{
				Result: policyv1.TestResults_RESULT_SKIPPED,
			}
			for _, action := range test.Input.Actions {
				addResult(results, test.Name.PrincipalKey, test.Name.ResourceKey, action, test.Name.TestTableName, testResult)
			}
			continue
		}
		for _, action := range test.Input.Actions {
			result := runTest(ctx, eng, test, action, filter, suite, trace)
			addResult(results, test.Name.PrincipalKey, test.Name.ResourceKey, action, test.Name.TestTableName, result)
		}
	}

	return results
}

type testSuiteRun struct {
	Suite           *policyv1.TestSuite
	Fixture         *TestFixture
	PrincipalGroups map[string][]string
	ResourceGroups  map[string][]string
}

func (r *testSuiteRun) checkUniqueTestNames() error {
	dupes := make(map[string]struct{})
	var errs error
	for _, t := range r.Suite.Tests {
		if _, ok := dupes[t.Name]; ok {
			errs = multierr.Append(errs, fmt.Errorf("another test named %s already exists", t.Name))
		}
		dupes[t.Name] = struct{}{}
	}

	return errs
}

func (r *testSuiteRun) getTests() ([]*policyv1.Test, error) {
	var allTests []*policyv1.Test

	for _, table := range r.Suite.Tests {
		tests, err := r.buildTests(table)
		if err != nil {
			return nil, fmt.Errorf("invalid test %q: %w", table.Name, err)
		}

		allTests = append(allTests, tests...)
	}

	return allTests, nil
}

func (r *testSuiteRun) buildTests(table *policyv1.TestTable) ([]*policyv1.Test, error) {
	matrix, err := r.buildTestMatrix(table)
	if err != nil {
		return nil, err
	}

	tests := make([]*policyv1.Test, len(matrix))

	for i, element := range matrix {
		tests[i], err = r.buildTest(table, element)
		if err != nil {
			return nil, err
		}
	}

	return tests, nil
}

func (r *testSuiteRun) buildTest(table *policyv1.TestTable, matrixElement testMatrixElement) (*policyv1.Test, error) {
	name := &policyv1.Test_TestName{
		TestTableName: table.Name,
		PrincipalKey:  matrixElement.Principal,
		ResourceKey:   matrixElement.Resource,
	}

	principal, err := r.lookupPrincipal(matrixElement.Principal)
	if err != nil {
		return nil, err
	}

	resource, err := r.lookupResource(matrixElement.Resource)
	if err != nil {
		return nil, err
	}

	auxData, err := r.lookupAuxData(table.Input.AuxData)
	if err != nil {
		return nil, err
	}

	options := table.Options
	if options == nil {
		options = r.Suite.Options
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

func (r *testSuiteRun) lookupPrincipal(name string) (*enginev1.Principal, error) {
	if principal, ok := r.Suite.Principals[name]; ok {
		return principal, nil
	}

	if principal, ok := r.Fixture.lookupPrincipal(name); ok {
		return principal, nil
	}

	return nil, fmt.Errorf("principal %q not found", name)
}

func (r *testSuiteRun) lookupPrincipalGroup(name string) ([]string, error) {
	if group, ok := r.Suite.PrincipalGroups[name]; ok {
		return group.Principals, nil
	}

	if group, ok := r.Fixture.lookupPrincipalGroup(name); ok {
		return group, nil
	}

	return nil, fmt.Errorf("principal group %q not found", name)
}

func (r *testSuiteRun) lookupResource(name string) (*enginev1.Resource, error) {
	if resource, ok := r.Suite.Resources[name]; ok {
		return resource, nil
	}

	if resource, ok := r.Fixture.lookupResource(name); ok {
		return resource, nil
	}

	return nil, fmt.Errorf("resource %q not found", name)
}

func (r *testSuiteRun) lookupResourceGroup(name string) ([]string, error) {
	if group, ok := r.Suite.ResourceGroups[name]; ok {
		return group.Resources, nil
	}

	if group, ok := r.Fixture.lookupResourceGroup(name); ok {
		return group, nil
	}

	return nil, fmt.Errorf("principal group %q not found", name)
}

func (r *testSuiteRun) lookupAuxData(name string) (*enginev1.AuxData, error) {
	if name == "" {
		return nil, nil
	}

	if auxData, ok := r.Suite.AuxData[name]; ok {
		return auxData, nil
	}

	if auxData, ok := r.Fixture.lookupAuxData(name); ok {
		return auxData, nil
	}

	return nil, fmt.Errorf("auxData %q not found", name)
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
