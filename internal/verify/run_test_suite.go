// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"time"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

var errUsedDefaultNow = errors.New("a policy used a time-based condition, but `now` was not provided in the test options")

func runTestSuite(ctx context.Context, eng Checker, filter *testFilter, file string, suite *policyv1.TestSuite, fixture *TestFixture, trace, skipBatching bool) *policyv1.TestResults_Suite {
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
		results.SkipReason = suite.SkipReason
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

		if skipped := filter.Apply(test, suite); skipped != nil {
			for _, action := range test.Input.Actions {
				addResult(results, test.Name, action, skipped)
			}

			continue
		}

		actions, skippedActions := filter.partitionActions(test.Input.Actions)

		if !skipBatching {
			actionResults := runTest(ctx, eng, test, actions, trace)
			for _, action := range actions {
				addResult(results, test.Name, action, actionResults[action])
			}
		} else {
			for _, action := range actions {
				actionResults := runTest(ctx, eng, test, []string{action}, trace)
				addResult(results, test.Name, action, actionResults[action])
			}
		}

		for _, action := range skippedActions {
			addResult(results, test.Name, action, &policyv1.TestResults_Details{
				Result:  policyv1.TestResults_RESULT_SKIPPED,
				Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonFilterAction},
			})
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

func runTest(ctx context.Context, eng Checker, test *policyv1.Test, actions []string, trace bool) map[string]*policyv1.TestResults_Details {
	results := make(map[string]*policyv1.TestResults_Details, len(actions))

	inputs := []*enginev1.CheckInput{{
		RequestId: test.Input.RequestId,
		Resource:  test.Input.Resource,
		Principal: test.Input.Principal,
		Actions:   actions,
		AuxData:   test.Input.AuxData,
	}}

	actual, traces, err := performCheck(ctx, eng, inputs, test.Options, trace)
	if err != nil {
		for _, action := range actions {
			results[action] = &policyv1.TestResults_Details{
				Result:           policyv1.TestResults_RESULT_ERRORED,
				EngineTrace:      traces,
				EngineTraceBatch: tracer.TracesToBatch(traces),
				Outcome:          &policyv1.TestResults_Details_Error{Error: err.Error()},
			}
		}
		return results
	}

	if len(actual) == 0 {
		for _, action := range actions {
			results[action] = &policyv1.TestResults_Details{
				Result:           policyv1.TestResults_RESULT_ERRORED,
				EngineTrace:      traces,
				EngineTraceBatch: tracer.TracesToBatch(traces),
				Outcome:          &policyv1.TestResults_Details_Error{Error: "Empty response from server"},
			}
		}
		return results
	}
	actualOutputs := make(map[string]*structpb.Value, len(actual[0].Outputs))
	for _, action := range actions {
		clear(actualOutputs)
		var outputs []*enginev1.OutputEntry
		for _, output := range actual[0].Outputs {
			if output.Action == action {
				actualOutputs[output.Src] = output.Val
				outputs = append(outputs, output)
			}
		}

		details := &policyv1.TestResults_Details{
			EngineTrace:      traces,
			EngineTraceBatch: tracer.TracesToBatch(traces),
		}
		expectedEffect := test.Expected[action]
		if expectedEffect == effectv1.Effect_EFFECT_UNSPECIFIED {
			expectedEffect = effectv1.Effect_EFFECT_DENY
		}

		actionResult := actual[0].Actions[action]
		if actionResult == nil {
			details.Result = policyv1.TestResults_RESULT_ERRORED
			details.Outcome = &policyv1.TestResults_Details_Error{Error: fmt.Sprintf("no result for action %q", action)}
			results[action] = details
			continue
		}

		if expectedEffect != actionResult.Effect {
			details.Result = policyv1.TestResults_RESULT_FAILED
			details.Outcome = &policyv1.TestResults_Details_Failure{
				Failure: &policyv1.TestResults_Failure{
					Expected: expectedEffect,
					Actual:   actionResult.Effect,
				},
			}
			results[action] = details
			continue
		}

		if expectedOutputs, ok := test.ExpectedOutputs[action]; ok {
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
						Actual:   actionResult.Effect,
						Outputs:  failures,
					},
				}
				results[action] = details
				continue
			}
		}

		details.Result = policyv1.TestResults_RESULT_PASSED
		details.Outcome = &policyv1.TestResults_Details_Success{
			Success: &policyv1.TestResults_Success{
				Effect:  actionResult.Effect,
				Outputs: outputs,
			},
		}
		results[action] = details
	}

	return results
}

func performCheck(ctx context.Context, eng Checker, inputs []*enginev1.CheckInput, options *policyv1.TestOptions, trace bool) (_ []*enginev1.CheckOutput, traces []*enginev1.Trace, _ error) {
	var checkOpts []evaluator.CheckOpt

	usedDefaultNow := false
	if now := options.GetNow(); now != nil {
		checkOpts = append(checkOpts, evaluator.WithNowFunc(now.AsTime))
	} else {
		checkOpts = append(checkOpts, evaluator.WithNowFunc(func() time.Time {
			usedDefaultNow = true
			return time.Time{}
		}))
	}

	if options.GetLenientScopeSearch() {
		checkOpts = append(checkOpts, evaluator.WithLenientScopeSearch())
	}

	if globals := options.GetGlobals(); len(globals) > 0 {
		checkOpts = append(checkOpts, evaluator.WithGlobals((&structpb.Struct{Fields: globals}).AsMap()))
	}

	if defaultPolicyVersion := options.GetDefaultPolicyVersion(); defaultPolicyVersion != "" {
		checkOpts = append(checkOpts, evaluator.WithDefaultPolicyVersion(defaultPolicyVersion))
	}

	if defaultScope := options.GetDefaultScope(); defaultScope != "" {
		checkOpts = append(checkOpts, evaluator.WithDefaultScope(defaultScope))
	}

	if trace {
		traceCollector := tracer.NewCollector()
		checkOpts = append(checkOpts, evaluator.WithTraceSink(traceCollector))
		defer func() { traces = traceCollector.Traces() }()
	}

	output, err := eng.Check(ctx, inputs, checkOpts...)
	if err == nil && usedDefaultNow {
		err = errUsedDefaultNow
	}
	return output, traces, err
}
