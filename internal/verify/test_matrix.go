// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

type testMatrixKey struct {
	Principal string
	Resource  string
}

type testMatrixExpectations struct {
	actions map[string]effectv1.Effect
	outputs map[string]*policyv1.Test_OutputEntries
}

type testMatrixElement struct {
	Expected *testMatrixExpectations
	testMatrixKey
}

func (r *testSuiteRun) buildTestMatrix(table *policyv1.TestTable) ([]testMatrixElement, error) {
	expectationLookup, err := r.buildExpectationLookup(table)
	if err != nil {
		return nil, err
	}

	defaultExpectation := buildDefaultExpectation(table)

	principals, err := r.collectFixtures("", table.Input.Principals, table.Input.PrincipalGroups, r.lookupPrincipalGroup)
	if err != nil {
		return nil, err
	}

	resources, err := r.collectFixtures("", table.Input.Resources, table.Input.ResourceGroups, r.lookupResourceGroup)
	if err != nil {
		return nil, err
	}

	matrix := make([]testMatrixElement, 0, len(principals)*len(resources))

	for _, principal := range principals {
		for _, resource := range resources {
			key := testMatrixKey{Principal: principal, Resource: resource}
			expectation, ok := expectationLookup[key]
			if !ok {
				expectation = defaultExpectation
			}
			delete(expectationLookup, key)
			matrix = append(matrix, testMatrixElement{testMatrixKey: key, Expected: expectation})
		}
	}

	for key := range expectationLookup {
		return nil, fmt.Errorf("found an expectation for principal %q and resource %q, but at least one of these is not present in input", key.Principal, key.Resource)
	}

	return matrix, nil
}

func (r *testSuiteRun) buildExpectationLookup(table *policyv1.TestTable) (map[testMatrixKey]*testMatrixExpectations, error) {
	inputActions := table.Input.GetActions()
	inputActionsMap := make(map[string]struct{}, len(inputActions))
	for _, a := range inputActions {
		inputActionsMap[a] = struct{}{}
	}

	lookup := make(map[testMatrixKey]*testMatrixExpectations, len(table.Expected))
	for _, expectation := range table.Expected {
		outputs := outputExpectations(expectation)

		var unreachableOutputs []string
		for action := range outputs {
			if _, ok := inputActionsMap[action]; !ok {
				unreachableOutputs = append(unreachableOutputs, action)
			}
		}

		if len(unreachableOutputs) > 0 {
			return nil, fmt.Errorf("found output expectations for actions that are not in the input actions list: [%s]", strings.Join(unreachableOutputs, ","))
		}

		principals, err := r.collectFixtures(expectation.Principal, expectation.Principals, expectation.PrincipalGroups, r.lookupPrincipalGroup)
		if err != nil {
			return nil, err
		}

		resources, err := r.collectFixtures(expectation.Resource, expectation.Resources, expectation.ResourceGroups, r.lookupResourceGroup)
		if err != nil {
			return nil, err
		}

		for _, principal := range principals {
			for _, resource := range resources {
				key := testMatrixKey{Principal: principal, Resource: resource}

				var extraExpectations []string
				for a := range expectation.Actions {
					if _, ok := inputActionsMap[a]; !ok {
						extraExpectations = append(extraExpectations, a)
					}
				}
				if len(extraExpectations) > 0 {
					sort.Strings(extraExpectations)
					return nil, fmt.Errorf("found expectations for actions that do not exist in the input actions list: [%s]", strings.Join(extraExpectations, ","))
				}

				lookup[key], err = mergeExpectations(key, lookup[key], expectation.Actions, outputs)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return lookup, nil
}

func outputExpectations(expectation *policyv1.TestTable_Expectation) map[string]*policyv1.Test_OutputEntries {
	outputs := make(map[string]*policyv1.Test_OutputEntries, len(expectation.Outputs))
	for _, oe := range expectation.Outputs {
		entries := make(map[string]*structpb.Value, len(oe.Expected))
		for _, entry := range oe.Expected {
			entries[entry.Src] = entry.Val
		}
		outputs[oe.Action] = &policyv1.Test_OutputEntries{Entries: entries}
	}
	return outputs
}

func mergeExpectations(key testMatrixKey, target *testMatrixExpectations, actions map[string]effectv1.Effect, outputs map[string]*policyv1.Test_OutputEntries) (*testMatrixExpectations, error) {
	if target == nil {
		target = &testMatrixExpectations{
			actions: make(map[string]effectv1.Effect, len(actions)),
			outputs: make(map[string]*policyv1.Test_OutputEntries, len(outputs)),
		}
	}

	err := mergeEffectExpectations(key, target.actions, actions)
	if err != nil {
		return nil, err
	}

	target.outputs, err = mergeOutputExpectations(key, target.outputs, outputs)
	return target, err
}

func mergeEffectExpectations(key testMatrixKey, target, source map[string]effectv1.Effect) error {
	for action, newEffect := range source {
		if oldEffect, ok := target[action]; ok {
			if newEffect != oldEffect {
				return fmt.Errorf("found inconsistent expectations for principal %q performing action %q on resource %q", key.Principal, action, key.Resource)
			}
		} else {
			target[action] = newEffect
		}
	}

	return nil
}

func mergeOutputExpectations(key testMatrixKey, target, source map[string]*policyv1.Test_OutputEntries) (map[string]*policyv1.Test_OutputEntries, error) {
	for action, entries := range source {
		var err error
		target[action], err = mergeOutputEntries(key, action, target[action], entries)
		if err != nil {
			return nil, err
		}
	}

	return target, nil
}

func mergeOutputEntries(key testMatrixKey, action string, target, source *policyv1.Test_OutputEntries) (*policyv1.Test_OutputEntries, error) {
	if target == nil {
		target = &policyv1.Test_OutputEntries{}
	}

	if target.Entries == nil {
		target.Entries = make(map[string]*structpb.Value, len(source.Entries))
	}

	for src, newVal := range source.Entries {
		if oldVal, ok := target.Entries[src]; ok {
			if !proto.Equal(newVal, oldVal) {
				return nil, fmt.Errorf("found inconsistent expectations for output %q from principal %q performing action %q on resource %q", src, key.Principal, action, key.Resource)
			}
		} else {
			target.Entries[src] = newVal
		}
	}

	return target, nil
}

func (r *testSuiteRun) collectFixtures(fixture string, fixtures, groups []string, lookup func(string) ([]string, error)) ([]string, error) {
	if fixture != "" {
		fixtures = []string{fixture}
	}

	seen := make(map[string]struct{}, len(fixtures)+len(groups))

	for _, fixture := range fixtures {
		seen[fixture] = struct{}{}
	}

	for _, group := range groups {
		groupFixtures, err := lookup(group)
		if err != nil {
			return nil, err
		}

		for _, fixture := range groupFixtures {
			_, alreadySeen := seen[fixture]
			if !alreadySeen {
				fixtures = append(fixtures, fixture)
				seen[fixture] = struct{}{}
			}
		}
	}

	return fixtures, nil
}

func buildDefaultExpectation(table *policyv1.TestTable) *testMatrixExpectations {
	actions := make(map[string]effectv1.Effect, len(table.Input.Actions))
	for _, a := range table.Input.Actions {
		actions[a] = effectv1.Effect_EFFECT_DENY
	}

	return &testMatrixExpectations{actions: actions}
}
