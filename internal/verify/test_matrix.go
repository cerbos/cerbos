// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"

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
	Expected testMatrixExpectations
	testMatrixKey
}

func buildTestMatrix(table *policyv1.TestTable) ([]testMatrixElement, error) {
	expectationLookup, err := buildExpectationLookup(table)
	if err != nil {
		return nil, err
	}

	defaultExpectation := buildDefaultExpectation(table)

	matrix := make([]testMatrixElement, 0, len(table.Input.Principals)*len(table.Input.Resources))

	for _, principal := range table.Input.Principals {
		for _, resource := range table.Input.Resources {
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

func buildExpectationLookup(table *policyv1.TestTable) (map[testMatrixKey]testMatrixExpectations, error) {
	lookup := make(map[testMatrixKey]testMatrixExpectations, len(table.Expected))

	for _, expectation := range table.Expected {
		key := testMatrixKey{Principal: expectation.Principal, Resource: expectation.Resource}

		if _, ok := lookup[key]; ok {
			return nil, fmt.Errorf("found multiple expectations for principal %q and resource %q", key.Principal, key.Resource)
		}

		tmExpectation := testMatrixExpectations{actions: expectation.Actions}
		if n := len(expectation.Outputs); n > 0 {
			tmExpectation.outputs = make(map[string]*policyv1.Test_OutputEntries, n)
			for _, oe := range expectation.Outputs {
				entries := make(map[string]*structpb.Value, len(oe.Expected))
				for _, entry := range oe.Expected {
					entries[entry.Src] = entry.Val
				}
				tmExpectation.outputs[oe.Action] = &policyv1.Test_OutputEntries{Entries: entries}
			}
		}

		lookup[key] = tmExpectation
	}

	return lookup, nil
}

func buildDefaultExpectation(table *policyv1.TestTable) testMatrixExpectations {
	actions := make(map[string]effectv1.Effect, len(table.Input.Actions))
	for _, a := range table.Input.Actions {
		actions[a] = effectv1.Effect_EFFECT_DENY
	}

	return testMatrixExpectations{actions: actions}
}
