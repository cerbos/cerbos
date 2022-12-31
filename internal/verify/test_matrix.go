// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

type testMatrixKey struct {
	Principal string
	Resource  string
}

type testMatrixExpectation = map[string]effectv1.Effect

type testMatrixElement struct {
	Expected testMatrixExpectation
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

func buildExpectationLookup(table *policyv1.TestTable) (map[testMatrixKey]testMatrixExpectation, error) {
	lookup := make(map[testMatrixKey]testMatrixExpectation, len(table.Expected))

	for _, expectation := range table.Expected {
		key := testMatrixKey{Principal: expectation.Principal, Resource: expectation.Resource}

		if _, ok := lookup[key]; ok {
			return nil, fmt.Errorf("found multiple expectations for principal %q and resource %q", key.Principal, key.Resource)
		}

		lookup[key] = expectation.Actions
	}

	return lookup, nil
}

func buildDefaultExpectation(table *policyv1.TestTable) testMatrixExpectation {
	expectation := make(testMatrixExpectation, len(table.Input.Actions))
	for _, action := range table.Input.Actions {
		expectation[action] = effectv1.Effect_EFFECT_DENY
	}
	return expectation
}
