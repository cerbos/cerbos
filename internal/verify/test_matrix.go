// Copyright 2021-2022 Zenauth Ltd.
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
	principals, err := testMatrixAxis("principal", table.Input.Principal, table.Input.Principals)
	if err != nil {
		return nil, err
	}

	resources, err := testMatrixAxis("resource", table.Input.Resource, table.Input.Resources)
	if err != nil {
		return nil, err
	}

	expectationLookup, err := buildExpectationLookup(table)
	if err != nil {
		return nil, err
	}

	defaultExpectation := buildDefaultExpectation(table)

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

func testMatrixAxis(name, item string, items []string) ([]string, error) {
	if item != "" {
		if len(items) > 0 {
			return nil, fmt.Errorf(`wanted one of "%s" or "%[1]ss" in input; got both`, name)
		}

		return []string{item}, nil
	}

	if len(items) > 0 {
		return items, nil
	}

	return nil, fmt.Errorf(`wanted one of "%s" or "%[1]ss" in input; got neither`, name)
}

func buildExpectationLookup(table *policyv1.TestTable) (map[testMatrixKey]testMatrixExpectation, error) {
	lookup := make(map[testMatrixKey]testMatrixExpectation, len(table.Expected))

	for i, expectation := range table.Expected {
		principal, err := expectationKey("principal", i, expectation.Principal, table.Input.Principal)
		if err != nil {
			return nil, err
		}

		resource, err := expectationKey("resource", i, expectation.Resource, table.Input.Resource)
		if err != nil {
			return nil, err
		}

		key := testMatrixKey{Principal: principal, Resource: resource}

		if _, ok := lookup[key]; ok {
			return nil, fmt.Errorf("found multiple expectations for principal %q and resource %q", principal, resource)
		}

		lookup[key] = expectation.Actions
	}

	return lookup, nil
}

func expectationKey(name string, index int, value, defaultValue string) (string, error) {
	if value != "" {
		return value, nil
	}

	if defaultValue != "" {
		return defaultValue, nil
	}

	return "", fmt.Errorf("missing %s in expected at index %d", name, index)
}

func buildDefaultExpectation(table *policyv1.TestTable) testMatrixExpectation {
	expectation := make(testMatrixExpectation, len(table.Input.Actions))
	for _, action := range table.Input.Actions {
		expectation[action] = effectv1.Effect_EFFECT_DENY
	}
	return expectation
}
