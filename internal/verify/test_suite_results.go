// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"

func addResult(suite *policyv1.TestResults_Suite, name *policyv1.Test_TestName, action string, details *policyv1.TestResults_Details) {
	addAction(addResource(addPrincipal(addTestCase(suite, name.TestTableName), name.PrincipalKey), name.ResourceKey), action).Details = details
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
