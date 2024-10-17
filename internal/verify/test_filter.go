// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"regexp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

const (
	SkipReasonName      = "Test name did not match the provided pattern"
	SkipReasonResource  = "Resource matched a policy that was excluded from the bundle"
	SkipReasonPrincipal = "Principal matched a policy that was excluded from the bundle"
)

type testFilter struct {
	excludedResourcePolicyFQNs  map[string]struct{}
	excludedPrincipalPolicyFQNs map[string]struct{}
	includedTestNamesRegexp     *regexp.Regexp
}

func newTestFilter(conf *Config) (*testFilter, error) {
	filter := &testFilter{
		excludedResourcePolicyFQNs:  conf.ExcludedResourcePolicyFQNs,
		excludedPrincipalPolicyFQNs: conf.ExcludedPrincipalPolicyFQNs,
	}

	if conf.IncludedTestNamesRegexp != "" {
		var err error
		filter.includedTestNamesRegexp, err = regexp.Compile(conf.IncludedTestNamesRegexp)
		if err != nil {
			return nil, fmt.Errorf("invalid run specification: %w", err)
		}
	}

	return filter, nil
}

// Apply checks if the filter matches the given test, returning nil if the test should be run or a "skipped" result otherwise.
func (f *testFilter) Apply(test *policyv1.Test, suite *policyv1.TestSuite) *policyv1.TestResults_Details {
	switch {
	case !f.shouldRunTestNamed(fmt.Sprintf("%s/%s", suite.Name, test.Name.String())):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonName},
		}

	case !f.shouldRunTestForResource(test.Input.Resource):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonResource},
		}

	case !f.shouldRunTestForPrincipal(test.Input.Principal):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonPrincipal},
		}

	case test.Skip:
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: test.SkipReason},
		}

	default:
		return nil
	}
}

func (f *testFilter) shouldRunTestNamed(name string) bool {
	if f.includedTestNamesRegexp == nil {
		return true
	}

	return f.includedTestNamesRegexp.MatchString(name)
}

func (f *testFilter) shouldRunTestForResource(resource *enginev1.Resource) bool {
	if len(f.excludedResourcePolicyFQNs) == 0 {
		return true
	}

	version := resource.PolicyVersion
	if version == "" {
		version = namer.DefaultVersion
	}

	_, excluded := f.excludedResourcePolicyFQNs[namer.ResourcePolicyFQN(resource.Kind, version, resource.Scope)]
	return !excluded
}

func (f *testFilter) shouldRunTestForPrincipal(principal *enginev1.Principal) bool {
	if len(f.excludedPrincipalPolicyFQNs) == 0 {
		return true
	}

	version := principal.PolicyVersion
	if version == "" {
		version = namer.DefaultVersion
	}

	_, excluded := f.excludedPrincipalPolicyFQNs[namer.PrincipalPolicyFQN(principal.Id, version, principal.Scope)]
	return !excluded
}
