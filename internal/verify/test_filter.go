// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"regexp"
	"strings"

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

	case !f.shouldRunTestForResource(test.Input.Resource, test.Options):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonResource},
		}

	case !f.shouldRunTestForPrincipal(test.Input.Principal, test.Options):
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

func (f *testFilter) shouldRunTestForResource(resource *enginev1.Resource, options *policyv1.TestOptions) bool {
	if len(f.excludedResourcePolicyFQNs) == 0 {
		return true
	}

	_, excluded := f.excludedResourcePolicyFQNs[namer.ResourcePolicyFQN(resource.Kind, policyVersion(resource, options), scope(resource, options))]
	return !excluded
}

func (f *testFilter) shouldRunTestForPrincipal(principal *enginev1.Principal, options *policyv1.TestOptions) bool {
	if len(f.excludedPrincipalPolicyFQNs) == 0 {
		return true
	}

	_, excluded := f.excludedPrincipalPolicyFQNs[namer.PrincipalPolicyFQN(principal.Id, policyVersion(principal, options), scope(principal, options))]
	return !excluded
}

func policyVersion(fixture interface{ GetPolicyVersion() string }, options *policyv1.TestOptions) string {
	if version := fixture.GetPolicyVersion(); version != "" {
		return version
	}

	if defaultVersion := options.GetDefaultPolicyVersion(); defaultVersion != "" {
		return defaultVersion
	}

	return namer.DefaultVersion
}

func scope(fixture interface{ GetScope() string }, options *policyv1.TestOptions) string {
	if scope := strings.TrimPrefix(fixture.GetScope(), "."); scope != "" {
		return scope
	}

	if defaultScope := options.GetDefaultScope(); defaultScope != "" {
		return defaultScope
	}

	return namer.DefaultScope
}
