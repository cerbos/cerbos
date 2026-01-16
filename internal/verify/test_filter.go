// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"regexp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	SkipReasonName            = "Test name did not match the provided pattern"
	SkipReasonResource        = "Resource matched a policy that was excluded from the bundle"
	SkipReasonPrincipal       = "Principal matched a policy that was excluded from the bundle"
	SkipReasonFilterTest      = "Test name did not match the test filter"
	SkipReasonFilterPrincipal = "Principal did not match the test filter"
	SkipReasonFilterResource  = "Resource did not match the test filter"
	SkipReasonFilterAction    = "No actions matched the test filter"
)

type testFilter struct {
	excludedResourcePolicyFQNs  map[string]struct{}
	excludedPrincipalPolicyFQNs map[string]struct{}
	includedTestNamesRegexp     *regexp.Regexp
	filter                      *FilterConfig
}

func newTestFilter(conf *Config) (*testFilter, error) {
	filter := &testFilter{
		excludedResourcePolicyFQNs:  conf.ExcludedResourcePolicyFQNs,
		excludedPrincipalPolicyFQNs: conf.ExcludedPrincipalPolicyFQNs,
		filter:                      conf.Filter,
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

	case !f.matchesFilterTest(fmt.Sprintf("%s/%s", suite.Name, test.Name.String())):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonFilterTest},
		}

	case !f.matchesFilterPrincipal(test.Name.PrincipalKey):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonFilterPrincipal},
		}

	case !f.matchesFilterResource(test.Name.ResourceKey):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonFilterResource},
		}

	case !f.matchesFilterActions(test.Input.Actions):
		return &policyv1.TestResults_Details{
			Result:  policyv1.TestResults_RESULT_SKIPPED,
			Outcome: &policyv1.TestResults_Details_SkipReason{SkipReason: SkipReasonFilterAction},
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
	if scope := namer.ScopeValue(fixture.GetScope()); scope != "" {
		return scope
	}

	if defaultScope := options.GetDefaultScope(); defaultScope != "" {
		return defaultScope
	}

	return namer.DefaultScope
}

func (f *testFilter) matchesFilterTest(name string) bool {
	if f.filter == nil || len(f.filter.Test) == 0 {
		return true
	}
	return matchesAnyGlob(f.filter.Test, name)
}

func (f *testFilter) matchesFilterPrincipal(principalKey string) bool {
	if f.filter == nil || len(f.filter.Principal) == 0 {
		return true
	}
	return matchesAnyGlob(f.filter.Principal, principalKey)
}

func (f *testFilter) matchesFilterResource(resourceKey string) bool {
	if f.filter == nil || len(f.filter.Resource) == 0 {
		return true
	}
	return matchesAnyGlob(f.filter.Resource, resourceKey)
}

func (f *testFilter) matchesFilterActions(actions []string) bool {
	if f.filter == nil || len(f.filter.Action) == 0 {
		return true
	}
	for _, action := range actions {
		if matchesAnyGlob(f.filter.Action, action) {
			return true
		}
	}
	return false
}

// matchesAnyGlob checks if the value matches any of the provided glob patterns.
func matchesAnyGlob(globs []string, value string) bool {
	for _, g := range globs {
		if util.MatchesGlob(g, value) {
			return true
		}
	}
	return false
}
