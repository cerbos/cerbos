// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"testing"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFilterConfig(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    *FilterConfig
		expectError bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: &FilterConfig{},
		},
		{
			name:  "single dimension with single glob",
			input: "test=album*",
			expected: &FilterConfig{
				Test: []string{"album*"},
			},
		},
		{
			name:  "single dimension with multiple globs",
			input: "principal=alice,bob,carol",
			expected: &FilterConfig{
				Principal: []string{"alice", "bob", "carol"},
			},
		},
		{
			name:  "multiple dimensions",
			input: "test=album*;principal=alice;resource=my_album;action=view",
			expected: &FilterConfig{
				Test:      []string{"album*"},
				Principal: []string{"alice"},
				Resource:  []string{"my_album"},
				Action:    []string{"view"},
			},
		},
		{
			name:  "multiple dimensions with multiple globs",
			input: "principal=alice,bob;action=view,edit,delete",
			expected: &FilterConfig{
				Principal: []string{"alice", "bob"},
				Action:    []string{"view", "edit", "delete"},
			},
		},
		{
			name:  "dimensions with spaces",
			input: "  test = album* ; principal = alice , bob  ",
			expected: &FilterConfig{
				Test:      []string{"album*"},
				Principal: []string{"alice", "bob"},
			},
		},
		{
			name:  "wildcard globs",
			input: "test=*;action=*",
			expected: &FilterConfig{
				Test:   []string{"*"},
				Action: []string{"*"},
			},
		},
		{
			name:  "case insensitive dimension names",
			input: "Test=foo",
			expected: &FilterConfig{
				Test: []string{"foo"},
			},
		},
		{
			name:        "unknown dimension",
			input:       "unknown=value",
			expectError: true,
		},
		{
			name:        "invalid format - no equals",
			input:       "test",
			expectError: true,
		},
		{
			name:        "empty value for dimension",
			input:       "test=",
			expectError: true,
		},
		{
			name:  "empty segments are skipped",
			input: "test=foo;;principal=bar",
			expected: &FilterConfig{
				Test:      []string{"foo"},
				Principal: []string{"bar"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseFilterConfig(tc.input)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

type filterOption func(*FilterConfig)

func withSuiteFilter(globs ...string) filterOption {
	return func(fc *FilterConfig) { fc.Suite = append(fc.Suite, globs...) }
}

func withTestFilter(globs ...string) filterOption {
	return func(fc *FilterConfig) { fc.Test = append(fc.Test, globs...) }
}

func withPrincipalFilter(globs ...string) filterOption {
	return func(fc *FilterConfig) { fc.Principal = append(fc.Principal, globs...) }
}

func withResourceFilter(globs ...string) filterOption {
	return func(fc *FilterConfig) { fc.Resource = append(fc.Resource, globs...) }
}

func withActionFilter(globs ...string) filterOption {
	return func(fc *FilterConfig) { fc.Action = append(fc.Action, globs...) }
}

func mkFilter(opts ...filterOption) *FilterConfig {
	fc := &FilterConfig{}
	for _, opt := range opts {
		opt(fc)
	}
	return fc
}

func TestTestFilterApply(t *testing.T) {
	makeTest := func(testName, principalKey, resourceKey string, actions []string) *policyv1.Test {
		return &policyv1.Test{
			Name: &policyv1.Test_TestName{
				TestTableName: testName,
				PrincipalKey:  principalKey,
				ResourceKey:   resourceKey,
			},
			Input: &enginev1.CheckInput{
				Principal: &enginev1.Principal{Id: principalKey},
				Resource:  &enginev1.Resource{Kind: "album", Id: resourceKey},
				Actions:   actions,
			},
		}
	}

	suite := &policyv1.TestSuite{Name: "TestSuite"}
	defaultTest := makeTest("TestAlbum", "alice", "my_album", []string{"view"})

	testCases := []struct {
		name       string
		filter     *FilterConfig
		test       *policyv1.Test
		skipReason string
	}{
		{
			name:   "no filter - test runs",
			filter: nil,
			test:   defaultTest,
		},
		{
			name:   "empty filter - test runs",
			filter: mkFilter(),
			test:   defaultTest,
		},
		{
			name:   "suite filter matches",
			filter: mkFilter(withSuiteFilter("TestSuite")),
			test:   defaultTest,
		},
		{
			name:   "suite filter matches with glob",
			filter: mkFilter(withSuiteFilter("Test*")),
			test:   defaultTest,
		},
		{
			name:       "suite filter does not match",
			filter:     mkFilter(withSuiteFilter("OtherSuite")),
			test:       defaultTest,
			skipReason: SkipReasonFilterSuite,
		},
		{
			name:   "test filter matches",
			filter: mkFilter(withTestFilter("TestAlbum")),
			test:   defaultTest,
		},
		{
			name:   "test filter matches with glob",
			filter: mkFilter(withTestFilter("Test*")),
			test:   defaultTest,
		},
		{
			name:       "test filter does not match",
			filter:     mkFilter(withTestFilter("OtherTest")),
			test:       defaultTest,
			skipReason: SkipReasonFilterTest,
		},
		{
			name:   "principal filter matches",
			filter: mkFilter(withPrincipalFilter("alice")),
			test:   defaultTest,
		},
		{
			name:   "principal filter matches with glob",
			filter: mkFilter(withPrincipalFilter("ali*")),
			test:   defaultTest,
		},
		{
			name:       "principal filter does not match",
			filter:     mkFilter(withPrincipalFilter("bob")),
			test:       defaultTest,
			skipReason: SkipReasonFilterPrincipal,
		},
		{
			name:   "resource filter matches",
			filter: mkFilter(withResourceFilter("my_album")),
			test:   defaultTest,
		},
		{
			name:   "resource filter matches with glob",
			filter: mkFilter(withResourceFilter("*_album")),
			test:   defaultTest,
		},
		{
			name:       "resource filter does not match",
			filter:     mkFilter(withResourceFilter("other_resource")),
			test:       defaultTest,
			skipReason: SkipReasonFilterResource,
		},
		{
			name:   "action filter matches single action",
			filter: mkFilter(withActionFilter("view")),
			test:   defaultTest,
		},
		{
			name:   "action filter matches one of multiple actions",
			filter: mkFilter(withActionFilter("edit")),
			test:   makeTest("TestAlbum", "alice", "my_album", []string{"view", "edit", "delete"}),
		},
		{
			name:   "action filter matches with glob",
			filter: mkFilter(withActionFilter("view*")),
			test:   makeTest("TestAlbum", "alice", "my_album", []string{"view_all"}),
		},
		{
			name:       "action filter does not match any action",
			filter:     mkFilter(withActionFilter("admin*")),
			test:       makeTest("TestAlbum", "alice", "my_album", []string{"view", "edit"}),
			skipReason: SkipReasonFilterAction,
		},
		{
			name:   "multiple filters all match",
			filter: mkFilter(withPrincipalFilter("alice"), withResourceFilter("*_album"), withActionFilter("view", "edit")),
			test:   defaultTest,
		},
		{
			name:       "multiple filters - principal fails",
			filter:     mkFilter(withPrincipalFilter("bob"), withResourceFilter("*_album"), withActionFilter("view")),
			test:       defaultTest,
			skipReason: SkipReasonFilterPrincipal,
		},
		{
			name:   "wildcard matches everything",
			filter: mkFilter(withPrincipalFilter("*"), withResourceFilter("*"), withActionFilter("*")),
			test:   defaultTest,
		},
		{
			name:   "multiple globs in one dimension - one matches",
			filter: mkFilter(withPrincipalFilter("bob", "alice", "carol")),
			test:   defaultTest,
		},
		{
			name:       "multiple globs in one dimension - none match",
			filter:     mkFilter(withPrincipalFilter("bob", "carol", "dave")),
			test:       defaultTest,
			skipReason: SkipReasonFilterPrincipal,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := newTestFilter(&Config{Filter: tc.filter})
			require.NoError(t, err)

			result := filter.Apply(tc.test, suite)

			if tc.skipReason != "" {
				require.NotNil(t, result)
				assert.Equal(t, policyv1.TestResults_RESULT_SKIPPED, result.Result)
				skipReason := result.Outcome.(*policyv1.TestResults_Details_SkipReason)
				assert.Equal(t, tc.skipReason, skipReason.SkipReason)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}
