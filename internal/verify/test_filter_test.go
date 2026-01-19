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
