// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/util"
)

func TestStringSet(t *testing.T) {
	testCases := []struct {
		input    []string
		expected map[string]struct{}
	}{
		{
			input:    input(t),
			expected: expected(t),
		},
		{
			input:    input(t, "x", "y"),
			expected: expected(t, "x", "y"),
		},
	}

	for idx, testCase := range testCases {
		t.Run(fmt.Sprint(idx), func(t *testing.T) {
			ss := util.ToStringSet(testCase.input)
			var m map[string]struct{} = ss
			require.Equal(t, testCase.expected, m)
		})
	}
}

func input(t *testing.T, inputs ...string) []string {
	t.Helper()

	return inputs
}

func expected(t *testing.T, expectedKeys ...string) map[string]struct{} {
	t.Helper()

	m := make(map[string]struct{})
	for _, e := range expectedKeys {
		m[e] = struct{}{}
	}

	return m
}
