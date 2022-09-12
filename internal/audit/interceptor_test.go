// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package audit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMkIncludeKeysMethod(t *testing.T) {
	testCases := []struct {
		key      string
		expected bool
	}{
		{
			key:      "a",
			expected: false,
		},
		{
			key:      "b",
			expected: false,
		},
		{
			key:      "c",
			expected: true,
		},
	}

	excludedMetadataKeys := []string{"a", "b"}
	includedMetadataKeys := []string{"a", "c"}
	includeKeys := mkIncludeKeysMethod(excludedMetadataKeys, includedMetadataKeys)

	for _, tc := range testCases {
		t.Run(tc.key, func(t *testing.T) {
			actual := includeKeys(tc.key)
			require.Equal(t, tc.expected, actual)
		})
	}
}
