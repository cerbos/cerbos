// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package namer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// isInvalidIdentifierChar is a fast path in front of invalidIdentifierChars, so the two must agree.
func TestIsInvalidIdentifierCharAgreesWithRegexp(t *testing.T) {
	runes := make([]rune, 0, 260)
	for r := range rune(256) {
		runes = append(runes, r)
	}
	runes = append(runes, 'é', 'ß', '世', '🚀')

	for _, r := range runes {
		want := invalidIdentifierChars.MatchString(string(r))
		require.Equal(t, want, isInvalidIdentifierChar(r), "rune %q (U+%04X)", r, r)
	}
}

func TestSanitize(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{input: "leave_request", want: "leave_request"},
		{input: "leave.request", want: "leave.request"},
		{input: "udm:module:users/simple_regular-user", want: "udm_module_users_simple_regular_user"},
		{input: "the:one:ring", want: "the_one_ring"},
		{input: "user@example.com/x", want: "user_example.com_x"},
		// outside the legacy pattern: stored as written
		{input: "foo:1bar", want: "foo:1bar"},
		{input: "1foo:bar", want: "1foo:bar"},
		{input: "foo:bar!", want: "foo:bar!"},
		{input: "udm:module:*", want: "udm:module:*"},
		{input: "foo::bar", want: "foo::bar"},
		{input: ":udm:module:users/x", want: ":udm:module:users/x"},
		{input: "café", want: "café"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.want, sanitize(tc.input))
		})
	}
}
