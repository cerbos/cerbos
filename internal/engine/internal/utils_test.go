// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetIntersects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		s1   ProtoSet
		s2   StringSet
		want bool
	}{
		{
			name: "empty",
			want: false,
		},
		{
			name: "intersects/no_wildcard",
			s1:   ProtoSet{"foo": {}, "bar": {}, "baz": {}},
			s2:   StringSet{"wibble": {}, "wobble": {}, "foo": {}},
			want: true,
		},
		{
			name: "intersects/wildcard",
			s1:   ProtoSet{"*": {}},
			s2:   StringSet{"wibble": {}, "wobble": {}, "wubble": {}},
			want: true,
		},
		{
			name: "no_intersects",
			s1:   ProtoSet{"foo*": {}, "bar": {}, "baz": {}},
			s2:   StringSet{"wibble": {}, "wobble": {}, "wubble": {}},
			want: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			have := SetIntersects(tc.s1, tc.s2)
			require.Equal(t, tc.want, have)
		})
	}
}
