// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package engine

import (
	"math/rand"
	"testing"

	"github.com/cerbos/cerbos/internal/test"
	"github.com/stretchr/testify/require"
)

var dummyVar int

func BenchmarkSetIntersects(b *testing.B) {
	n := 1000
	nItems := 10

	inputs := make([]stringSet, n)
	for i := 0; i < n; i++ {
		m := make(stringSet, nItems)
		for j := 0; j < nItems; j++ {
			item := test.RandomStr(15)
			m[item] = struct{}{}
		}
		inputs[i] = m
	}

	b.Run("with_globs", func(b *testing.B) {
		b.ReportAllocs()
		checkSet := protoSet{"wibble": {}, "foobar": {}, "*": {}}
		for i := 0; i < b.N; i++ {
			if setIntersects(checkSet, inputs[i%n]) {
				dummyVar = rand.Intn(10) << 2 //nolint:gosec
			}
		}
	})

	b.Run("without_globs", func(b *testing.B) {
		b.ReportAllocs()
		checkSet := protoSet{"wibble": {}, "foobar": {}, "wobble": {}}
		for i := 0; i < b.N; i++ {
			if setIntersects(checkSet, inputs[i%n]) {
				dummyVar = rand.Intn(10) << 2 //nolint:gosec
			}
		}
	})
}

func TestSetIntersects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		s1   protoSet
		s2   stringSet
		want bool
	}{
		{
			name: "empty",
			want: false,
		},
		{
			name: "intersects/no_wildcard",
			s1:   protoSet{"foo": {}, "bar": {}, "baz": {}},
			s2:   stringSet{"wibble": {}, "wobble": {}, "foo": {}},
			want: true,
		},
		{
			name: "intersects/wildcard",
			s1:   protoSet{"*": {}, "bar": {}, "baz": {}},
			s2:   stringSet{"wibble": {}, "wobble": {}, "wubble": {}},
			want: true,
		},
		{
			name: "no_intersects",
			s1:   protoSet{"foo*": {}, "bar": {}, "baz": {}},
			s2:   stringSet{"wibble": {}, "wobble": {}, "wubble": {}},
			want: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			have := setIntersects(tc.s1, tc.s2)
			require.Equal(t, tc.want, have)
		})
	}
}
