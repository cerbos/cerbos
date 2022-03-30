// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectiveParser(t *testing.T) {
	testCases := []struct {
		directive string
		wantErr   bool
		check     func(*testing.T, *REPLDirective)
	}{
		{
			directive: "q",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.True(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.False(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "quit",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.True(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.False(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "exit",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.True(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.False(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "reset",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.True(t, rd.Reset)
				require.False(t, rd.Vars)
				require.False(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "vars",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.True(t, rd.Vars)
				require.False(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "help",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.True(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "h",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.True(t, rd.Help)
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "let x = true",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				checkLetIsDefined(t, rd)
				require.Equal(t, "x", rd.Let.Name)
				require.Equal(t, "true", strings.TrimSpace(rd.Let.Expr))
			},
		},
		{
			directive: "let num = 25",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				checkLetIsDefined(t, rd)
				require.Equal(t, "num", rd.Let.Name)
				require.Equal(t, "25", strings.TrimSpace(rd.Let.Expr))
			},
		},
		{
			directive: "let num=25.12",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				checkLetIsDefined(t, rd)
				require.Equal(t, "num", rd.Let.Name)
				require.Equal(t, "25.12", strings.TrimSpace(rd.Let.Expr))
			},
		},
		{
			directive: `let str = "wibble wobble"`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				checkLetIsDefined(t, rd)
				require.Equal(t, "str", rd.Let.Name)
				require.Equal(t, `"wibble wobble"`, strings.TrimSpace(rd.Let.Expr))
			},
		},
		{
			directive: `let array = ["wibble", "wobble"]`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				checkLetIsDefined(t, rd)
				require.Equal(t, "array", rd.Let.Name)
				require.Equal(t, `["wibble", "wobble"]`, strings.TrimSpace(rd.Let.Expr))
			},
		},
		{
			directive: `let nested_map = {"k1": [true, false], "k2": {"kk1": true}, "k3": 12}`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				checkLetIsDefined(t, rd)
				require.Equal(t, "nested_map", rd.Let.Name)
				require.Equal(t, `{"k1": [true, false], "k2": {"kk1": true}, "k3": 12}`, strings.TrimSpace(rd.Let.Expr))
			},
		},
	}

	parser, err := NewParser()
	require.NoError(t, err)

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.directive, func(t *testing.T) {
			have := &REPLDirective{}
			err := parser.ParseString("", tc.directive, have)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			tc.check(t, have)
		})
	}
}

func checkLetIsDefined(t *testing.T, rd *REPLDirective) {
	t.Helper()
	require.False(t, rd.Exit)
	require.False(t, rd.Reset)
	require.False(t, rd.Vars)
	require.False(t, rd.Help)
	require.NotNil(t, rd.Let)
}
