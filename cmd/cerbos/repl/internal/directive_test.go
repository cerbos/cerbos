// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
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
				require.Nil(t, rd.Let)
			},
		},
		{
			directive: "let x := true",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "x", rd.Let.Name)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewBoolValue(true), have, protocmp.Transform()))
			},
		},
		{
			directive: "let x := false",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "x", rd.Let.Name)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewBoolValue(false), have, protocmp.Transform()))
			},
		},
		{
			directive: "let num := 25",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "num", rd.Let.Name)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewNumberValue(25), have, protocmp.Transform()))
			},
		},
		{
			directive: "let num := 25.12",
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "num", rd.Let.Name)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewNumberValue(25.12), have, protocmp.Transform()))
			},
		},
		{
			directive: `let str := "wibble wobble"`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "str", rd.Let.Name)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewStringValue("wibble wobble"), have, protocmp.Transform()))
			},
		},
		{
			directive: `let array := ["wibble", "wobble"]`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "array", rd.Let.Name)

				want, err := structpb.NewList([]interface{}{"wibble", "wobble"})
				require.NoError(t, err)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewListValue(want), have, protocmp.Transform()))
			},
		},
		{
			directive: `let array := ["wibble", [true, false], {"k": true}, 12]`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "array", rd.Let.Name)

				want, err := structpb.NewList([]interface{}{"wibble", []interface{}{true, false}, map[string]interface{}{"k": true}, 12})
				require.NoError(t, err)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewListValue(want), have, protocmp.Transform()))
			},
		},
		{
			directive: `let empty_array := []`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "empty_array", rd.Let.Name)

				want, err := structpb.NewList([]interface{}{})
				require.NoError(t, err)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewListValue(want), have, protocmp.Transform()))
			},
		},
		{
			directive: `let nested_map := {"k1": [true, false], "k2": {"kk1": true}, "k3": 12}`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "nested_map", rd.Let.Name)

				want, err := structpb.NewStruct(map[string]interface{}{
					"k1": []interface{}{true, false},
					"k2": map[string]interface{}{"kk1": true},
					"k3": 12,
				})
				require.NoError(t, err)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewStructValue(want), have, protocmp.Transform()))
			},
		},
		{
			directive: `let empty_map := {}`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "empty_map", rd.Let.Name)

				want, err := structpb.NewStruct(map[string]interface{}{})
				require.NoError(t, err)

				have := rd.Let.Value.ToProto()
				require.Empty(t, cmp.Diff(structpb.NewStructValue(want), have, protocmp.Transform()))
			},
		},
		{
			directive: `let x := $(int(10))`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "x", rd.Let.Name)
				require.Equal(t, Expr("int(10)"), *rd.Let.Value.Expr)
			},
		},
		{
			directive: `let x := $( "test".indexOf("e"))`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "x", rd.Let.Name)
				require.Equal(t, Expr(`"test".indexOf("e")`), *rd.Let.Value.Expr)
			},
		},
		{
			directive: `let x := $(1 in [1,2,3])`,
			check: func(t *testing.T, rd *REPLDirective) {
				t.Helper()
				require.False(t, rd.Exit)
				require.False(t, rd.Reset)
				require.False(t, rd.Vars)
				require.NotNil(t, rd.Let)
				require.Equal(t, "x", rd.Let.Name)
				require.Equal(t, Expr("1 in [1,2,3]"), *rd.Let.Value.Expr)
			},
		},
		{
			directive: `let := `,
			wantErr:   true,
		},
		{
			directive: `let x := `,
			wantErr:   true,
		},
		{
			directive: `let x := {"unclosed": true`,
			wantErr:   true,
		},
		{
			directive: `let x := $(()`,
			wantErr:   true,
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
