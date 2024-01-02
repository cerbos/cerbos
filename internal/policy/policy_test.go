// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package policy_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	derivedRolesFmt = "derived_roles.my_derived_roles_%d"
	source          = "testsource"
)

var policyKey = fmt.Sprintf(derivedRolesFmt, 1)

func TestWith(t *testing.T) {
	t.Run("WithStoreIdentifier", func(t *testing.T) {
		p := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p.Metadata)

		p = policy.WithStoreIdentifier(p, policyKey)
		require.NotEmpty(t, p.Metadata.StoreIdentifier)
		require.Equal(t, fmt.Sprintf(derivedRolesFmt, 1), policyKey)
	})

	t.Run("WithHash", func(t *testing.T) {
		p1 := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p1.Metadata)

		p2 := policy.WithHash(p1)
		require.NotEmpty(t, p2.Metadata.Hash)
		require.Equal(t, wrapperspb.UInt64(util.HashPB(p2, policy.IgnoreHashFields)), p2.Metadata.Hash)

		p3 := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		p3.Description = "With additional fields set that don't affect the hash"
		p3.Disabled = true
		p3.JsonSchema = "https://api.cerbos.dev/latest/cerbos/policy/v1/Policy.schema.json"
		require.Equal(t, p2.Metadata.Hash, policy.WithHash(p3).Metadata.Hash)
	})

	t.Run("WithMetadata", func(t *testing.T) {
		p := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p.Metadata)

		keyVal := "test"
		p = policy.WithMetadata(p, source, map[string]string{keyVal: keyVal}, policyKey, policy.SourceFile(source))
		require.NotEmpty(t, p.Metadata)
		require.Equal(t, fmt.Sprintf(derivedRolesFmt, 1), policyKey)
		require.Equal(t, wrapperspb.UInt64(util.HashPB(p, policy.IgnoreHashFields)), p.Metadata.Hash)
		require.Equal(t, source, p.Metadata.SourceFile)
		require.Equal(t, keyVal, p.Metadata.Annotations[keyVal])
		require.Equal(t, source, p.Metadata.SourceAttributes.Attributes["source"].GetStringValue())
	})
}

func TestAncestors(t *testing.T) {
	testCases := []struct {
		scope string
		want  []namer.ModuleID
	}{
		{
			scope: "",
			want:  nil,
		},
		{
			scope: "foo",
			want: []namer.ModuleID{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"),
			},
		},
		{
			scope: "foo.bar",
			want: []namer.ModuleID{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"),
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"),
			},
		},
		{
			scope: "foo.bar.baz",
			want: []namer.ModuleID{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo.bar"),
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"),
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("scope=%q", tc.scope), func(t *testing.T) {
			p := test.GenResourcePolicy(test.NoMod())
			p.GetResourcePolicy().Scope = tc.scope
			have := policy.Ancestors(p)
			require.Equal(t, tc.want, have)
		})
	}
}

func TestRequiredAncestors(t *testing.T) {
	testCases := []struct {
		scope string
		want  map[namer.ModuleID]string
	}{
		{
			scope: "",
			want:  nil,
		},
		{
			scope: "foo",
			want: map[namer.ModuleID]string{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"): "cerbos.resource.leave_request.vdefault",
			},
		},
		{
			scope: "foo.bar",
			want: map[namer.ModuleID]string{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"): "cerbos.resource.leave_request.vdefault/foo",
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"):     "cerbos.resource.leave_request.vdefault",
			},
		},
		{
			scope: "foo.bar.baz",
			want: map[namer.ModuleID]string{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo.bar"): "cerbos.resource.leave_request.vdefault/foo.bar",
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"):     "cerbos.resource.leave_request.vdefault/foo",
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"):         "cerbos.resource.leave_request.vdefault",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("scope=%q", tc.scope), func(t *testing.T) {
			p := test.GenResourcePolicy(test.NoMod())
			p.GetResourcePolicy().Scope = tc.scope
			have := policy.RequiredAncestors(p)
			require.Equal(t, tc.want, have)
		})
	}
}
