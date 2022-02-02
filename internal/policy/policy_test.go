// Copyright 2021-2022 Zenauth Ltd.
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
		require.NotEmpty(t, p.Metadata.StoreIdentifer)
		require.Equal(t, fmt.Sprintf(derivedRolesFmt, 1), policyKey)
	})

	t.Run("WithHash", func(t *testing.T) {
		p := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p.Metadata)

		p = policy.WithHash(p)
		require.NotEmpty(t, p.Metadata.Hash)
		require.Equal(t, wrapperspb.UInt64(util.HashPB(p, policy.IgnoreHashFields)), p.Metadata.Hash)
	})

	t.Run("WithMetadata", func(t *testing.T) {
		p := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p.Metadata)

		keyVal := "test"
		p = policy.WithMetadata(p, source, map[string]string{keyVal: keyVal}, policyKey)
		require.NotEmpty(t, p.Metadata)
		require.Equal(t, fmt.Sprintf(derivedRolesFmt, 1), policyKey)
		require.Equal(t, wrapperspb.UInt64(util.HashPB(p, policy.IgnoreHashFields)), p.Metadata.Hash)
		require.Equal(t, source, p.Metadata.SourceFile)
		require.Equal(t, keyVal, p.Metadata.Annotations[keyVal])
	})
}
