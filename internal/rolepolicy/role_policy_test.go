// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package rolepolicy_test

import (
	"sort"
	"testing"

	"github.com/cerbos/cerbos/internal/rolepolicy"
	"github.com/kelindar/bitmap"
	"github.com/stretchr/testify/require"
)

func TestRolePolicyManager(t *testing.T) {
	mgr := rolepolicy.NewManager()

	t.Run("Actions", func(t *testing.T) {
		mgr.AddAction("a")
		mgr.AddAction("b")
		mgr.AddAction("c")

		require.Equal(t, 0, mgr.GetActionIndex("a"))
		require.Equal(t, 1, mgr.GetActionIndex("b"))
		require.Equal(t, 2, mgr.GetActionIndex("c"))

		// In the PDP, we can only pass guaranteed existing keys, so this is a bit of a "just-in-case" check
		require.Equal(t, -1, mgr.GetActionIndex("x"))

		var mask bitmap.Bitmap = mgr.OnesMask()
		// 3 bits are set, but the mask rounds up to the nearest full uint64 (64 bits)
		require.Equal(t, 64, mask.Count())
	})

	t.Run("Resources", func(t *testing.T) {
		resources := []string{"foo", "bar", "bosh"}
		for _, r := range resources {
			mgr.SetResource(r)
		}

		haveResources := mgr.GetAllResources()

		sort.Strings(resources)
		sort.Strings(haveResources)

		require.ElementsMatch(t, resources, mgr.GetAllResources())
	})
}
