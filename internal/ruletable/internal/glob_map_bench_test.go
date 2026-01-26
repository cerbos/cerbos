// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"testing"
)

// 30 action glob patterns.
var actionGlobs = []string{
	"read:*",
	"view:*",
	"delete:*",
	"create:*",
	"update:*",
	"list:*",
	"manage:*",
	"admin:*",
	"edit:*",
	"publish:*",
	"archive:*",
	"restore:*",
	"export:*",
	"import:*",
	"share:*",
	"invite:*",
	"approve:*",
	"reject:*",
	"submit:*",
	"cancel:*",
	"clone:*",
	"move:*",
	"copy:*",
	"rename:*",
	"download:*",
	"upload:*",
	"preview:*",
	"comment:*",
	"subscribe:*",
	"unsubscribe:*",
}

// Actions to look up (mix of matching and non-matching).
var lookupActions = []string{
	"read:documents",
	"view:reports",
	"delete:users",
	"create:projects",
	"update:settings",
	"list:items",
	"manage:teams",
	"admin:system",
	"unknown:action",
	"other:thing",
}

func BenchmarkGlobMap(b *testing.B) {
	b.Run("Get", func(b *testing.B) {
		gm := NewGlobMap(make(map[string]int))
		for i, g := range actionGlobs {
			gm.Set(g, i)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			action := lookupActions[i%len(lookupActions)]
			gm.Get(action)
		}
	})

	b.Run("GetMerged", func(b *testing.B) {
		gm := NewGlobMap(make(map[string]int))
		for i, g := range actionGlobs {
			gm.Set(g, i)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			action := lookupActions[i%len(lookupActions)]
			gm.GetMerged(action)
		}
	})

	b.Run("SetThenGet", func(b *testing.B) {
		gm := NewGlobMap(make(map[string]int))

		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			// Simulate per-request pattern: set globs, then query
			if i%100 == 0 {
				gm.Clear()
				for j, g := range actionGlobs {
					gm.Set(g, j)
				}
			}
			action := lookupActions[i%len(lookupActions)]
			gm.Get(action)
		}
	})
}
