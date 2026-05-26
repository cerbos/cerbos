// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLazyDimensionAddBitmap(t *testing.T) {
	d := newLazyDimension()
	d.Add("a", 5)
	d.Add("a", 200)
	d.Add("a", 64) // out-of-order -> sorted insert
	d.Add("a", 64) // duplicate -> ignored
	d.Add("b", 1)

	require.Nil(t, d.m["a"].state.Load().bm, "entry should be cold before first Bitmap()")

	bm, ok := d.Bitmap("a")
	require.True(t, ok)
	require.Equal(t, uint64(3), bm.GetCardinality())
	require.True(t, bm.Contains(5))
	require.True(t, bm.Contains(64))
	require.True(t, bm.Contains(200))

	st := d.m["a"].state.Load()
	require.NotNil(t, st.bm, "entry should be hot after Bitmap()")
	require.Nil(t, st.ids, "ID slice should be dropped on materialisation")

	bm2, _ := d.Bitmap("a")
	require.Same(t, bm, bm2, "subsequent calls return the cached bitmap")

	_, ok = d.Bitmap("missing")
	require.False(t, ok)
}

func TestLazyDimensionRemove(t *testing.T) {
	d := newLazyDimension()
	d.Add("a", 5)
	d.Add("a", 10)

	// remove while cold
	d.Remove("a", 5)
	bm, ok := d.Bitmap("a")
	require.True(t, ok)
	require.False(t, bm.Contains(5))
	require.True(t, bm.Contains(10))

	// remove while hot; key drops when empty
	d.Remove("a", 10)
	_, ok = d.Bitmap("a")
	require.False(t, ok, "key should be dropped once empty")
}

func TestLazyDimensionMarshalSymmetryViaIDs(t *testing.T) {
	d := newLazyDimension()
	ids := []uint32{3, 70, 4096, 100000}
	for _, id := range ids {
		d.Add("p", id)
	}
	// forEachBitmap must reproduce the IDs without mutating (entry stays cold).
	var got []uint32
	require.NoError(t, d.forEachBitmap(func(_ string, bm *Bitmap) error {
		for it := bm.Iterator(); it.HasNext(); {
			got = append(got, it.Next())
		}
		return nil
	}))
	require.Equal(t, ids, got)
	require.Nil(t, d.m["p"].state.Load().bm, "forEachBitmap must not materialise/cache")
}

// TestLazyDimensionConcurrentMaterialize hammers Bitmap() from many goroutines on
// a single cold entry to exercise the materialise CAS. Run with -race.
func TestLazyDimensionConcurrentMaterialize(t *testing.T) {
	d := newLazyDimension()
	const n = 500
	for i := range uint32(n) {
		d.Add("p", i*64+1) // scattered across words
	}

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]*Bitmap, goroutines)
	start := make(chan struct{})
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			bm, _ := d.Bitmap("p")
			results[g] = bm
		}(g)
	}
	close(start)
	wg.Wait()

	final, ok := d.Bitmap("p")
	require.True(t, ok)
	require.Equal(t, uint64(n), final.GetCardinality())
	for _, bm := range results {
		require.NotNil(t, bm)
		require.Same(t, final, bm, "every query must observe the single installed bitmap")
	}
}
