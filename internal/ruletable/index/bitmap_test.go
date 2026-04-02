// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func collectIterator(b *Bitmap) []uint32 {
	var result []uint32
	it := b.Iterator()
	for it.HasNext() {
		result = append(result, it.Next())
	}
	return result
}

func TestBitmapEmpty(t *testing.T) {
	b := NewBitmap()
	require.True(t, b.IsEmpty())
	require.Equal(t, uint64(0), b.GetCardinality())
	require.False(t, b.Contains(0))

	it := b.Iterator()
	require.False(t, it.HasNext())
}

func TestBitmapAddContainsRemove(t *testing.T) {
	b := NewBitmap()
	b.Add(0)
	b.Add(1)
	b.Add(63)
	b.Add(64)
	b.Add(1000)

	for _, id := range []uint32{0, 1, 63, 64, 1000} {
		require.True(t, b.Contains(id), "should contain %d", id)
	}
	for _, id := range []uint32{2, 62, 65, 999, 1001} {
		require.False(t, b.Contains(id), "should not contain %d", id)
	}
	require.Equal(t, uint64(5), b.GetCardinality())

	b.Remove(63)
	require.False(t, b.Contains(63))
	require.Equal(t, uint64(4), b.GetCardinality())

	// Remove non-existent is a no-op.
	b.Remove(9999)
	require.Equal(t, uint64(4), b.GetCardinality())
}

func TestBitmapRemoveUpdatesMeta(t *testing.T) {
	b := NewBitmap()
	b.Add(5)
	require.False(t, b.IsEmpty())

	b.Remove(5)
	require.True(t, b.IsEmpty())
	require.Equal(t, uint64(0), b.meta[0], "meta should be zero after removing last bit in word")
}

func TestBitmapWordBoundaries(t *testing.T) {
	b := NewBitmap()
	boundaries := []uint32{0, 63, 64, 127, 128, 191, 192}
	for _, id := range boundaries {
		b.Add(id)
	}
	require.Equal(t, uint64(len(boundaries)), b.GetCardinality())
	for _, id := range boundaries {
		require.True(t, b.Contains(id), "should contain %d", id)
	}
}

func TestBitmapMetaBoundary(t *testing.T) {
	b := NewBitmap()
	b.Add(63*64 + 5)   // word 63, last word in meta[0]
	b.Add(64*64 + 10)  // word 64, first word in meta[1]
	b.Add(127*64 + 20) // word 127, last word in meta[1]

	require.Equal(t, uint64(3), b.GetCardinality())
	require.True(t, b.Contains(63*64+5))
	require.True(t, b.Contains(64*64+10))
	require.True(t, b.Contains(127*64+20))
}

func TestBitmapIterator(t *testing.T) {
	b := NewBitmap()
	ids := []uint32{0, 1, 63, 64, 100, 500, 1000}
	for _, id := range ids {
		b.Add(id)
	}
	require.Equal(t, ids, collectIterator(b))
}

func TestBitmapIteratorSparse(t *testing.T) {
	b := NewBitmap()
	ids := []uint32{5, 64*64 + 3, 128*64 + 7}
	for _, id := range ids {
		b.Add(id)
	}
	require.Equal(t, ids, collectIterator(b))
}

func TestBitmapOr(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(3)
	a.Add(100)

	b := NewBitmap()
	b.Add(2)
	b.Add(3)
	b.Add(200)

	a.Or(b)

	require.Equal(t, []uint32{1, 2, 3, 100, 200}, collectIterator(a))
}

func TestBitmapOrIntoEmpty(t *testing.T) {
	a := NewBitmap()
	b := NewBitmap()
	b.Add(42)

	a.Or(b)
	require.True(t, a.Contains(42))
}

func TestBitmapOrDifferentSizes(t *testing.T) {
	a := NewBitmap()
	a.Add(1)

	b := NewBitmap()
	b.Add(5000)

	a.Or(b)
	require.True(t, a.Contains(1))
	require.True(t, a.Contains(5000))

	// Reverse direction.
	c := NewBitmap()
	c.Add(5000)

	d := NewBitmap()
	d.Add(1)

	c.Or(d)
	require.True(t, c.Contains(1))
	require.True(t, c.Contains(5000))
}

func TestBitmapOrCommutativity(t *testing.T) {
	makeAB := func() (*Bitmap, *Bitmap) {
		a := NewBitmap()
		a.Add(1)
		a.Add(64)
		a.Add(200)

		b := NewBitmap()
		b.Add(2)
		b.Add(64)
		b.Add(300)
		return a, b
	}

	a1, b1 := makeAB()
	a1.Or(b1)

	a2, b2 := makeAB()
	b2.Or(a2)

	require.Equal(t, collectIterator(a1), collectIterator(b2))
}

func TestBitmapAnd(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(3)
	a.Add(100)

	b := NewBitmap()
	b.Add(2)
	b.Add(3)
	b.Add(100)

	a.And(b)

	require.Equal(t, []uint32{3, 100}, collectIterator(a))
}

func TestBitmapAndEmpty(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(2)

	b := NewBitmap()

	a.And(b)
	require.True(t, a.IsEmpty())
}

func TestBitmapAndDifferentSizes(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(5000)

	b := NewBitmap()
	b.Add(1)

	a.And(b)
	require.True(t, a.Contains(1))
	require.False(t, a.Contains(5000), "beyond b's range should be cleared")
	require.Equal(t, uint64(1), a.GetCardinality())
}

func TestBitmapAndDisjointClearsMeta(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(2)

	b := NewBitmap()
	b.Add(3)

	a.And(b)

	require.True(t, a.IsEmpty())
	for _, m := range a.meta {
		require.Equal(t, uint64(0), m, "meta should be zero after disjoint And")
	}
}

func TestBitmapClear(t *testing.T) {
	b := NewBitmap()
	b.Add(1)
	b.Add(100)
	b.Add(5000)

	b.Clear()

	require.True(t, b.IsEmpty())
	require.Equal(t, uint64(0), b.GetCardinality())
	require.False(t, b.Contains(1))
	require.False(t, b.Contains(100))
	require.False(t, b.Contains(5000))
}

func TestBitmapClearAndReuse(t *testing.T) {
	b := NewBitmap()
	b.Add(100)
	b.Add(200)
	b.Clear()

	b.Add(50)
	require.Equal(t, uint64(1), b.GetCardinality())
	require.True(t, b.Contains(50))
	require.False(t, b.Contains(100), "stale data after Clear")
	require.False(t, b.Contains(200), "stale data after Clear")
}

func TestBitmapClearAndReuseWithGrowth(t *testing.T) {
	b := NewBitmap()
	b.Add(5000) // forces large allocation
	b.Clear()

	// Reuse with a smaller range — grow into old capacity.
	b.Add(10)
	require.Equal(t, uint64(1), b.GetCardinality())
	require.False(t, b.Contains(5000), "stale bit after Clear + smaller reuse")

	// Grow back to the original range.
	b.Add(5000)
	require.Equal(t, uint64(2), b.GetCardinality())
}

func TestBitmapWordsLen(t *testing.T) {
	a := NewBitmap()
	require.Equal(t, 0, a.WordsLen())

	a.Add(0) // word 0
	require.Equal(t, 1, a.WordsLen())

	a.Add(63) // still word 0
	require.Equal(t, 1, a.WordsLen())

	a.Add(64) // word 1
	require.Equal(t, 2, a.WordsLen())

	b := NewBitmap()
	b.Add(5000) // word 78
	require.Greater(t, b.WordsLen(), a.WordsLen())
}

func TestBitmapGetCardinalityFullWord(t *testing.T) {
	b := NewBitmap()
	for i := uint32(0); i < 64; i++ {
		b.Add(i)
	}
	require.Equal(t, uint64(64), b.GetCardinality())

	b.Add(1000)
	b.Add(2000)
	require.Equal(t, uint64(66), b.GetCardinality())
}

func TestBitmapIsEmptyAfterRemoveAll(t *testing.T) {
	b := NewBitmap()
	ids := []uint32{5, 10, 64, 128}
	for _, id := range ids {
		b.Add(id)
	}
	for _, id := range ids {
		b.Remove(id)
	}
	require.True(t, b.IsEmpty())
}

func TestBitmapPoolRoundtrip(t *testing.T) {
	bm := bitmapPool.Get().(*Bitmap)
	bm.Add(10)
	bm.Add(20)
	bm.Clear()
	bitmapPool.Put(bm)

	bm2 := bitmapPool.Get().(*Bitmap)
	require.True(t, bm2.IsEmpty(), "bitmap from pool after Clear should be empty")

	bm2.Add(30)
	require.False(t, bm2.Contains(10), "stale data from pooled bitmap")
	require.False(t, bm2.Contains(20), "stale data from pooled bitmap")
	require.True(t, bm2.Contains(30))
	bm2.Clear()
	bitmapPool.Put(bm2)
}

func TestBitmapMarshalRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		ids  []uint32
	}{
		{name: "empty", ids: nil},
		{name: "single", ids: []uint32{42}},
		{name: "word_boundaries", ids: []uint32{0, 63, 64, 127, 128}},
		{name: "sparse", ids: []uint32{5, 64*64 + 3, 128*64 + 7}},
		{name: "dense", ids: func() []uint32 {
			ids := make([]uint32, 64)
			for i := range ids {
				ids[i] = uint32(i)
			}
			return ids
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := NewBitmap()
			for _, id := range tt.ids {
				orig.Add(id)
			}

			buf, err := orig.MarshalBinary()
			require.NoError(t, err)

			restored := NewBitmap()
			_, err = restored.UnmarshalBinary(buf)
			require.NoError(t, err)

			require.Equal(t, collectIterator(orig), collectIterator(restored))
			require.Equal(t, orig.GetCardinality(), restored.GetCardinality())
			require.Equal(t, len(orig.words), len(restored.words))
			require.Equal(t, len(orig.meta), len(restored.meta))
		})
	}
}

func TestBitmapUnmarshalErrors(t *testing.T) {
	b := NewBitmap()
	_, err := b.UnmarshalBinary(nil)
	require.Error(t, err, "nil buffer")
	_, err = b.UnmarshalBinary([]byte{1, 2})
	require.Error(t, err, "too short")
	_, err = b.UnmarshalBinary([]byte{1, 2, 1, 2})
	require.Error(t, err, "truncated words")
}

func TestBitmapArenaOrInto(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(3)

	b := NewBitmap()
	b.Add(2)
	b.Add(3)

	arena := newBitmapArena()
	defer arena.release()

	result := arena.orInto([]*Bitmap{a, b})
	require.Equal(t, []uint32{1, 2, 3}, collectIterator(result))
}

func TestBitmapArenaAnd2(t *testing.T) {
	a := NewBitmap()
	a.Add(1)
	a.Add(3)
	a.Add(100)

	b := NewBitmap()
	b.Add(3)
	b.Add(100)
	b.Add(200)

	arena := newBitmapArena()
	defer arena.release()

	result := arena.and2(a, b)
	require.Equal(t, []uint32{3, 100}, collectIterator(result))
}

func TestBitmapArenaAndInto(t *testing.T) {
	a := NewBitmap()
	for i := uint32(0); i < 100; i++ {
		a.Add(i)
	}

	b := NewBitmap()
	for i := uint32(50); i < 150; i++ {
		b.Add(i)
	}

	c := NewBitmap()
	for i := uint32(75); i < 200; i++ {
		c.Add(i)
	}

	arena := newBitmapArena()
	defer arena.release()

	result := arena.andInto([]*Bitmap{a, b, c})
	got := collectIterator(result)

	require.Len(t, got, 25)
	for i, id := range got {
		require.Equal(t, uint32(75+i), id)
	}
}
