// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import "math/bits"

// Bitmap is a two-level hierarchical bitset. The first level (words) stores the
// actual bits. The second level (meta) tracks which words are non-zero: bit j of
// meta[i] is set iff words[i*64+j] != 0. This lets bulk operations (And, Or,
// IsEmpty, GetCardinality, iteration) skip empty regions cheaply.
type Bitmap struct {
	words []uint64
	meta  []uint64
}

// NewBitmap returns a new empty Bitmap.
func NewBitmap() *Bitmap {
	return &Bitmap{}
}

func (b *Bitmap) Add(id uint32) {
	wIdx := int(id / 64) //nolint:mnd
	b.ensure(wIdx + 1)
	b.words[wIdx] |= 1 << (id % 64)  //nolint:mnd
	b.meta[wIdx/64] |= 1 << (uint(wIdx) % 64) //nolint:mnd
}

func (b *Bitmap) Remove(id uint32) {
	wIdx := int(id / 64) //nolint:mnd
	if wIdx >= len(b.words) {
		return
	}
	b.words[wIdx] &^= 1 << (id % 64) //nolint:mnd
	if b.words[wIdx] == 0 {
		b.meta[wIdx/64] &^= 1 << (uint(wIdx) % 64) //nolint:mnd
	}
}

func (b *Bitmap) Contains(id uint32) bool {
	wIdx := int(id / 64) //nolint:mnd
	if wIdx >= len(b.words) {
		return false
	}
	return b.words[wIdx]&(1<<(id%64)) != 0 //nolint:mnd
}

func (b *Bitmap) IsEmpty() bool {
	for _, m := range b.meta {
		if m != 0 {
			return false
		}
	}
	return true
}

func (b *Bitmap) GetCardinality() uint64 {
	var n uint64
	for mi, m := range b.meta {
		for m != 0 {
			j := bits.TrailingZeros64(m)
			n += uint64(bits.OnesCount64(b.words[mi*64+j])) //nolint:mnd
			m &^= 1 << j
		}
	}
	return n
}

// WordsLen returns the number of uint64 words in the bitmap. O(1) proxy for
// bitmap size, useful for choosing the shortest operand in AND.
func (b *Bitmap) WordsLen() int {
	return len(b.words)
}

// Or performs in-place union: b = b | other.
func (b *Bitmap) Or(other *Bitmap) {
	b.ensure(len(other.words))
	for mi, m := range other.meta {
		if m == 0 {
			continue
		}
		b.meta[mi] |= m
		base := mi * 64 //nolint:mnd
		for m != 0 {
			j := bits.TrailingZeros64(m)
			b.words[base+j] |= other.words[base+j]
			m &^= 1 << j
		}
	}
}

// And performs in-place intersection: b = b & other.
func (b *Bitmap) And(other *Bitmap) {
	for mi := range b.meta {
		bm := b.meta[mi]
		if bm == 0 {
			continue
		}
		// Fast skip: if meta words don't overlap, clear all words in this group.
		if mi >= len(other.meta) || bm&other.meta[mi] == 0 {
			base := mi * 64 //nolint:mnd
			for m := bm; m != 0; {
				j := bits.TrailingZeros64(m)
				b.words[base+j] = 0
				m &^= 1 << j
			}
			b.meta[mi] = 0
			continue
		}
		base := mi * 64 //nolint:mnd
		newMeta := uint64(0)
		for m := bm; m != 0; {
			j := bits.TrailingZeros64(m)
			wIdx := base + j
			if wIdx < len(other.words) {
				b.words[wIdx] &= other.words[wIdx]
			} else {
				b.words[wIdx] = 0
			}
			if b.words[wIdx] != 0 {
				newMeta |= 1 << j
			}
			m &^= 1 << j
		}
		b.meta[mi] = newMeta
	}
}

// MetaIntersects returns true if the meta-level intersection of all given
// bitmaps is non-empty. This is a cheap necessary condition for the full
// intersection being non-empty — if the meta AND is zero, the bitmaps are
// disjoint and no per-bit work is needed.
func MetaIntersects(bitmaps ...*Bitmap) bool {
	minMeta := len(bitmaps[0].meta)
	for _, bm := range bitmaps[1:] {
		if len(bm.meta) < minMeta {
			minMeta = len(bm.meta)
		}
	}
	for mi := range minMeta {
		combined := bitmaps[0].meta[mi]
		for _, bm := range bitmaps[1:] {
			combined &= bm.meta[mi]
		}
		if combined != 0 {
			return true
		}
	}
	return false
}

// Clear resets the bitmap for reuse, retaining the backing arrays.
func (b *Bitmap) Clear() {
	clear(b.words)
	clear(b.meta)
	b.words = b.words[:0]
	b.meta = b.meta[:0]
}

// Iterator returns a BitmapIterator over the set bits.
func (b *Bitmap) Iterator() BitmapIterator {
	it := BitmapIterator{bm: b}
	it.advance()
	return it
}

// ensure grows words and meta to accommodate at least n words.
func (b *Bitmap) ensure(n int) {
	if n <= len(b.words) {
		return
	}
	needMeta := (n + 63) / 64 //nolint:mnd
	if n <= cap(b.words) {
		b.words = b.words[:n]
		b.meta = b.meta[:needMeta]
		return
	}
	newCap := max(n, cap(b.words)*2)
	newWords := make([]uint64, n, newCap)
	copy(newWords, b.words)
	b.words = newWords

	newMetaCap := (newCap + 63) / 64 //nolint:mnd
	newMeta := make([]uint64, needMeta, newMetaCap)
	copy(newMeta, b.meta)
	b.meta = newMeta
}

// BitmapIterator iterates over set bits in ascending order, using the meta
// level to skip empty word regions.
type BitmapIterator struct {
	bm      *Bitmap
	metaIdx int
	metaW   uint64 // remaining meta bits in current meta word
	word    uint64 // remaining bits in current data word
	wordIdx int    // index of current data word
}

func (it *BitmapIterator) HasNext() bool {
	return it.word != 0
}

func (it *BitmapIterator) Next() uint32 {
	bit := bits.TrailingZeros64(it.word)
	id := uint32(it.wordIdx*64 + bit) //nolint:mnd
	it.word &^= 1 << bit
	if it.word == 0 {
		it.nextWord()
	}
	return id
}

// advance finds the first non-zero data word using meta.
func (it *BitmapIterator) advance() {
	for it.metaIdx < len(it.bm.meta) {
		if it.bm.meta[it.metaIdx] != 0 {
			it.metaW = it.bm.meta[it.metaIdx]
			it.nextWord()
			return
		}
		it.metaIdx++
	}
	it.word = 0
}

// nextWord moves to the next non-zero data word within the current or
// subsequent meta words.
func (it *BitmapIterator) nextWord() {
	for {
		if it.metaW != 0 {
			j := bits.TrailingZeros64(it.metaW)
			it.metaW &^= 1 << j
			it.wordIdx = it.metaIdx*64 + j //nolint:mnd
			it.word = it.bm.words[it.wordIdx]
			if it.word != 0 {
				return
			}
			continue
		}
		it.metaIdx++
		if it.metaIdx >= len(it.bm.meta) {
			it.word = 0
			return
		}
		it.metaW = it.bm.meta[it.metaIdx]
	}
}
