// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import "math/bits"

// Bitmap is a flat bitset backed by []uint64. It is a drop-in replacement for
// roaring.Bitmap for the dense, sequential ID space used by the bitmap index.
type Bitmap struct {
	words []uint64
}

// NewBitmap returns a new empty Bitmap.
func NewBitmap() *Bitmap {
	return &Bitmap{}
}

func (b *Bitmap) Add(id uint32) {
	idx := int(id / 64) //nolint:mnd
	b.ensure(idx + 1)
	b.words[idx] |= 1 << (id % 64) //nolint:mnd
}

func (b *Bitmap) Remove(id uint32) {
	idx := int(id / 64) //nolint:mnd
	if idx < len(b.words) {
		b.words[idx] &^= 1 << (id % 64) //nolint:mnd
	}
}

func (b *Bitmap) Contains(id uint32) bool {
	idx := int(id / 64) //nolint:mnd
	if idx >= len(b.words) {
		return false
	}
	return b.words[idx]&(1<<(id%64)) != 0 //nolint:mnd
}

func (b *Bitmap) IsEmpty() bool {
	for _, w := range b.words {
		if w != 0 {
			return false
		}
	}
	return true
}

func (b *Bitmap) GetCardinality() uint64 {
	var n uint64
	for _, w := range b.words {
		n += uint64(bits.OnesCount64(w))
	}
	return n
}

// Len returns the number of uint64 words in the bitmap. This is an O(1)
// proxy for bitmap size, useful for choosing the smallest operand in AND
// without the cost of a full popcount.
func (b *Bitmap) Len() int {
	return len(b.words)
}

// Or performs in-place union: b = b | other.
func (b *Bitmap) Or(other *Bitmap) {
	b.ensure(len(other.words))
	for i, w := range other.words {
		b.words[i] |= w
	}
}

// And performs in-place intersection: b = b & other.
func (b *Bitmap) And(other *Bitmap) {
	minLen := min(len(b.words), len(other.words))
	for i := range minLen {
		b.words[i] &= other.words[i]
	}
	// Words beyond other's length are ANDed with implicit zeros.
	clear(b.words[minLen:])
}

// Clear resets the bitmap for reuse, retaining the backing array.
func (b *Bitmap) Clear() {
	clear(b.words[:cap(b.words)])
	b.words = b.words[:0]
}

// Iterator returns a BitmapIterator over the set bits.
func (b *Bitmap) Iterator() BitmapIterator {
	it := BitmapIterator{words: b.words}
	it.advance()
	return it
}

// ensure grows words to at least n elements if necessary.
func (b *Bitmap) ensure(n int) {
	if n <= len(b.words) {
		return
	}
	if n <= cap(b.words) {
		b.words = b.words[:n]
		return
	}
	newWords := make([]uint64, n, max(n, cap(b.words)*2))
	copy(newWords, b.words)
	b.words = newWords
}

// BitmapIterator iterates over set bits in ascending order.
type BitmapIterator struct {
	words   []uint64
	wordIdx int
	word    uint64
}

func (it *BitmapIterator) HasNext() bool {
	return it.word != 0
}

func (it *BitmapIterator) Next() uint32 {
	bit := bits.TrailingZeros64(it.word)
	id := uint32(it.wordIdx*64 + bit) //nolint:mnd
	it.word &^= 1 << bit
	if it.word == 0 {
		it.wordIdx++
		it.advance()
	}
	return id
}

func (it *BitmapIterator) advance() {
	for it.wordIdx < len(it.words) {
		if it.words[it.wordIdx] != 0 {
			it.word = it.words[it.wordIdx]
			return
		}
		it.wordIdx++
	}
	it.word = 0
}
