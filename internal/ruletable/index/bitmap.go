// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

const (
	wordLenSize = 4 // bytes for the encoded word count (uint32)
	wordSize    = 8 // bytes per uint64 bitmap word
)

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
	i := int(id / 64) //nolint:mnd
	b.ensure(i + 1)
	b.words[i] |= 1 << (id % 64)        //nolint:mnd
	b.meta[i/64] |= 1 << (uint(i) % 64) //nolint:mnd
}

func (b *Bitmap) Remove(id uint32) {
	i := int(id / 64) //nolint:mnd
	if i >= len(b.words) {
		return
	}
	b.words[i] &^= 1 << (id % 64) //nolint:mnd
	if b.words[i] == 0 {
		b.meta[i/64] &^= 1 << (uint(i) % 64) //nolint:mnd
	}
}

func (b *Bitmap) Contains(id uint32) bool {
	i := int(id / 64) //nolint:mnd
	if i >= len(b.words) {
		return false
	}
	return b.words[i]&(1<<(id%64)) != 0 //nolint:mnd
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
	for mi, bm := range b.meta {
		if bm == 0 {
			continue
		}
		// Fast skip: if meta words don't overlap, clear all words in this group.
		base := mi * 64 //nolint:mnd
		if mi >= len(other.meta) || bm&other.meta[mi] == 0 {
			for m := bm; m != 0; {
				j := bits.TrailingZeros64(m)
				b.words[base+j] = 0
				m &^= 1 << j
			}
			b.meta[mi] = 0
			continue
		}
		newMeta := uint64(0)
		for m := bm; m != 0; {
			j := bits.TrailingZeros64(m)
			m &^= 1 << j
			i := base + j
			if i >= len(other.words) {
				b.words[i] = 0
				continue
			}
			b.words[i] &= other.words[i]
			if b.words[i] != 0 {
				newMeta |= 1 << j
			}
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
	nMeta := (n + 63) / 64 //nolint:mnd
	if n <= cap(b.words) {
		b.words = b.words[:n]
		b.meta = b.meta[:nMeta]
		return
	}
	newCap := max(n, cap(b.words)*2) //nolint:mnd
	newWords := make([]uint64, n, newCap)
	copy(newWords, b.words)
	b.words = newWords

	newMetaCap := (newCap + 63) / 64 //nolint:mnd
	newMeta := make([]uint64, nMeta, newMetaCap)
	copy(newMeta, b.meta)
	b.meta = newMeta
}

// MarshalBinary encodes the bitmap as a byte slice. The format is:
// [4 bytes: wordLen (little-endian uint32)] [wordLen * 8 bytes: words] [remaining: meta].
// meta length is derived from wordLen as (wordLen+63)/64.
func (b *Bitmap) MarshalBinary() ([]byte, error) {
	buf := make([]byte, wordLenSize+len(b.words)*wordSize+len(b.meta)*wordSize)
	binary.LittleEndian.PutUint32(buf, uint32(len(b.words)))
	off := wordLenSize
	for _, w := range b.words {
		binary.LittleEndian.PutUint64(buf[off:], w)
		off += wordSize
	}
	for _, m := range b.meta {
		binary.LittleEndian.PutUint64(buf[off:], m)
		off += wordSize
	}
	return buf, nil
}

// UnmarshalBinary decodes a bitmap from a byte slice produced by MarshalBinary.
func (b *Bitmap) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) < wordLenSize {
		return 0, fmt.Errorf("bitmap: buffer too short (%d bytes)", len(buf))
	}
	wLen := int(binary.LittleEndian.Uint32(buf))
	mLen := (wLen + 63) / 64 //nolint:mnd
	expected := wordLenSize + wLen*wordSize + mLen*wordSize
	if len(buf) < expected {
		return 0, fmt.Errorf("bitmap: buffer size %d, expected at least %d", len(buf), expected)
	}
	b.words = make([]uint64, wLen)
	b.meta = make([]uint64, mLen)
	off := wordLenSize
	for i := range b.words {
		b.words[i] = binary.LittleEndian.Uint64(buf[off:]) //nolint:gosec
		off += wordSize
	}
	for i := range b.meta {
		b.meta[i] = binary.LittleEndian.Uint64(buf[off:]) //nolint:gosec
		off += wordSize
	}
	return expected, nil
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

// HasNext reports whether the iterator has remaining IDs.
func (it *BitmapIterator) HasNext() bool {
	return it.word != 0
}

// Next returns the ID of the next set bit in ascending order. Callers must
// check HasNext() before calling Next(); behaviour is undefined if the
// iterator is exhausted. The underlying bitmap must not be modified during
// iteration.
func (it *BitmapIterator) Next() uint32 {
	j := bits.TrailingZeros64(it.word)
	id := uint32(it.wordIdx*64 + j) //nolint:mnd
	it.word &^= 1 << j
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
			if it.word != 0 { // shouldn't be, but check for safety
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

// intersectionNonEmpty returns true if the intersection of all bitmaps is
// non-empty without allocating any new bitmaps. It ANDs words across all
// bitmaps, checking 64 bits at a time, with a meta-level early exit.
func intersectionNonEmpty(bitmaps ...*Bitmap) bool {
	if !MetaIntersects(bitmaps...) {
		return false
	}

	minWords := bitmaps[0].WordsLen()
	for _, bm := range bitmaps[1:] {
		if bm.WordsLen() < minWords {
			minWords = bm.WordsLen()
		}
	}

	for w := range minWords {
		val := bitmaps[0].words[w]
		for _, bm := range bitmaps[1:] {
			val &= bm.words[w]
			if val == 0 {
				break
			}
		}
		if val != 0 {
			return true
		}
	}
	return false
}
