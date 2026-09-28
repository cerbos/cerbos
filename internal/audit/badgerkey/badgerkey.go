// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package badgerkey

import (
	"bytes"
	"encoding/binary"
	"slices"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
)

const (
	kindLen      = 4
	timestampLen = 6
	entropyLen   = 10
	idLen        = timestampLen + entropyLen
	byteSizeLen  = 4
	fixedLen     = kindLen + idLen + byteSizeLen
)

var maxBytes = bytes.Repeat([]byte{0xFF}, fixedLen)

type Kind [4]byte

var (
	KindAccessLogEntry   = Kind{'a', 'a', 'c', 'c'}
	KindDecisionLogEntry = Kind{'a', 'd', 'e', 'c'}
	KindAccessLogSync    = Kind{'b', 's', 'a', 'c'} // 'b' for contiguity with the 'a'-prefixed kinds; 's' for "sync"
	KindDecisionLogSync  = Kind{'b', 's', 'd', 'e'}
)

type Key []byte

const WithoutByteSize = 0

func New(prefix []byte, kind Kind, id audit.IDBytes, byteSize int) Key {
	key, n := newKey(prefix, kind)
	n += copy(key[n:], id[:])

	if byteSize > 0 {
		binary.BigEndian.PutUint32(key[n:], uint32(byteSize))
	}

	return key
}

func KindRange(prefix []byte, kind Kind) (Key, Key) {
	minKey, n := newKey(prefix, kind)
	maxKey := maximize(slices.Clone(minKey), n)
	return minKey, maxKey
}

func TimeRange(prefix []byte, kind Kind, start, end time.Time) (Key, Key) {
	minKey, _ := newKeyWithTime(prefix, kind, start)
	maxKey := maximize(newKeyWithTime(prefix, kind, end))
	return minKey, maxKey
}

func newKey(prefix []byte, kind Kind) (Key, int) {
	key := make(Key, len(prefix)+fixedLen)
	n := copy(key, prefix)
	n += copy(key[n:], kind[:])
	return key, n
}

func newKeyWithTime(prefix []byte, kind Kind, ts time.Time) (Key, int) {
	key, n := newKey(prefix, kind)
	n += copy(key[n:], audit.TimeRepr(ts))
	return key, n
}

func maximize(key Key, n int) Key {
	copy(key[n:], maxBytes)
	return key
}
