// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"hash"
	"sync"

	"github.com/cespare/xxhash/v2"
)

var hashPool = &sync.Pool{New: func() any { return xxhash.New() }}

type Hashable interface {
	HashPB(hash.Hash, map[string]struct{})
}

func HashPB(h Hashable, ignore map[string]struct{}) uint64 {
	d := hashPool.Get().(*xxhash.Digest) //nolint:forcetypeassert
	h.HashPB(d, ignore)
	res := d.Sum64()

	d.Reset()
	hashPool.Put(d)

	return res
}

func HashStr(s string) uint64 {
	return xxhash.Sum64String(s)
}
