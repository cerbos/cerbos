// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util_test

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/cespare/xxhash"
	xxhashv2 "github.com/cespare/xxhash/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/test"
)

var dummy uint64

var (
	strPool = &sync.Pool{New: func() any { return xxhashv2.New() }}
	pbPool  = &sync.Pool{New: func() any { return xxhashv2.New() }}
)

func TestXXHashV2(t *testing.T) {
	for i := 0; i < 1000; i++ {
		input := test.RandomStr(50)
		v1 := xxhash.Sum64String(input)
		v2 := xxhashv2.Sum64String(input)
		require.Equal(t, v1, v2)
	}
}

//nolint:gosec
func BenchmarkHashString(b *testing.B) {
	numInp := 10_000
	inputs := make([]string, numInp)
	for i := 0; i < numInp; i++ {
		inputs[i] = test.RandomStr(200)
	}

	b.ResetTimer()
	b.Run("no_pool", func(b *testing.B) {
		b.SetBytes(int64(len(inputs[0])))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h := xxhashv2.Sum64String(inputs[rand.Intn(numInp)])
			dummy += h >> 4
		}
	})

	b.Run("with_pool", func(b *testing.B) {
		b.SetBytes(int64(len(inputs[0])))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h := hashStrPool(inputs[rand.Intn(numInp)])
			dummy += h >> 4
		}
	})
}

func hashStrPool(s string) uint64 {
	d := strPool.Get().(*xxhashv2.Digest)
	_, _ = d.WriteString(s)
	r := d.Sum64()

	d.Reset()
	strPool.Put(d)

	return r
}

//nolint:gosec
func BenchmarkHashPB(b *testing.B) {
	numInp := 10_000
	inputs := make([]*policyv1.Policy, numInp)
	for i := 0; i < numInp; i++ {
		inputs[i] = test.GenResourcePolicy(test.Suffix(test.RandomStr(5)))
	}

	b.ResetTimer()
	b.Run("no_pool", func(b *testing.B) {
		b.SetBytes(int64(proto.Size(inputs[0])))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h := hashPBNoPool(inputs[rand.Intn(numInp)])
			dummy += h >> 4
		}
	})

	b.Run("with_pool", func(b *testing.B) {
		b.SetBytes(int64(proto.Size(inputs[0])))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h := hashPBPool(inputs[rand.Intn(numInp)])
			dummy += h >> 4
		}
	})
}

func hashPBNoPool(pb *policyv1.Policy) uint64 {
	d := xxhashv2.New()
	pb.HashPB(d, nil)
	return d.Sum64()
}

func hashPBPool(pb *policyv1.Policy) uint64 {
	d := pbPool.Get().(*xxhashv2.Digest)
	pb.HashPB(d, nil)
	r := d.Sum64()

	d.Reset()
	pbPool.Put(d)

	return r
}
