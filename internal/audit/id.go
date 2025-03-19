// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"io"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"
)

var idGen = NewIDGen(uint64(runtime.NumCPU()), time.Now().UnixNano())

type (
	ID      string
	IDBytes = ulid.ULID
)

func (id ID) Repr() (IDBytes, error) {
	return ulid.ParseStrict(string(id))
}

// FromRepr converts the byte representation to a string ID.
func FromRepr(id IDBytes) ID {
	return ID(id.String())
}

// NewID generates a new ULID using the current time.
func NewID() (ID, error) {
	return idGen.New()
}

// NewIDForTime generates a new ULID using the given time.
func NewIDForTime(ts time.Time) (ID, error) {
	return idGen.NewForTime(ts)
}

// NewIDForTS generates a new ULID for the given timestamp.
func NewIDForTS(ts uint64) (ID, error) {
	return idGen.NewForTS(ts)
}

// IDGen is a generator for ULIDs without the monotonicity guarantee.
// Monotonicity adds overhead that we don't really need because approximate order
// is good enough for decision logs.
type IDGen struct {
	randPool *randPool
}

func NewIDGen(poolSize uint64, randSeed int64) *IDGen {
	return &IDGen{
		randPool: newRandPool(poolSize, randSeed),
	}
}

// New generates a new ULID using the current time.
func (ug *IDGen) New() (ID, error) {
	return ug.NewForTime(time.Now())
}

// NewForTime generates a new ULID using the given time.
func (ug *IDGen) NewForTime(ts time.Time) (ID, error) {
	return ug.NewForTS(ulid.Timestamp(ts))
}

// NewForTS generates a new ULID for the given timestamp.
func (ug *IDGen) NewForTS(ts uint64) (ID, error) {
	entropy := ug.randPool.get()
	idBytes, err := ulid.New(ts, entropy)
	if err != nil {
		return "", err
	}

	return FromRepr(idBytes), nil
}

// randPool is a pool of rand objects used to produce random bytes for ID generation.
type randPool struct {
	pool    []io.Reader
	counter uint64
	size    uint64
}

// newRandPool creates a random pool of given size (rounded to nearest power of 2) and seeded using the given seed.
func newRandPool(size uint64, seed int64) *randPool {
	s := nearestPowerOfTwo(size)
	rp := &randPool{
		size: s,
		pool: make([]io.Reader, s),
	}

	randSeed := rand.NewSource(seed)
	for i := range int(s) {
		rp.pool[i] = newLockedRand(randSeed.Int63())
	}

	return rp
}

func (rp *randPool) get() io.Reader {
	// fast modulo of powers of 2
	idx := atomic.AddUint64(&rp.counter, 1) & (rp.size - 1)
	return rp.pool[idx]
}

// https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
//
//nolint:mnd
func nearestPowerOfTwo(v uint64) uint64 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	v++

	return v
}

// lockedRand is a rand protected by a mutex because random sources are not thread-safe.
type lockedRand struct {
	rnd *rand.Rand
	mu  sync.Mutex
}

func newLockedRand(seed int64) *lockedRand {
	src := rand.NewSource(seed)
	return &lockedRand{rnd: rand.New(src)} //nolint:gosec
}

func (lr *lockedRand) Read(p []byte) (n int, err error) {
	lr.mu.Lock()
	n, err = lr.rnd.Read(p)
	lr.mu.Unlock()

	return
}
