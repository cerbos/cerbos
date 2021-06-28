// Copyright 2021 Zenauth Ltd.

package common

import (
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	decisionlogv1 "github.com/cerbos/cerbos/internal/genpb/decisionlog/v1"
)

// LogEntry is a record read from the decision log.
type LogEntry struct {
	Decision *decisionlogv1.Decision
	Err      error
}

type ULID = ulid.ULID

// ULIDGen is a generator for ULIDs without the monotonicity guarantee.
// Monotonicity adds overhead that we don't really need because approximate order
// is good enough for decision logs.
type ULIDGen struct {
	randPool *RandPool
}

func NewULIDGen(poolSize uint64, randSeed int64) *ULIDGen {
	return &ULIDGen{
		randPool: NewRandPool(poolSize, randSeed),
	}
}

// New generates a new ULID using the current time.
func (ug *ULIDGen) New() (ULID, error) {
	return ug.NewForTime(time.Now())
}

// NewForTime generates a new ULID using the given time.
func (ug *ULIDGen) NewForTime(ts time.Time) (ULID, error) {
	return ug.NewForTS(ulid.Timestamp(ts))
}

// NewForTS generates a new ULID for the given timestamp.
func (ug *ULIDGen) NewForTS(ts uint64) (ULID, error) {
	entropy := ug.randPool.Get()
	return ulid.New(ts, entropy)
}

// RandPool is a pool of rand objects used to produce random bytes for ID generation.
type RandPool struct {
	pool    []io.Reader
	counter uint64
	size    uint64
}

// NewRandPool creates a random pool of given size (rounded to nearest power of 2) and seeded using the given seed.
func NewRandPool(size uint64, seed int64) *RandPool {
	s := nearestPowerOfTwo(size)
	rp := &RandPool{
		size: s,
		pool: make([]io.Reader, s),
	}

	randSeed := rand.NewSource(seed)
	for i := 0; i < int(s); i++ {
		rp.pool[i] = NewLockedRand(randSeed.Int63())
	}

	return rp
}

func (rp *RandPool) Get() io.Reader {
	// fast modulo of powers of 2
	idx := atomic.AddUint64(&rp.counter, 1) & (rp.size - 1)
	return rp.pool[idx]
}

// https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
//nolint:gomnd
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

// LockedRand is a rand protected by a mutex because random sources are not thread-safe.
type LockedRand struct {
	mu  sync.Mutex
	rnd *rand.Rand
}

func NewLockedRand(seed int64) *LockedRand {
	src := rand.NewSource(seed)
	return &LockedRand{rnd: rand.New(src)} //nolint:gosec
}

func (lr *LockedRand) Read(p []byte) (n int, err error) {
	lr.mu.Lock()
	n, err = lr.rnd.Read(p)
	lr.mu.Unlock()

	return
}
