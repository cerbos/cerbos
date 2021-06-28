// Copyright 2021 Zenauth Ltd.

package common_test

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cerbos/cerbos/internal/decisionlog/common"
)

var finalTotal uint64

func BenchmarkRandomPool(b *testing.B) {
	for i := uint64(2); i <= 64; i *= 2 {
		b.Run(fmt.Sprintf("poolSize=%d", i), func(b *testing.B) {
			gen := common.NewULIDGen(i, time.Now().UnixNano())
			var counter uint64
			b.SetParallelism(1000)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					id, err := gen.New()
					if err != nil {
						panic(err)
					}
					atomic.AddUint64(&counter, uint64(id[1]))
				}
			})

			finalTotal = counter
		})
	}
}

func TestULIDGen(t *testing.T) {
	gen := common.NewULIDGen(uint64(runtime.NumCPU()), time.Now().UnixNano())
	ids := make(map[string]struct{}, 1_000_000)
	out := make(chan ulid.ULID, 8)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 10_000; j++ {
				id, err := gen.New()
				if err != nil {
					panic(err)
				}
				out <- id
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	for id := range out {
		idStr := id.String()
		if _, ok := ids[idStr]; ok {
			t.Fatalf("Collision: %s", idStr)
		}

		ids[idStr] = struct{}{}
	}

	if len(ids) != 1_000_000 {
		t.Fatalf("Expected 1,000,000 unique IDs. Got %d", len(ids))
	}
}
