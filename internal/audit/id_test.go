// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
)

var finalTotal uint64

func BenchmarkIDGen(b *testing.B) {
	for i := uint64(2); i <= 64; i *= 2 {
		b.Run(fmt.Sprintf("poolSize=%d", i), func(b *testing.B) {
			gen := audit.NewIDGen(i, time.Now().UnixNano())
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

func TestIDGen(t *testing.T) {
	ids := make(map[audit.ID]struct{}, 1_000_000)
	out := make(chan audit.ID, 8)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			for range 10_000 {
				id, err := audit.NewID()
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
		if _, ok := ids[id]; ok {
			t.Fatalf("Collision: %s", id)
		}

		ids[id] = struct{}{}
	}

	if len(ids) != 1_000_000 {
		t.Fatalf("Expected 1,000,000 unique IDs. Got %d", len(ids))
	}
}
