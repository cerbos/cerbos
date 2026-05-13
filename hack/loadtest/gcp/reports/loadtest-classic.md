# Load Test -- Classic Policies Scaling (800 → 80K)

**Date:** 2026-05-12  
**Environment:** GCP c3-standard-4 PDP (4 vCPU), e2-standard-4 client, disk storage  
**Cerbos version:** latest  
**Config:** concurrency=100, connections=5, mixed requests (cr_req01 + cr_req02), sustained-rate target at ~80% of throughput ceiling (120s), 100K iterations (throughput)

## Summary

- Throughput degrades gradually from 800 to 80K policies -- no cliff.
- p99 latency roughly doubles per 10x policy increase under sustained load at 80% of capacity.
- Memory grows worse than linearly with policy count (O(n²) bitmap index).
- Only 80K policies exhibit stalls and throughput gaps from GC pressure.

---

## Memory Consumption

| Policies | RSS | Heap Alloc | Heap Sys | Heap In-Use | GC Overhead |
|---------:|----:|-----------:|---------:|------------:|------------:|
| 800 | 225 MiB | 57 MiB | 163 MiB | 115 MiB | 5.6 MiB |
| 8K | 1.1 GiB | 313 MiB | 1.7 GiB | 913 MiB | 22 MiB |
| 24K | 3.3 GiB | 617 MiB | 4.8 GiB | 2.6 GiB | 54 MiB |
| 40K | 5.1 GiB | 1.8 GiB | 7.0 GiB | 4.5 GiB | 83 MiB |
| 80K | 11 GiB | 3.9 GiB | 14 GiB | 9.1 GiB | 159 MiB |

**Legend:** RSS = `process_resident_memory_bytes`, Heap Alloc = `go_memstats_heap_alloc_bytes`, Heap Sys = `go_memstats_heap_sys_bytes`, Heap In-Use = `go_memstats_heap_inuse_bytes`, GC Overhead = `go_memstats_gc_sys_bytes`

Heap alloc grows worse than linearly: from 40K to 80K, policies double but heap alloc more than doubles (1.8 GiB → 3.9 GiB). RSS follows a similar pattern (5.1 GiB → 11 GiB).

### Root cause: O(n²) bitmap index memory

`pprof -alloc_space` and bitmap index stats identified `Bitmap.ensure` (bitmap resizing during index construction) as the primary allocator. The bitmap index stores per-dimension bitmaps where both the **number of bitmaps** (keys) and the **width of each bitmap** (binding ID range) grow with policy count. Doubling policies doubles both → 4x memory per dimension.

| Dimension | 40K keys | 40K avg words | 40K est. | 80K keys | 80K avg words | 80K est. | Ratio |
|-----------|--------:|--------------:|---------:|--------:|--------------:|---------:|------:|
| resource | 5,002 | 1,435 | 55 MiB | 10,002 | 2,867 | 220 MiB | 4x |
| principal | 5,000 | 871 | 33 MiB | 10,000 | 1,725 | 132 MiB | 4x |

Total estimated bitmap memory: ~88 MiB at 40K, ~352 MiB at 80K. The bitmap index is the primary driver of the worse-than-linear heap growth. (Note: the `fqnBindings` dimension was previously the largest contributor at ~790 MiB for 80K policies but has since been converted from a bitmap to a map, eliminating that cost.)

This is a deliberate space-time tradeoff. The two-level meta structure enables O(cardinality) iteration and O(1) skipping of empty regions in `Or`/`And` operations. The O(n²) memory cost is the price for fast bitmap operations.

### Roaring bitmap comparison

The two-level layered bitmap replaced roaring bitmaps. Performance improvement over roaring:

| Metric | 800 roaring | 800 layered | Delta | 8K roaring | 8K layered | Delta |
|--------|------------:|------------:|------:|-----------:|-----------:|------:|
| Throughput RPS | 5,167 | 7,953 | **+54%** | 2,270 | 6,323 | **+178%** |
| p99 sustained | 42.99 ms | 24.24 ms | -44% | 100.90 ms | 39.91 ms | -60% |
| RSS | 210 MiB | 233 MiB | +10% | 1.1 GiB | 1.1 GiB | same |

The layered bitmap delivers 54–178% higher throughput and 44–60% lower p99 latency at the cost of ~10% more memory at low policy counts (negligible at 8K+).

GC overhead grows 26x from 800 to 80K policies.

## Requests Per Second

| Policies | Sustained RPS (target) | Throughput (max) |
|---------:|-----------------------:|-----------------:|
| 800 | 7,000 (7K) | 7,658 |
| 8K | 5,000 (5K) | 6,469 |
| 24K | 4,399 (4.4K) | 5,516 |
| 40K | 4,000 (4K) | 4,877 |
| 80K | 3,300 (3.3K) | 3,820 |

Sustained-rate targets are set to ~80% of throughput ceiling and all achieved. Throughput degrades gradually: 7.7K (800) → 6.5K (8K) → 5.5K (24K) → 4.9K (40K) → 3.8K (80K). No cliff -- the decline is smooth.

## Tail Latencies -- Sustained-Rate Test (ms)

| Percentile | 800 (7K) | 8K (5K) | 24K (4.4K) | 40K (4K) | 80K (3.3K) |
|------------|-----:|-----:|-----:|-----:|-----:|
| p50 | 4.13 | 1.19 | 1.79 | 1.37 | 11.56 |
| p90 | 12.94 | 16.89 | 23.78 | 28.55 | 40.41 |
| p95 | 16.56 | 22.13 | 30.24 | 35.51 | 49.24 |
| p99 | 24.53 | 31.73 | 42.44 | 48.35 | 73.26 |
| max | 56.01 | 75.49 | 83.48 | 96.80 | 390.17 |

With sustained-rate targets below capacity, p50 is very low at 8K–40K (1–2ms) -- most requests complete quickly with headroom available. GC pressure, larger bitmap operations, and more CEL evaluations push up the tail (p99, max, CV), and this effect grows with policy count.

### p99 scaling per 10x policy increase

| Step | p99 ratio |
|------|----------:|
| 800 → 8K | 1.29x |
| 8K → 80K | 2.31x |

p99 roughly doubles per 10x policy increase at the 8K→80K step. The 800→8K step shows a smaller ratio (1.29x) because the 800-policy test runs closer to saturation (7K target vs 7.7K ceiling = 91%) than the other runs (~80%).

## Tail Latencies -- Throughput Test (ms)

| Percentile | 800 | 8K | 24K | 40K | 80K |
|------------|-----:|-----:|-----:|-----:|-----:|
| p50 | 9.08 | 11.66 | 14.32 | 16.25 | 22.16 |
| p90 | 22.90 | 25.00 | 28.87 | 32.69 | 41.56 |
| p95 | 27.92 | 30.09 | 34.05 | 39.19 | 48.47 |
| p99 | 36.16 | 41.92 | 45.19 | 52.62 | 61.87 |
| max | 61.29 | 113.66 | 93.57 | 101.72 | 102.26 |

## CPU Utilization (% of all cores)

| Policies | PDP avg | PDP max | Client avg | Client max |
|---------:|--------:|--------:|-----------:|-----------:|
| 800 | 64% | 93% | 61% | 80% |
| 8K | 60% | 95% | 58% | 84% |
| 24K | 58% | 99% | 56% | 98% |
| 40K | 57% | 100% | 55% | 98% |
| 80K | 53% | 100% | 52% | 91% |

With corrected RPS targets (~80% of capacity), PDP avg CPU is 53–64% in sustained-rate tests. Max CPU still hits 100% at 24K+ from GC spikes. Client VM is not a bottleneck (max spikes are isolated GC events, not sustained saturation).

## Error Rates

| Policies | OK | Unavailable | Error Rate |
|---------:|--------:|------------:|-----------:|
| 800 | 839,904 | 87 | 0.010% |
| 8K | 599,991 | 2 | 0.000% |
| 24K | 527,763 | 100 | 0.019% |
| 40K | 479,972 | 2 | 0.000% |
| 80K | 395,969 | 5 | 0.001% |

All errors are `Unavailable` (connection resets), not application errors. Error clustering analysis shows these are isolated events (typically clustered in 1–2 time windows), not systemic. Throughput tests had zero errors.

## Stalls and Throughput Gaps (sustained-rate, p99 threshold)

Stall = window where >10% of requests exceed p99 latency.
Gap = window where throughput drops below 75% of the mean.

| Suite | p99 (ms) | CV | Stalls | Gaps |
|------:|---------:|---:|-------:|-----:|
| 800 policies | 24.53 | 61% | 0 | 0 |
| 8K policies | 31.73 | 71% | 0 | 0 |
| 24K policies | 42.44 | 75% | 0 | 0 |
| 40K policies | 48.35 | 129% | 0 | 0 |
| 80K policies | 73.26 | 247% | 8 | 8 |

### 80K policies -- stalls and throughput gaps

8 stalls and 8 throughput gaps (out of 120 windows), consistent with periodic GC pauses under the 11 GiB heap. The 390ms max latency spike also points to GC pressure.

## Connection Count (HOL Blocking Test)

Tested whether HTTP/2 head-of-line blocking affects latency by varying gRPC connection count at 800 policies, 5.4K RPS sustained-rate, 100 workers.

| Metric | 1 conn | 5 conn | 20 conn |
|--------|-------:|-------:|--------:|
| Sustained p50 | 0.77 ms | 1.02 ms | 1.25 ms |
| Sustained p99 | 9.93 ms | 12.72 ms | 14.17 ms |
| Throughput RPS | 7,848 | 7,670 | 7,382 |

Fewer connections is slightly faster -- 1 connection delivers the lowest latency and highest throughput. On a same-zone VPC with near-zero packet loss, HTTP/2 multiplexing works efficiently and HOL blocking is not a factor. More connections add server-side overhead (per-connection goroutines, buffers, flow control) without benefit. The default of 5 connections is fine; real deployments don't need connection pooling beyond gRPC defaults.

## PGO (Profile-Guided Optimization)

A CPU profile collected from a classic 8K-policy throughput test was used as `default.pgo` to rebuild the Cerbos binary. Tests were run at 800 and 8K policies with cr_req01 only (single request type, 7K RPS target).

| Metric | 800 | 800 PGO | Delta | 8K | 8K PGO | Delta |
|--------|-----:|--------:|------:|-----:|-------:|------:|
| Throughput RPS | 7,953 | 7,610 | -4.3% | 6,323 | 6,581 | +4.1% |
| p99 sustained | 24.24 ms | 22.46 ms | -7.3% | 39.91 ms | 38.24 ms | -4.2% |
| p99 throughput | 29.71 ms | 31.04 ms | +4.5% | 40.79 ms | 38.22 ms | -6.3% |

PGO improves 8K consistently (+4% throughput, -4–6% latency). At 800 policies the results are mixed -- sustained-rate p99 improves but throughput drops slightly. Zero stalls or gaps in all PGO runs. Note: these PGO results use the old single-request-type config; re-run with mixed requests and corrected RPS targets is pending.

## Key Takeaways

1. **Memory grows worse than linearly** (O(n²) bitmap index), reaching 11 GiB RSS at 80K.
2. **Throughput degrades gradually from 800 to 80K** -- no cliff. Max RPS: 7.7K (800) → 6.5K (8K) → 5.5K (24K) → 4.9K (40K) → 3.8K (80K).
3. **p99 latency roughly doubles per 10x policy increase** at the 8K→80K step (2.31x) when tested at 80% of capacity.
4. **Stalls and throughput gaps only appear at 80K policies** -- 8 stalls and 8 gaps, consistent with GC pressure under the 11 GiB heap. CV rises from 61% (800) to 247% (80K).
5. **Client VM is not a bottleneck** -- max CPU spikes (up to 98%) are isolated GC events, not sustained saturation.
