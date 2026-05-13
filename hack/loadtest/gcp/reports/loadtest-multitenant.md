# Load Test -- Multitenant Policies Scaling (800 → 80K)

**Date:** 2026-05-12  
**Environment:** GCP c3-standard-4 PDP (4 vCPU, 16 GB RAM), e2-standard-4 client, disk storage  
**Cerbos version:** latest  
**Config:** concurrency=100, connections=5, mixed requests (cr_req01 + cr_req02), sustained-rate target at ~80% of throughput ceiling (120s), 100K iterations (throughput)

## Summary

- Throughput degrades with policy count, similar to classic policies.
- Memory scales with policy count, reaching 5.9 GiB RSS at 80K.
- Stalls appear only at 80K policies (4 windows); no throughput gaps at any count.
- At 80K policies, max throughput is ~2.8K RPS.

---

## Memory Consumption

| Policies | RSS | Heap Alloc | Heap Sys | Heap In-Use | GC Overhead |
|---------:|----:|-----------:|---------:|------------:|------------:|
| 800 | 150 MiB | 27 MiB | 88 MiB | 48 MiB | 4.8 MiB |
| 8K | 712 MiB | 118 MiB | 639 MiB | 260 MiB | 12 MiB |
| 80K | 5.9 GiB | 4.1 GiB | 8.4 GiB | 5.1 GiB | 77 MiB |

**Legend:** RSS = `process_resident_memory_bytes`, Heap Alloc = `go_memstats_heap_alloc_bytes`, Heap Sys = `go_memstats_heap_sys_bytes`, Heap In-Use = `go_memstats_heap_inuse_bytes`, GC Overhead = `go_memstats_gc_sys_bytes`

Memory grows worse than linearly with policy count (same O(n²) bitmap index pattern as classic policies). Heap alloc: 27 MiB (800) → 118 MiB (8K) → 4.1 GiB (80K).

## Requests Per Second

| Policies | Sustained RPS (target) | Throughput (max) |
|---------:|-----------------------:|-----------------:|
| 800 | 5,400 (5.4K) | 8,127 |
| 8K | 4,500 (4.5K) | 6,921 |
| 80K | 1,700 (1.7K) | 2,815 |

Sustained-rate targets are set to ~80% of throughput ceiling and all achieved. Throughput degrades gradually: 8.1K (800) → 6.9K (8K) → 2.8K (80K).

## Tail Latencies -- Sustained-Rate Test (ms)

| Percentile | 800 (5.4K) | 8K (4.5K) | 80K (1.7K) |
|------------|-----:|-----:|------:|
| p50 | 0.78 | 0.86 | 1.52 |
| p90 | 3.31 | 5.70 | 2.41 |
| p95 | 4.73 | 9.32 | 2.96 |
| p99 | 8.10 | 16.45 | 38.56 |
| max | 24.80 | 71.02 | 137.88 |

With sustained-rate targets below capacity, p50 is sub-millisecond at 800 and 8K. GC pressure and larger bitmap operations push up the tail (p99, max), and this effect grows with policy count. The 80K p90/p95 being lower than 8K reflects the much lower RPS target (1.7K vs 4.5K), but p99 and max are significantly higher due to GC-induced spikes.

### p99 scaling per 10x policy increase

| Step | p99 ratio |
|------|----------:|
| 800 → 8K | 2.03x |
| 8K → 80K | 2.34x |

## Tail Latencies -- Throughput Test (ms)

| Percentile | 800 | 8K | 80K |
|------------|-----:|-----:|------:|
| p50 | 10.13 | 11.24 | 31.03 |
| p90 | 20.10 | 24.56 | 61.75 |
| p95 | 23.38 | 30.10 | 73.57 |
| p99 | 30.51 | 42.57 | 99.54 |
| max | 61.01 | 85.85 | 202.31 |

## Error Rates

| Policies | OK | Unavailable | Error Rate |
|---------:|--------:|------------:|-----------:|
| 800 | 647,995 | 2 | 0.000% |
| 8K | 540,024 | 16 | 0.003% |
| 80K | 203,983 | 2 | 0.001% |

All errors are `Unavailable` (connection resets), not application errors. Error clustering analysis shows these are isolated events. Throughput tests had zero errors.

## Stalls and Throughput Gaps (sustained-rate, p99 threshold)

Stall = window where >10% of requests exceed p99 latency.
Gap = window where throughput drops below 75% of the mean.

| Suite | p99 (ms) | CV | Stalls | Gaps |
|------:|---------:|---:|-------:|-----:|
| 800 policies | 8.10 | 61% | 0 | 0 |
| 8K policies | 16.45 | 83% | 0 | 0 |
| 80K policies | 38.56 | 557% | 4 | 0 |

### 80K policies -- stalls

4 stall windows (out of 120) with >10% slow requests, consistent with GC pressure under the 5.9 GiB heap. No throughput gaps -- the 1.7K RPS target leaves enough headroom that overall throughput recovers between GC pauses.

## Comparison with Classic Policies

| Metric | Classic 800 | Multitenant 800 | Classic 8K | Multitenant 8K | Classic 80K | Multitenant 80K |
|--------|------------:|----------------:|-----------:|---------------:|------------:|----------------:|
| Throughput RPS | 7,658 | 8,127 | 6,469 | 6,921 | 3,820 | 2,815 |
| p99 throughput | 36.16 ms | 30.51 ms | 41.92 ms | 42.57 ms | 61.87 ms | 99.54 ms |
| RSS | 225 MiB | 150 MiB | 1.1 GiB | 712 MiB | 11 GiB | 5.9 GiB |

At 800 and 8K policies, multitenant throughput is slightly **higher** than classic (likely due to fewer bindings per policy reducing bitmap operation cost). At 80K, multitenant is **slower** -- the scope resolution and role policy evaluation path becomes more expensive at scale. Memory is consistently lower for multitenant.

## PGO (Profile-Guided Optimization)

A CPU profile from a classic 8K-policy throughput test was used as `default.pgo`. Multitenant tests were run at 800 and 8K policies with cr_req01 only (single request type, 7K RPS target).

| Metric | 800 | 800 PGO | Delta | 8K | 8K PGO | Delta |
|--------|-----:|--------:|------:|-----:|-------:|------:|
| Sustained RPS | 6,847 | 7,000 | +2.2% | 5,740 | 5,921 | +3.2% |
| Throughput RPS | 6,857 | 7,040 | +2.7% | 5,686 | 5,876 | +3.4% |
| p99 sustained | 37.39 ms | 35.15 ms | -6.0% | 48.56 ms | 46.37 ms | -4.5% |
| p99 throughput | 36.67 ms | 34.96 ms | -4.7% | 48.55 ms | 47.11 ms | -3.0% |
| max sustained | 88.75 ms | 78.03 ms | -12.1% | 111.92 ms | 95.58 ms | -14.6% |

Consistent improvement at both policy counts. PGO from classic 8K helps multitenant too -- the hot paths (bitmap `Or`/`And`) are shared. Zero stalls or gaps in all PGO runs. Note: these PGO results use the old single-request-type config; re-run with mixed requests and corrected RPS targets is pending.

## Key Takeaways

1. **Throughput degrades with policy count** -- max RPS: 8.1K (800) → 6.9K (8K) → 2.8K (80K).
2. **Multitenant is faster than classic at small scale** (800, 8K) but **slower at 80K** -- scope resolution cost dominates at scale.
3. **Memory is lower than classic** -- 5.9 GiB vs 11 GiB at 80K, due to fewer bindings per policy.
4. **Stalls appear only at 80K** (4 windows), no throughput gaps at any count.
5. **p99 roughly doubles per 10x policies** -- 2.03x (800→8K), 2.34x (8K→80K).
