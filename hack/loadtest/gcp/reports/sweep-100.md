# Provisioning sweep - 100 policies

Floor (cold, no load): R (Sys-HeapReleased) = 34MiB; settled RSS = 90MiB; off-runtime offset O = 57MiB; build high-water = 92MiB.
Edge 2: soft GOMEMLIMIT = mult x R. Validation: GOMEMLIMIT = 1.5 x (loaded RSS peak - O), the recommended max-RPS backstop. Both pair a hard cgroup MemoryMax = GOMEMLIMIT + O + safety (safety = 0.2 x GOMEMLIMIT; RSS-correct; soft bites before the kernel OOM-kills).
stalls/gaps: 1s windows on the sustained run flagged as stall (>10% of reqs above p95) / gap (<75% of mean throughput) by analyse_latency.sh; clustering tracks GC pressure.

## Edge 1 - sizing (no limit)

| Arm | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|---|
| GOGC=100 | 0.13 GiB | 9.0539% | 8564 | 7300 | 12.86 | 1/0 | ok |
| GOGC=50 | 0.11 GiB | 16.7497% | 7073 | 6000 | 10.16 | 1/0 | ok |
| GOGC=20 | 0.10 GiB | 32.7401% | 4618 | 3900 | 8.39 | 1/0 | ok |

## Edge 2 - backstop cost (GOGC=off; GOMEMLIMIT = mult x R, cgroup = GOMEMLIMIT + O + safety)

| Arm | cgroup | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| mult=2.0 (GOMEMLIMIT 68MiB) | 0.13 GiB | 0.12 GiB | 9.4008% | 8093 | 6900 | 11.10 | 1/0 | ok |
| mult=1.8 (GOMEMLIMIT 61MiB) | 0.13 GiB | 0.12 GiB | 10.5735% | 7468 | 6300 | 9.26 | 1/0 | ok |
| mult=1.5 (GOMEMLIMIT 51MiB) | 0.11 GiB | 0.11 GiB | 16.2001% | 6255 | 5300 | 7.43 | 1/0 | ok |
| mult=1.15 (GOMEMLIMIT 39MiB) | 0.10 GiB | 0.10 GiB | 47.5987% | 2701 | 2300 | 41.86 | 16/0 | ok |

## Validation

| Arm | cgroup | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| GOGC=100, GOMEMLIMIT=119MiB (1.5(peak RSS-O)) | 0.19 GiB | 0.14 GiB | 9.1020% | 8482 | 7200 | 11.14 | 1/0 | ok |
| GOGC=100, no GOMEMLIMIT | 0.09 GiB | 0.13 GiB | 8.7209% | 8688 | 7400 | 12.24 | 2/0 | ok |
