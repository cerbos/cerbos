# Provisioning sweep - 1000 policies

Floor (cold, no load): R (Sys-HeapReleased) = 76MiB; settled RSS = 131MiB; off-runtime offset O = 56MiB; build high-water = 129MiB.
Edge 2: soft GOMEMLIMIT = mult x R. Validation: GOMEMLIMIT = 1.5 x (loaded RSS peak - O), the recommended max-RPS backstop. Both pair a hard cgroup MemoryMax = GOMEMLIMIT + O + safety (safety = 0.2 x GOMEMLIMIT; RSS-correct; soft bites before the kernel OOM-kills).
stalls/gaps: 1s windows on the sustained run flagged as stall (>10% of reqs above p95) / gap (<75% of mean throughput) by analyse_latency.sh; clustering tracks GC pressure.

## Edge 1 - sizing (no limit)

| Arm | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|---|
| GOGC=100 | 0.22 GiB | 9.1576% | 7657 | 6500 | 22.88 | 1/0 | ok |
| GOGC=50 | 0.16 GiB | 18.0094% | 6504 | 5500 | 22.93 | 1/0 | ok |
| GOGC=20 | 0.15 GiB | 33.5182% | 4282 | 3600 | 17.41 | 2/0 | ok |

## Edge 2 - backstop cost (GOGC=off; GOMEMLIMIT = mult x R, cgroup = GOMEMLIMIT + O + safety)

| Arm | cgroup | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| mult=2.0 (GOMEMLIMIT 152MiB) | 0.23 GiB | 0.20 GiB | 12.0280% | 6771 | 5800 | 20.15 | 2/0 | ok |
| mult=1.8 (GOMEMLIMIT 137MiB) | 0.21 GiB | 0.19 GiB | 14.0293% | 6628 | 5600 | 21.99 | 1/0 | ok |
| mult=1.5 (GOMEMLIMIT 114MiB) | 0.19 GiB | 0.17 GiB | 20.5822% | 5506 | 4700 | 19.48 | 1/0 | ok |
| mult=1.15 (GOMEMLIMIT 87MiB) | 0.16 GiB | 0.15 GiB | 50.8907% | 2633 | 2200 | 102.90 | 24/0 | ok |

## Validation

| Arm | cgroup | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| GOGC=100, GOMEMLIMIT=254MiB (1.5(peak RSS-O)) | 0.35 GiB | 0.22 GiB | 9.0102% | 7704 | 6500 | 23.02 | 2/0 | ok |
| GOGC=100, no GOMEMLIMIT | 0.13 GiB | n/a | n/a% | n/a | n/a | n/a | n/a | oom |
