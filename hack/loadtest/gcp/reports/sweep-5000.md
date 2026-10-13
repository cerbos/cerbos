# Provisioning sweep - 5000 policies

Floor (cold, no load): R (Sys-HeapReleased) = 260MiB; settled RSS = 320MiB; off-runtime offset O = 60MiB; build high-water = 323MiB.
Edge 2: soft GOMEMLIMIT = mult x R. Validation: GOMEMLIMIT = 1.5 x (loaded RSS peak - O), the recommended max-RPS backstop. Both pair a hard cgroup MemoryMax = GOMEMLIMIT + O + safety (safety = 0.2 x GOMEMLIMIT; RSS-correct; soft bites before the kernel OOM-kills).
stalls/gaps: 1s windows on the sustained run flagged as stall (>10% of reqs above p95) / gap (<75% of mean throughput) by analyse_latency.sh; clustering tracks GC pressure.

## Edge 1 - sizing (no limit)

| Arm | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|---|
| GOGC=100 | 0.73 GiB | 7.3826% | 5702 | 4799 | 39.62 | 4/0 | ok |
| GOGC=50 | 0.50 GiB | 15.0262% | 4925 | 4200 | 51.44 | 0/0 | ok |
| GOGC=20 | 0.41 GiB | 28.9024% | 3512 | 3000 | 65.32 | 0/0 | ok |

## Edge 2 - backstop cost (GOGC=off; GOMEMLIMIT = mult x R, cgroup = GOMEMLIMIT + O + safety)

| Arm | cgroup | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| mult=2.0 (GOMEMLIMIT 519MiB) | 0.67 GiB | 0.56 GiB | 16.8940% | 4606 | 3900 | 52.29 | 0/0 | ok |
| mult=1.8 (GOMEMLIMIT 467MiB) | 0.61 GiB | 0.51 GiB | 21.0058% | 4233 | 3600 | 57.39 | 0/0 | ok |
| mult=1.5 (GOMEMLIMIT 390MiB) | 0.51 GiB | 0.47 GiB | 46.8582% | 2233 | 1900 | 53.05 | 4/0 | ok |
| mult=1.15 (GOMEMLIMIT 299MiB) | 0.41 GiB | 0.43 GiB | 52.1646% | 2174 | 1800 | 21.29 | 1/0 | ok |

## Validation

| Arm | cgroup | RSS peak | GC CPU% | Max RPS | Sust RPS | p99@sust (ms) | stalls/gaps | outcome |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| GOGC=100, GOMEMLIMIT=1.1GiB (1.5(peak RSS-O)) | 1.26 GiB | 0.73 GiB | 7.4212% | 5703 | 4800 | 39.93 | 13/0 | ok |
| GOGC=100, no GOMEMLIMIT | 0.33 GiB | n/a | n/a% | n/a | n/a | n/a | n/a | oom |
