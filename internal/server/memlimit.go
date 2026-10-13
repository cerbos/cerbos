// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"

	"github.com/KimMachineGun/automemlimit/memlimit"

	"github.com/cerbos/cerbos/internal/observability/logging"
)

// memLimitSafetyFraction is the headroom expressed as a fraction of the
// soft limit: the hard cap equals GOMEMLIMIT + offset + safety, where safety
// = memLimitSafetyFraction * GOMEMLIMIT. Inverting for a known cap gives
// GOMEMLIMIT = (cap - offset) / (1 + memLimitSafetyFraction). This mirrors
// sweep.sh's SAFETY_FRAC, so the auto-configured limit matches the operating
// point the sweep load-test validated.
const memLimitSafetyFraction = 0.2

// fallbackOffsetBytes is the off-runtime offset used when it cannot be measured (R >= RSS): the
// empirically observed footprint (binary text/data, file maps), so GOMEMLIMIT is not set too high.
const fallbackOffsetBytes uint64 = 60 << 20 // 60 MiB

// configureMemoryLimit derives GOMEMLIMIT from the cgroup memory cap so users do not have to
// compute it themselves. It must be called once after the rule table build has settled, so the
// off-runtime offset (binary, stacks, maps) is measured against the cold heap floor.
//
// If GOMEMLIMIT is set explicitly the runtime value is left untouched; if that value cannot
// engage before the kernel OOM-kills, a warning is logged. With no cgroup cap, nothing is set.
func configureMemoryLimit() {
	log := logging.NewLogger("memlimit")

	capBytes, err := memlimit.FromCgroup()
	hasCap := err == nil && capBytes > 0 && capBytes < math.MaxInt64
	if !hasCap {
		return // no cgroup cap to derive from or warn against; leave GOMEMLIMIT as-is
	}

	runtime.GC()
	debug.FreeOSMemory()

	rss, ok := residentBytes()
	if !ok {
		log.Warnw("RSS unreadable; leaving GOMEMLIMIT unchanged", "cgroup_cap_bytes", capBytes)
		return
	}

	settledR := runtimeManagedBytes()
	// Normally RSS > R and the offset is RSS - R. When R >= RSS,
	// fall back to the observed floor rather than a near-zero offset.
	offset := fallbackOffsetBytes
	if rss > settledR {
		offset = rss - settledR
	}

	if gomemlimit := os.Getenv("GOMEMLIMIT"); gomemlimit != "" {
		cur := debug.SetMemoryLimit(-1)
		switch {
		case gomemlimit == "off":
			log.Warnw("GOMEMLIMIT is off", "cgroup_cap_bytes", capBytes)
		case uint64(cur)+offset >= capBytes: // offset is small, so the sum never overflows
			log.Warnw("GOMEMLIMIT is set too high to engage before the kernel OOM-kills",
				"gomemlimit_bytes", cur, "cgroup_cap_bytes", capBytes)
		}
		return
	}

	limit := computeMemLimit(capBytes, offset)
	if limit <= 0 || uint64(limit) <= settledR {
		log.Warnw("cgroup memory cap is too small for a GOMEMLIMIT backstop above the settled floor; leaving GOMEMLIMIT unset",
			"cgroup_cap_bytes", capBytes, "offset_bytes", offset, "floor_bytes", settledR)
		return
	}

	debug.SetMemoryLimit(limit)
	log.Infow("Auto-configured GOMEMLIMIT from the cgroup memory cap", "gomemlimit_bytes", limit, "cgroup_cap_bytes", capBytes,
		"offset_bytes", offset, "safety_fraction", memLimitSafetyFraction)
}

func computeMemLimit(capBytes, offset uint64) int64 {
	if capBytes <= offset {
		return 0
	}
	return int64(math.Round(float64(capBytes-offset) / (1 + memLimitSafetyFraction)))
}

// runtimeManagedBytes is R = Sys - HeapReleased: the runtime-managed memory GOMEMLIMIT accounts
// for (it excludes the binary and other off-runtime memory).
func runtimeManagedBytes() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	if released > total {
		return 0
	}
	return total - released
}

// residentBytes reads the process resident set size from /proc/self/statm (Linux). The bool is
// false when it cannot be read.
func residentBytes() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 { //nolint:mnd
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}
