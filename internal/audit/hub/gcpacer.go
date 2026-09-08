// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"os"
	"runtime/debug"
	"strconv"
	"sync"

	"go.uber.org/zap"
)

const (
	defaultSyncGCPercent = 10
	syncGCPercentEnvVar  = "CERBOS_AUDIT_SYNC_GC_PERCENT"
)

var syncGCPacer struct {
	sync.Mutex
	depth int
	prev  int
}

// targetSyncGCPercent resolves the sync GC percent from the environment once.
// If the env var is unset or unparsable, it defaults to defaultSyncGCPercent.
// Values from 1 to 100 pace the GC at that value. Anything else disables pacing.
var targetSyncGCPercent = sync.OnceValue(func() int {
	s := os.Getenv(syncGCPercentEnvVar)
	if s == "" {
		return defaultSyncGCPercent
	}

	log := zap.L().Named("auditlog")
	p, err := strconv.Atoi(s)
	if err != nil {
		log.Warn("Ignoring invalid sync GC percent override", zap.String("var", syncGCPercentEnvVar), zap.String("value", s))
		return defaultSyncGCPercent
	}
	if syncGCPacingOff(p) {
		log.Info("GC pacing for audit log sync disabled", zap.String("var", syncGCPercentEnvVar), zap.String("value", s))
	}
	return p
})

func syncGCPacingOff(target int) bool {
	return target > 100 || target < 1
}

// paceSyncGC lowers the GC percent while a sync cycle streams a backlog and
// returns a function restoring the original value. It is safe for the
// concurrent access and decision log streams.
func paceSyncGC() (restore func()) {
	target := targetSyncGCPercent()
	if syncGCPacingOff(target) {
		return func() {}
	}

	syncGCPacer.Lock()
	if syncGCPacer.depth == 0 {
		syncGCPacer.prev = debug.SetGCPercent(target)
	}
	syncGCPacer.depth++
	syncGCPacer.Unlock()

	return func() {
		syncGCPacer.Lock()
		syncGCPacer.depth--
		if syncGCPacer.depth == 0 {
			debug.SetGCPercent(syncGCPacer.prev)
		}
		syncGCPacer.Unlock()
	}
}
