// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"fmt"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit/local"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

// legacyKeys handles sync markers written by older PDP versions, whose keys
// lack the entry size in the final 4 bytes.
// TODO: rip this out in the future (requires a migration or a stepping-stone
// upgrade policy; a surviving legacy key would panic the modern size decode).
type legacyKeys struct {
	log         *Log
	logger      *zap.Logger
	deleteBatch *badgerv4.WriteBatch
	kind        logsv1.IngestBatch_EntryKind
}

func newLegacyKeys(log *Log, kind logsv1.IngestBatch_EntryKind, logger *zap.Logger) *legacyKeys {
	return &legacyKeys{log: log, kind: kind, logger: logger}
}

// isLegacy reports whether k is a legacy sync marker key.
func (lk *legacyKeys) isLegacy(k []byte) bool {
	return len(k) == local.KeyByteSizeStart
}

// rewriteOversized re-writes an oversized legacy entry through the write path.
// legacyKey must be an owned copy.
func (lk *legacyKeys) rewriteOversized(ctx context.Context, entry *logsv1.IngestBatch_Entry, legacyKey []byte) error {
	switch lk.kind { //nolint:exhaustive
	case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
		if err := lk.log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			return entry.GetAccessLogEntry(), nil
		}); err != nil {
			return err
		}
	case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
		if err := lk.log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
			return entry.GetDecisionLogEntry(), nil
		}); err != nil {
			return err
		}
	}

	return lk.delete(legacyKey)
}

func (lk *legacyKeys) delete(k []byte) error {
	if lk.deleteBatch == nil {
		lk.deleteBatch = lk.log.Db.NewWriteBatch()
	}

	if err := lk.deleteBatch.Delete(k); err != nil {
		if !errors.Is(err, badgerv4.ErrDiscardedTxn) {
			return fmt.Errorf("failed to delete key: %w", err)
		}
		lk.deleteBatch.Cancel()
		lk.deleteBatch = lk.log.Db.NewWriteBatch()
		_ = lk.deleteBatch.Delete(k)
	}

	return nil
}

// flush commits the queued deletions. Failures are logged, not returned:
// the legacy keys will simply be processed again on the next sync run.
func (lk *legacyKeys) flush() {
	if lk.deleteBatch == nil {
		return
	}

	if err := lk.deleteBatch.Flush(); err != nil {
		lk.logger.Warn("Failed to delete legacy keys, will retry on next run",
			zap.Error(err),
			zap.Stringer("kind", lk.kind))
	}
}

// cancel releases the delete batch without committing; safe after flush and
// when no batch was ever created.
func (lk *legacyKeys) cancel() {
	if lk.deleteBatch != nil {
		lk.deleteBatch.Cancel()
	}
}
