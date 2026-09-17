// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package local_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/audit/local"
)

// TestBlockSizeBackwardCompat checks that a database written with badger's
// previous default 4KB SSTable block size stays fully readable after the
// switch to 64KB blocks.
func TestBlockSizeBackwardCompat(t *testing.T) {
	const numKeys = 2000

	dir := t.TempDir()
	key := func(gen, i int) []byte { return fmt.Appendf(nil, "gen%d-key-%06d", gen, i) }
	value := func(gen, i int) []byte {
		return fmt.Appendf(nil, "gen%d-val-%06d-%s", gen, i, strings.Repeat("x", 1024))
	}

	writeKeys := func(db *badgerv4.DB, gen int) {
		t.Helper()
		wb := db.NewWriteBatch()
		defer wb.Cancel()
		for i := range numKeys {
			require.NoError(t, wb.Set(key(gen, i), value(gen, i)))
		}
		require.NoError(t, wb.Flush())
	}

	checkKeys := func(db *badgerv4.DB, gen int) {
		t.Helper()
		require.NoError(t, db.View(func(txn *badgerv4.Txn) error {
			for i := range numKeys {
				item, err := txn.Get(key(gen, i))
				require.NoError(t, err, "key %s must be readable", key(gen, i))
				v, err := item.ValueCopy(nil)
				require.NoError(t, err)
				require.Equal(t, value(gen, i), v)
			}
			return nil
		}))
	}

	// Generation 1: written with the old 4KB block size.
	oldDB, err := badgerv4.Open(badgerv4.DefaultOptions(dir).WithBlockSize(4 << 10).WithLogger(nil))
	require.NoError(t, err)
	writeKeys(oldDB, 1)
	require.NoError(t, oldDB.Close())

	// Closing flushes the memtable, so the data must be in SSTables now;
	// otherwise the reads below would not exercise 4KB block loads at all.
	ssts, err := filepath.Glob(filepath.Join(dir, "*.sst"))
	require.NoError(t, err)
	require.NotEmpty(t, ssts, "generation 1 must be flushed to SSTables")

	openLog := func() *local.Log {
		t.Helper()
		conf := &local.Conf{}
		conf.SetDefaults()
		conf.StoragePath = dir
		conf.RetentionPeriod = 24 * time.Hour
		conf.Advanced.MaxBatchSize = 32
		conf.Advanced.FlushInterval = 1 * time.Second
		log, err := local.NewLog(conf, nil)
		require.NoError(t, err)
		return log
	}

	// Reopen through the audit backend, which now configures 64KB blocks, and
	// add generation 2 so both block sizes end up coexisting on disk.
	log := openLog()
	require.EqualValues(t, 64<<10, log.Db.Opts().BlockSize, "test must exercise the new block size")
	checkKeys(log.Db, 1)
	writeKeys(log.Db, 2)
	require.NoError(t, log.Close())

	// Reopen once more so generation 2 is read back from 64KB-block SSTables
	// rather than the memtable, alongside generation 1's 4KB-block tables.
	log = openLog()
	defer log.Close()
	checkKeys(log.Db, 1)
	checkKeys(log.Db, 2)
}
