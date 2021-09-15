// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/verify"
)

func TestVerify(t *testing.T) {
	eng := mkEngine(t)

	conf := verify.Config{
		TestsDir: test.PathToDir(t, "verify"),
	}

	// TODO: (cell) add more test cases
	result, err := verify.Verify(context.Background(), eng, conf)
	is := require.New(t)
	is.NoError(err)
	is.NotZero(len(result.Results), "test results")
	is.False(result.Results[0].Skipped)
	is.False(result.Failed)
}

func mkEngine(t *testing.T) *engine.Engine {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir, ScratchDir: t.TempDir()})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), audit.NewNopLog())
	require.NoError(t, err)

	return eng
}
