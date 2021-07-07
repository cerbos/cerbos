// Copyright 2021 Zenauth Ltd.

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
	eng, cancelFunc := mkEngine(t)
	defer cancelFunc()

	conf := verify.Config{
		TestsDir: test.PathToDir(t, "verify"),
	}

	// TODO: (cell) add more test cases
	result, err := verify.Verify(context.Background(), eng, conf)
	require.NoError(t, err)
	require.False(t, result.Failed)
}

func mkEngine(t *testing.T) (*engine.Engine, context.CancelFunc) {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir, ScratchDir: t.TempDir()})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), audit.NewNopLog())
	require.NoError(t, err)

	return eng, cancelFunc
}
