// Copyright 2021 Zenauth Ltd.

package disk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/test"
)

func TestBuildIndex(t *testing.T) {
	dir := test.PathToDir(t, "store")

	idx, err := BuildIndex(context.Background(), os.DirFS(dir), ".")
	require.NoError(t, err)
	require.NotNil(t, idx)

	idxImpl, ok := idx.(*index)
	require.True(t, ok)

	data := idxImpl.Inspect()
	require.Len(t, data, 3)

	rp := filepath.Join("resource_policies", "policy_01.yaml")
	pp := filepath.Join("principal_policies", "policy_01.yaml")
	dr := filepath.Join("derived_roles", "derived_roles_01.yaml")

	require.Contains(t, data, rp)
	require.Len(t, data[rp].Dependencies, 1)
	require.Contains(t, data[rp].Dependencies, dr)
	require.Empty(t, data[rp].References)

	require.Contains(t, data, pp)
	require.Empty(t, data[pp].Dependencies)
	require.Empty(t, data[pp].References)

	require.Contains(t, data, dr)
	require.Empty(t, data[dr].Dependencies)
	require.Len(t, data[dr].References, 1)
	require.Contains(t, data[dr].References, rp)
}
