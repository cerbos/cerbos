// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloneResult(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	is := require.New(t)
	ctx := context.Background()
	dir := t.TempDir()
	bucket := newMinioBucket(ctx, t, "policies")
	cloner, err := NewCloner(bucket, storeFS{dir})
	is.NoError(err)
	result, err := cloner.Clone(ctx)
	is.NoError(err)
	is.Len(result.updateOrAdd, 22)
}
