// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"context"
	"os"
	"runtime"
	"testing"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/private/compile"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestFiles(t *testing.T) {
	index, _, err := compile.Files(context.Background(), os.DirFS(test.PathToDir(t, "store")))
	require.NoError(t, err)

	ctx := context.Background()

	store := disk.TempNewStoreWithIndex(ctx, index)

	eng, err := setupEngine(ctx, store, index)
	require.NoError(t, err, "Failed to setup the engine")

	inputs := []*enginev1.CheckInput{
		{
			RequestId: "1",
			Resource: &enginev1.Resource{
				Kind:          "leave_request",
				PolicyVersion: "20210210",
				Id:            "foo",
				Scope:         "acme",
				Attr: map[string]*structpb.Value{
					"public": structpb.NewBoolValue(true),
				},
			},
			Principal: &enginev1.Principal{
				Id:            "terry",
				PolicyVersion: "default",
				Roles:         []string{"acme_employee"},
				Scope:         "",
			},
			Actions: []string{"create", "view"},
		},
	}

	res, err := eng.Check(ctx, inputs)
	require.NoError(t, err)

	runtime.Breakpoint()
	_ = res
}

func setupEngine(ctx context.Context, store *disk.Store, idx index.Index) (*engine.Engine, error) {
	auditLog, err := audit.NewLog(ctx)
	if err != nil {
		return nil, err
	}

	schemaMgr, err := schema.New(ctx, store)
	if err != nil {
		return nil, err
	}

	compileMgr, err := internalcompile.NewManager(ctx, store, schemaMgr, policy.NewRolePolicyManager(idx.GetRolePolicyActionIndexes()))
	if err != nil {
		return nil, err
	}

	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader: compileMgr,
		SchemaMgr:    schemaMgr,
		AuditLog:     auditLog,
	})
	if err != nil {
		return nil, err
	}

	return eng, nil
}
