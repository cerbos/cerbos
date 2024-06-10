// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"context"
	"os"
	"testing"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/private/compile"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/spitfire/pkg/bundle/generator"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestFiles(t *testing.T) {
	storeFs := os.DirFS(test.PathToDir(t, "store"))

	index, _, err := compile.Files(context.Background(), storeFs)
	require.NoError(t, err)

	ctx := context.Background()

	tempDir := os.TempDir()
	bundleFileName := "bundlepath"

	out, err := os.CreateTemp(tempDir, bundleFileName)
	bundlePath := out.Name()

	require.NoError(t, err)
	defer out.Close()

	workDir, err := os.MkdirTemp("", "cerbos-bundle-*")
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	meta := &bundlev1.Meta{
		Identifier: "foo",
		Source:     "local",
	}

	_, err = generator.GenerateBundleArchive(ctx, meta, storeFs, out)
	require.NoError(t, err)

	opts := hub.OpenOpts{
		Source:     "local",
		BundlePath: bundlePath,
		ScratchFS:  afero.NewBasePathFs(afero.NewOsFs(), workDir),
		CacheSize:  1024,
	}

	bundle, err := hub.Open(opts)
	require.NoError(t, err)

	store, err := hub.NewLocalSource(hub.LocalParams{
		BundlePath: bundlePath,
		TempDir:    tempDir,
	})
	require.NoError(t, err)

	schemaMgr, err := schema.New(ctx, store)
	require.NoError(t, err)

	auditLog, err := audit.NewLog(ctx)
	require.NoError(t, err)

	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader:  bundle,
		SchemaMgr:     schemaMgr,
		AuditLog:      auditLog,
		RolePolicyMgr: index.GetRolePolicyManager(),
	})
	require.NoError(t, err)

	inputs := []*enginev1.CheckInput{
		{
			RequestId: "1",
			Resource: &enginev1.Resource{
				Kind:          "leave_request",
				PolicyVersion: "20210210",
				Id:            "foo",
				Attr: map[string]*structpb.Value{
					"public": structpb.NewBoolValue(true),
				},
			},
			Principal: &enginev1.Principal{
				Id:            "terry",
				PolicyVersion: "default",
				Roles:         []string{"acme_employee"},
				Scope:         "acme",
			},
			Actions: []string{"create", "view"},
		},
	}

	res, err := eng.Check(ctx, inputs)
	require.NoError(t, err)

	// runtime.Breakpoint()
	_ = res
}
