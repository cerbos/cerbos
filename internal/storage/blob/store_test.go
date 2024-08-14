// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/internal"
	"github.com/cerbos/cerbos/internal/test"
)

var (
	keysInStore []string
	_           bucketCloner = &mockCloner{}
)

type (
	cloneFn func(ctx context.Context) (*CloneResult, error)
	cleanFn func() error
)

func TestNewStore(t *testing.T) {
	ctx := context.Background()

	t.Run("clone failure makes ctor fail", func(t *testing.T) {
		dir := t.TempDir()
		conf := &Conf{WorkDir: dir}
		conf.SetDefaults()
		must := require.New(t)
		_, err := NewStore(
			ctx,
			conf,
			mkMockCloner("", "", nil, func(_ context.Context) (*CloneResult, error) {
				return nil, errors.New("any error")
			}),
		)
		must.Error(err)
	})
	t.Run("Minio bucket test", func(t *testing.T) {
		if testing.Short() {
			t.Skip()
		}
		dir := t.TempDir()
		conf := &Conf{WorkDir: dir}
		conf.SetDefaults()

		must := require.New(t)

		endpoint := StartMinio(ctx, t, bucketName)
		t.Setenv("AWS_ACCESS_KEY_ID", minioUsername)
		t.Setenv("AWS_SECRET_ACCESS_KEY", minioPassword)
		conf.Bucket = MinioBucketURL(bucketName, endpoint)

		bucket, err := newBucket(ctx, conf)
		must.NoError(err)
		_, err = NewStore(ctx, conf, NewCloner(bucket, storeFS{filepath.Join(dir, dotcache)}))
		must.NoError(err)
	})
}

func TestReloadable(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", minioUsername)
	t.Setenv("AWS_SECRET_ACCESS_KEY", minioPassword)

	dir := t.TempDir()
	store, bucket := mkStore(t, dir)
	internal.TestSuiteReloadable(store, mkInitFn(t, bucket), mkAddFn(t, bucket), mkDeleteFn(t, bucket))(t)
}

func TestStore_updateIndex(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	conf := &Conf{WorkDir: dir}
	conf.SetDefaults()

	must := require.New(t)

	policyDir := test.PathToDir(t, "store")
	policyFile := filepath.Join("resource_policies", "policy_02.yaml")
	schemaFile := filepath.Join(schema.Directory, "principal.json")
	noOfClonerCalls := 0
	store, err := NewStore(ctx, conf,
		mkMockCloner(filepath.Join(dir, dotcache), policyDir, nil, func(_ context.Context) (*CloneResult, error) {
			noOfClonerCalls++

			if noOfClonerCalls == 2 { // first call to updateIndex after init
				return &CloneResult{
					all: map[string][]string{
						"policy": {policyFile},
						"schema": {schemaFile},
					},
					addedOrUpdated: []info{
						{
							etag: "policy",
							file: policyFile,
						},
						{
							etag: "schema",
							file: schemaFile,
						},
					},
				}, nil
			} else if noOfClonerCalls == 3 { // second call to updateIndex after init
				return &CloneResult{
					deleted: []info{
						{
							etag: "policy",
							file: policyFile,
						},
						{
							etag: "schema",
							file: schemaFile,
						},
					},
				}, nil
			}

			return &CloneResult{}, nil
		}),
	)
	must.NoError(err)

	mustBeNotified := storage.TestSubscription(store)
	must.NoError(store.updateIndex(ctx))
	must.NoError(store.updateIndex(ctx))
	mustBeNotified(t, 1*time.Second,
		storage.NewSchemaEvent(storage.EventDeleteSchema, "principal.json"),
		storage.Event{
			Kind:     storage.EventAddOrUpdatePolicy,
			PolicyID: namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vstaging"),
		},
		storage.Event{
			Kind:     storage.EventDeleteOrDisablePolicy,
			PolicyID: namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vstaging"),
		},
		storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, "principal.json"),
	)
}

func mkInitFn(t *testing.T, bucket *blob.Bucket) internal.MutateStoreFn {
	t.Helper()

	relDir := filepath.Join("..", "testdata")
	testdataDir, err := filepath.Abs(relDir)
	require.NoError(t, err)

	return func() error {
		var err error
		keysInStore, err = uploadDirToBucket(t, context.Background(), testdataDir, bucket)
		if err != nil {
			return fmt.Errorf("failed to add to the store: %w", err)
		}
		return nil
	}
}

func mkDeleteFn(t *testing.T, bucket *blob.Bucket) internal.MutateStoreFn {
	t.Helper()

	return func() error {
		for _, key := range keysInStore {
			err := bucket.Delete(context.Background(), key)
			if err != nil {
				return fmt.Errorf("failed to delete from the store: %w", err)
			}
		}

		return nil
	}
}

func mkAddFn(t *testing.T, bucket *blob.Bucket) internal.MutateStoreFn {
	t.Helper()

	return func() error {
		var err error
		keysInStore, err = uploadDirToBucket(t, context.Background(), test.PathToDir(t, "store"), bucket)
		if err != nil {
			return fmt.Errorf("failed to add to the store: %w", err)
		}
		return nil
	}
}

func mkStore(t *testing.T, dir string) (*Store, *blob.Bucket) {
	t.Helper()

	endpoint := StartMinio(context.Background(), t, bucketName)
	conf := mkConf(t, dir, bucketName, endpoint)
	bucket, err := newBucket(context.Background(), conf)
	require.NoError(t, err)
	store, err := NewStore(context.Background(), conf, NewCloner(bucket, storeFS{filepath.Join(dir, dotcache)}))
	require.NoError(t, err)

	return store, bucket
}

func mkConf(t *testing.T, dir, bucketName, endpoint string) *Conf {
	t.Helper()

	conf := &Conf{WorkDir: dir}
	conf.SetDefaults()
	conf.Bucket = MinioBucketURL(bucketName, endpoint)

	return conf
}

func mkMockCloner(cacheDir, policyDir string, clean cleanFn, clone cloneFn) *mockCloner {
	return &mockCloner{
		cacheDir:  cacheDir,
		cleanFn:   clean,
		cloneFn:   clone,
		policyDir: policyDir,
	}
}

type mockCloner struct {
	cacheDir  string
	policyDir string
	cleanFn   cleanFn
	cloneFn   cloneFn
}

func (mc *mockCloner) Clean() error {
	if mc.cleanFn != nil {
		return mc.cleanFn()
	}

	return nil
}

func (mc *mockCloner) Clone(ctx context.Context) (*CloneResult, error) {
	cr, err := mc.cloneFn(ctx)
	if err != nil {
		return nil, err
	}

	if mc.cacheDir != "" && mc.policyDir != "" {
		for _, i := range cr.addedOrUpdated {
			f, err := os.Open(filepath.Join(mc.policyDir, i.file))
			if err != nil {
				return nil, err
			}

			fBytes, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}

			path := filepath.Join(mc.cacheDir, i.etag)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return nil, err
			}

			if err := os.WriteFile(path, fBytes, 0o600); err != nil {
				return nil, err
			}
		}
	}

	return cr, nil
}
