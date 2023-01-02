// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/storage/internal"
	"github.com/cerbos/cerbos/internal/test"
)

var keysInStore []string

type clonerFunc func(ctx context.Context) (*CloneResult, error)

func (r clonerFunc) Clone(ctx context.Context) (*CloneResult, error) { return r(ctx) }

func TestNewStore(t *testing.T) {
	ctx := context.Background()

	t.Run("partial failure", func(t *testing.T) {
		dir := t.TempDir()
		conf := &Conf{WorkDir: dir}
		conf.SetDefaults()
		must := require.New(t)
		_, err := NewStore(ctx, conf, clonerFunc(func(_ context.Context) (*CloneResult, error) {
			return &CloneResult{failuresCount: 1}, nil
		}))
		must.ErrorIs(err, ErrPartialFailureToDownloadOnInit)
	})
	t.Run("clone failure makes ctor fail", func(t *testing.T) {
		dir := t.TempDir()
		conf := &Conf{WorkDir: dir}
		conf.SetDefaults()
		must := require.New(t)
		_, err := NewStore(ctx, conf, clonerFunc(func(_ context.Context) (*CloneResult, error) {
			return nil, errors.New("any error")
		}))
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

		bucketName := "test"
		endpoint := startMinio(ctx, t, bucketName)
		t.Setenv("AWS_ACCESS_KEY_ID", minioUsername)
		t.Setenv("AWS_SECRET_ACCESS_KEY", minioPassword)
		conf.Bucket = MinioBucketURL(bucketName, endpoint)

		bucket, err := newBucket(ctx, conf)
		must.NoError(err)
		cloner, err := NewCloner(bucket, storeFS{dir})
		must.NoError(err)
		_, err = NewStore(ctx, conf, cloner)
		must.NoError(err)
	})
}

func TestReloadable(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", minioUsername)
	t.Setenv("AWS_SECRET_ACCESS_KEY", minioPassword)

	dir := t.TempDir()
	store, bucket := mkStore(t, dir)
	internal.TestSuiteReloadable(store, mkAddFn(t, bucket), mkDeleteFn(t, bucket))(t)
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

	endpoint := startMinio(context.Background(), t, bucketName)
	conf := mkConf(t, dir, bucketName, endpoint)
	bucket, err := newBucket(context.Background(), conf)
	require.NoError(t, err)
	cloner, err := NewCloner(bucket, storeFS{dir})
	require.NoError(t, err)
	store, err := NewStore(context.Background(), conf, cloner)
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

type mockIndex struct {
	index.Index
	addOrUpdate func(index.Entry) (storage.Event, error)
	delete      func(index.Entry) (storage.Event, error)
}

func (m *mockIndex) AddOrUpdate(e index.Entry) (storage.Event, error) {
	return m.addOrUpdate(e)
}

func (m *mockIndex) Delete(e index.Entry) (storage.Event, error) {
	return m.delete(e)
}

func TestStore_updateIndex(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	conf := &Conf{WorkDir: dir}
	conf.SetDefaults()

	must := require.New(t)

	policyDir := test.PathToDir(t, "store")
	policyFile := filepath.Join("resource_policies", "policy_01.yaml")
	schemaFile := filepath.Join(schema.Directory, "principal.json")
	store, err := NewStore(ctx, conf, clonerFunc(func(_ context.Context) (*CloneResult, error) {
		return &CloneResult{
			updateOrAdd: []string{policyFile, schemaFile},
			delete:      []string{policyFile, schemaFile},
		}, nil
	}))
	must.NoError(err)
	store.fsys = storeFS{dir: policyDir}

	var addOrUpdateCalled bool
	var deleteCalled bool
	addOrUpdateEvent := storage.Event{
		Kind: storage.EventAddOrUpdatePolicy,
	}
	deleteEvent := storage.Event{
		Kind: storage.EventDeletePolicy,
	}
	store.idx = &mockIndex{
		addOrUpdate: func(entry index.Entry) (storage.Event, error) {
			addOrUpdateCalled = true
			must.Equal(entry.File, policyFile)
			return addOrUpdateEvent, nil
		},
		delete: func(entry index.Entry) (storage.Event, error) {
			deleteCalled = true
			must.Equal(entry.File, policyFile)
			return deleteEvent, nil
		},
	}

	mustBeNotified := storage.TestSubscription(store)
	err = store.updateIndex(ctx)
	must.NoError(err)
	must.True(addOrUpdateCalled)
	must.True(deleteCalled)
	mustBeNotified(t, 1*time.Second,
		addOrUpdateEvent,
		deleteEvent,
		storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, "principal.json"),
		storage.NewSchemaEvent(storage.EventDeleteSchema, "principal.json"),
	)
}

func TestStore_AWSS3(t *testing.T) {
	t.Skip("Skip test with real S3 bucket")

	ctx := context.Background()
	dir := t.TempDir()
	conf := &Conf{
		Bucket:  "s3://test-dev.cerbos.dev?region=us-east-2",
		Prefix:  "policies",
		WorkDir: dir,
	}
	conf.SetDefaults()

	must := require.New(t)

	bucket, err := newBucket(ctx, conf)
	must.NoError(err)
	cloner, err := NewCloner(bucket, storeFS{dir})
	must.NoError(err)
	_, err = NewStore(ctx, conf, cloner)
	must.NoError(err)
}
