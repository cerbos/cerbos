// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"errors"
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
	store, bucket := mkStore(t, dir, false)
	internal.TestSuiteReloadable(store, false, mkPoliciesToStoreFn(t, bucket))(t)

	dir = t.TempDir()
	store, bucket = mkStore(t, dir, true)
	internal.TestSuiteReloadable(store, true, mkPoliciesToStoreFn(t, bucket))(t)
}

func mkStore(t *testing.T, dir string, watchForChanges bool) (*Store, *blob.Bucket) {
	t.Helper()

	endpoint := startMinio(context.Background(), t, bucketName)
	conf := mkConf(t, dir, bucketName, endpoint, watchForChanges)
	bucket, err := newBucket(context.Background(), conf)
	require.NoError(t, err)
	cloner, err := NewCloner(bucket, storeFS{dir})
	require.NoError(t, err)
	store, err := NewStore(context.Background(), conf, cloner)
	require.NoError(t, err)

	return store, bucket
}

func mkPoliciesToStoreFn(t *testing.T, bucket *blob.Bucket) internal.PoliciesToStoreFn {
	t.Helper()

	return func() error {
		_, err := uploadDirToBucket(t, context.Background(), test.PathToDir(t, "store"), bucket)
		if err != nil {
			return err
		}
		return nil
	}
}

func mkConf(t *testing.T, dir, bucketName, endpoint string, watchForChanges bool) *Conf {
	t.Helper()

	upi := 2 * time.Second
	if !watchForChanges {
		upi = 0
	}

	conf := &Conf{WorkDir: dir}
	conf.SetDefaults()
	conf.UpdatePollInterval = upi
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
