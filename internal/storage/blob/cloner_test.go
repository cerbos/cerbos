// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/test"
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
	is.Len(result.updateOrAdd, 9)
}

func uploadDirToBucket(ctx context.Context, dir string, bucket *blob.Bucket) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		defer func() { _ = file.Close() }()
		if err != nil {
			return err
		}
		key, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		writer, err := bucket.NewWriter(ctx, key, nil)
		defer func() { _ = writer.Close() }()
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		if err != nil {
			return err
		}
		files = append(files, key)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, err
}

var (
	minioUsername = "minioadmin"
	minioPassword = "minioadmin"
)

func startMinio(ctx context.Context, t *testing.T, bucketName string) string {
	t.Helper()
	is := require.New(t)
	pool, err := dockertest.NewPool("")
	is.NoError(err, "Could not connect to docker: %s", err)

	options := &dockertest.RunOptions{
		Repository: "minio/minio",
		Tag:        "latest",
		Cmd:        []string{"server", t.TempDir()},
		Env:        []string{"MINIO_ACCESS_KEY=" + minioUsername, "MINIO_SECRET_KEY=" + minioPassword},
	}

	resource, err := pool.RunWithOptions(options)
	is.NoError(err, "Could not start resource: %s", err)

	endpoint := fmt.Sprintf("localhost:%s", resource.GetPort("9000/tcp"))

	// Minio health check request
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/minio/health/live", endpoint), nil)
	is.NoError(err)
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	// the minio client does not do service discovery for you (i.e. it does not check if connection can be established), so we have to use the health check
	err = pool.Retry(func() error {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}
		return nil
	})
	is.NoError(err, "Could not connect to docker: %s", err)

	// now we can instantiate minio client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(minioUsername, minioPassword, ""),
		Secure: false,
	})
	is.NoError(err, "Could not instantiate minio client", err)

	t.Cleanup(func() {
		err = pool.Purge(resource)
		is.NoError(err, "Could not purge resource: %s", err)
	})

	err = client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	is.NoError(err, "Failed to create bucket %q: %s", bucketName, err)

	return endpoint
}

func minioBucketURL(bucketName, endpoint string) string {
	return fmt.Sprintf(
		"s3://%s?"+
			"region=local"+
			"&endpoint=%s"+
			"&disableSSL=true"+
			"&s3ForcePathStyle=true", bucketName, endpoint)
}

func newMinioBucket(ctx context.Context, t *testing.T, prefix string) *blob.Bucket {
	t.Helper()

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Minute)
	}

	ctx, cancelFunc := context.WithDeadline(ctx, deadline)
	defer cancelFunc()

	bucketName := "test"
	endpoint := startMinio(ctx, t, bucketName)
	t.Setenv("AWS_ACCESS_KEY_ID", minioUsername)
	t.Setenv("AWS_SECRET_ACCESS_KEY", minioPassword)
	is := require.New(t)

	bucket, err := blob.OpenBucket(ctx, minioBucketURL(bucketName, endpoint))

	is.NoError(err)
	if prefix != "" {
		bucket = blob.PrefixedBucket(bucket, prefix)
	}
	storeDir := test.PathToDir(t, "store")
	_, err = uploadDirToBucket(ctx, storeDir, bucket)
	is.NoError(err, "Failed to upload directory %q to bucket: %s", storeDir, err)

	t.Cleanup(func() {
		_ = bucket.Close()
	})

	return bucket
}
