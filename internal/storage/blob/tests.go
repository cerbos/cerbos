// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package blob

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"

	"github.com/cerbos/cerbos/internal/test"
)

const (
	minioUsername = "minioadmin"
	minioPassword = "minioadmin"
	bucketName    = "test"
)

const timeout = 5 * time.Minute

func MinioBucketURL(bucketName, endpoint string) string {
	return fmt.Sprintf(
		"s3://%s?"+
			"region=local"+
			"&endpoint=%s"+
			"&disableSSL=true"+
			"&s3ForcePathStyle=true", bucketName, endpoint)
}

type UploadParam struct {
	BucketURL    string
	BucketPrefix string
	Username     string
	Password     string
	Directory    string
}

//nolint:revive
func CopyDirToBucket(tb testing.TB, ctx context.Context, param UploadParam) *blob.Bucket {
	tb.Helper()

	is := require.New(tb)

	tb.Setenv("AWS_ACCESS_KEY_ID", param.Username)
	tb.Setenv("AWS_SECRET_ACCESS_KEY", param.Password)

	bucket, err := blob.OpenBucket(ctx, param.BucketURL)
	is.NoError(err)

	if param.BucketPrefix != "" {
		bucket = blob.PrefixedBucket(bucket, param.BucketPrefix)
	}

	_, err = uploadDirToBucket(tb, ctx, param.Directory, bucket)
	is.NoError(err, "Failed to upload directory %q to bucket: %s", param.Directory, err)

	tb.Cleanup(func() { _ = bucket.Close() })

	return bucket
}

func newMinioBucket(ctx context.Context, t *testing.T, prefix string) *blob.Bucket {
	t.Helper()

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}

	ctx, cancelFunc := context.WithDeadline(ctx, deadline)
	defer cancelFunc()

	endpoint := startMinio(ctx, t, bucketName)

	param := UploadParam{
		BucketURL:    MinioBucketURL(bucketName, endpoint),
		BucketPrefix: prefix,
		Username:     minioUsername,
		Password:     minioPassword,
		Directory:    test.PathToDir(t, "store"),
	}

	return CopyDirToBucket(t, ctx, param)
}

//nolint:revive
func uploadDirToBucket(tb testing.TB, ctx context.Context, dir string, bucket *blob.Bucket) ([]string, error) {
	tb.Helper()

	var files []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		key, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		fileBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", path, err)
		}

		tb.Logf("[START] Copying %s", key)
		if err := bucket.WriteAll(ctx, key, fileBytes, nil); err != nil {
			tb.Logf("[ERROR] Copying %s: %v", key, err)
			return fmt.Errorf("failed to write to bucket: %w", err)
		}
		tb.Logf("[END] Copying %s", key)

		files = append(files, key)

		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, err
}

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
