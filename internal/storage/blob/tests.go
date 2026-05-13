// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package blob

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
)

const (
	seaweedUsername = "weedadmin"
	seaweedPassword = "weedadmin"
)

const timeout = 5 * time.Minute

func SeaweedFSBucketURL(bucketName, endpoint string) string {
	return fmt.Sprintf("s3://%s?region=local&hostname_immutable=true&use_path_style=true&disable_https=true&endpoint=http%%3A%%2F%%2F%s", bucketName, endpoint)
}

type UploadParam struct {
	BucketURL    string
	BucketPrefix string
	Username     string
	Password     string //nolint:gosec
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

func newSeaweedFSBucket(t *testing.T, seaweedFS *SeaweedFS, path, prefix string) *blob.Bucket {
	t.Helper()

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}

	ctx, cancelFunc := context.WithDeadline(t.Context(), deadline)
	defer cancelFunc()

	param := UploadParam{
		BucketURL:    seaweedFS.CreateBucket(t),
		BucketPrefix: prefix,
		Username:     seaweedUsername,
		Password:     seaweedPassword,
		Directory:    path,
	}

	return CopyDirToBucket(t, ctx, param)
}

//nolint:revive
func uploadDirToBucket(tb testing.TB, ctx context.Context, dir string, bucket *blob.Bucket) ([]string, error) {
	tb.Helper()

	var files []string

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", dir, err)
	}
	defer root.Close()

	if err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		fileBytes, err := root.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", path, err)
		}

		tb.Logf("[START] Copying %s", path)
		if err := bucket.WriteAll(ctx, path, fileBytes, nil); err != nil {
			tb.Logf("[ERROR] Copying %s: %v", path, err)
			return fmt.Errorf("failed to write to bucket: %w", err)
		}
		tb.Logf("[END] Copying %s", path)

		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}

	return files, err
}

func bucketAdd(tb testing.TB, bucket *blob.Bucket, key string, data []byte) {
	tb.Helper()

	tb.Logf("[START] Adding %s", key)
	//nolint:gosec
	sum := md5.Sum(data)
	tb.Logf("key: %s, etag: %s", key, hex.EncodeToString(sum[:]))
	require.NoError(tb, bucket.WriteAll(tb.Context(), key, data, &blob.WriterOptions{
		ContentMD5: sum[:],
	}))
	tb.Logf("[END] Adding %s", key)
}

func bucketDelete(tb testing.TB, bucket *blob.Bucket, key string) {
	tb.Helper()

	tb.Logf("[START] Deleting %s", key)
	require.NoError(tb, bucket.Delete(tb.Context(), key))
	tb.Logf("[END] Deleting %s", key)
}

type SeaweedFS struct {
	endpoint string
	buckets  atomic.Int64
}

func (s *SeaweedFS) CreateBucket(t *testing.T) string {
	t.Helper()

	cfg, err := config.LoadDefaultConfig(
		t.Context(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(seaweedUsername, seaweedPassword, "")),
		config.WithRegion("local"),
		config.WithBaseEndpoint("http://"+s.endpoint),
	)
	require.NoError(t, err, "Failed to load AWS config")

	bucket := fmt.Sprintf("test-%d", s.buckets.Add(1))

	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true })
	_, err = client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket})
	require.NoError(t, err, "Failed to create bucket %q: %v", bucket, err)

	return SeaweedFSBucketURL(bucket, s.endpoint)
}

func StartSeaweedFS(t *testing.T) *SeaweedFS {
	t.Helper()

	is := require.New(t)
	pool := dockertest.NewPoolT(t, "")

	resource := pool.RunT(t, "chrislusf/seaweedfs",
		dockertest.WithTag("latest"),
		dockertest.WithCmd([]string{"server", "-s3"}),
		dockertest.WithEnv([]string{"AWS_ACCESS_KEY_ID=" + strings.TrimPrefix(seaweedUsername, "admin-"), "AWS_SECRET_ACCESS_KEY=" + seaweedPassword}),
	)

	go func() { _ = resource.FollowLogs(t.Context(), os.Stdout, os.Stderr) }()

	endpoint := fmt.Sprintf("localhost:%s", resource.GetPort("8333/tcp"))
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	err := pool.Retry(t.Context(), timeout, func() error {
		ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/healthz", endpoint), nil)
		if err != nil {
			return err
		}

		resp, err := http.DefaultClient.Do(req) //nolint:gosec
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

	t.Setenv("AWS_ACCESS_KEY_ID", seaweedUsername)
	t.Setenv("AWS_SECRET_ACCESS_KEY", seaweedPassword)

	return &SeaweedFS{endpoint: endpoint}
}
