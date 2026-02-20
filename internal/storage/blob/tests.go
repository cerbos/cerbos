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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
)

const (
	seaweedUsername = "weedadmin"
	seaweedPassword = "weedadmin"
	bucketName      = "test"
)

const timeout = 5 * time.Minute

func SeaweedFSBucketURL(bucketName, endpoint string) string {
	return fmt.Sprintf("s3://%s?region=local&hostname_immutable=true&use_path_style=true&disable_https=true&endpoint=http%%3A%%2F%%2F%s", bucketName, endpoint)
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

func newSeaweedFSBucket(ctx context.Context, t *testing.T, path, prefix string) *blob.Bucket {
	t.Helper()

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}

	ctx, cancelFunc := context.WithDeadline(ctx, deadline)
	defer cancelFunc()

	param := UploadParam{
		BucketURL:    SeaweedFSBucketURL(bucketName, StartSeaweedFS(ctx, t, bucketName)),
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

func bucketAdd(ctx context.Context, tb testing.TB, bucket *blob.Bucket, key string, data []byte) {
	tb.Helper()

	tb.Logf("[START] Adding %s", key)
	//nolint:gosec
	sum := md5.Sum(data)
	tb.Logf("key: %s, etag: %s", key, hex.EncodeToString(sum[:]))
	require.NoError(tb, bucket.WriteAll(ctx, key, data, &blob.WriterOptions{
		ContentMD5: sum[:],
	}))
	tb.Logf("[END] Adding %s", key)
}

func bucketDelete(ctx context.Context, tb testing.TB, bucket *blob.Bucket, key string) {
	tb.Helper()

	tb.Logf("[START] Deleting %s", key)
	require.NoError(tb, bucket.Delete(ctx, key))
	tb.Logf("[END] Deleting %s", key)
}

func StartSeaweedFS(ctx context.Context, t *testing.T, bucketName string) string {
	t.Helper()

	is := require.New(t)
	pool, err := dockertest.NewPool("")
	is.NoError(err, "Could not connect to docker: %s", err)

	options := &dockertest.RunOptions{
		Repository: "chrislusf/seaweedfs",
		Tag:        "latest",
		Cmd:        []string{"server", "-s3"},
		Env:        []string{"AWS_ACCESS_KEY_ID=" + strings.TrimPrefix(seaweedUsername, "admin-"), "AWS_SECRET_ACCESS_KEY=" + seaweedPassword},
	}

	resource, err := pool.RunWithOptions(options)
	is.NoError(err, "Could not start resource: %s", err)

	go func() {
		_ = pool.Client.Logs(docker.LogsOptions{
			Context:      ctx,
			Stderr:       true,
			Stdout:       true,
			Follow:       true,
			Timestamps:   true,
			RawTerminal:  true,
			Container:    resource.Container.ID,
			OutputStream: os.Stdout,
		})
	}()

	endpoint := fmt.Sprintf("localhost:%s", resource.GetPort("8333/tcp"))
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	err = pool.Retry(func() error {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/healthz", endpoint), nil)
		if err != nil {
			return err
		}

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

	t.Cleanup(func() {
		err = pool.Purge(resource)
		is.NoError(err, "Could not purge resource: %s", err)
	})

	s3APIEndpoint := "http://" + endpoint
	cfg, err := config.LoadDefaultConfig(
		t.Context(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(seaweedUsername, seaweedPassword, "")),
		config.WithRegion("local"),
		config.WithBaseEndpoint(s3APIEndpoint),
	)
	is.NoError(err, "Failed to load AWS config")

	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true })
	_, err = client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucketName})
	is.NoError(err, "Failed to create bucket %q: %v", bucketName, err)

	t.Setenv("AWS_ACCESS_KEY_ID", seaweedUsername)
	t.Setenv("AWS_SECRET_ACCESS_KEY", seaweedPassword)

	return endpoint
}
