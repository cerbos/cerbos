// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	"google.golang.org/protobuf/testing/protocmp"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestCloneResult(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ctx := context.Background()
	testCases := test.LoadTestCases(t, "blob_cloner")
	for _, testMetadata := range testCases {
		testCase := readTestCase(t, testMetadata.Input)
		dir := t.TempDir()

		bucketDir := filepath.Join(dir, "bucket")
		require.NoError(t, os.MkdirAll(bucketDir, perm775))
		cacheDir := cacheDir(bucketDir, dir)
		bucket := newMinioBucket(ctx, t, bucketDir, "")
		applyFiles(ctx, t, bucket, testCase.Inputs)

		cloner, err := NewCloner(bucket, cacheDir)
		require.NoError(t, err)

		t.Run(testMetadata.Name, func(t *testing.T) {
			for idx, s := range testCase.Steps {
				t.Run(fmt.Sprint(idx), func(t *testing.T) {
					switch step := s.Op.(type) {
					case *privatev1.BlobClonerTestCase_Step_Differences_:
						applyFiles(ctx, t, bucket, step.Differences.Files)
					case *privatev1.BlobClonerTestCase_Step_Expectation_:
						cr, err := cloner.Clone(ctx)
						require.NoError(t, err)

						require.Empty(t, cmp.Diff(step.Expectation.All, toExpectedAllMap(cr.all), protocmp.Transform()))
						require.Empty(t, cmp.Diff(step.Expectation.AddedOrUpdated, toInfos(cr.addedOrUpdated), protocmp.Transform()))
						require.Empty(t, cmp.Diff(step.Expectation.Deleted, toInfos(cr.deleted), protocmp.Transform()))
						require.NoError(t, cloner.Clean())
					}
				})
			}
		})
	}
}

func applyFiles(ctx context.Context, t *testing.T, bucket *blob.Bucket, files []*privatev1.BlobClonerTestCase_File) {
	t.Helper()

	for _, file := range files {
		switch f := file.Operation.(type) {
		case *privatev1.BlobClonerTestCase_File_AddOrUpdate_:
			bucketAdd(ctx, t, bucket, f.AddOrUpdate.Name, []byte(f.AddOrUpdate.Content))
		case *privatev1.BlobClonerTestCase_File_Delete_:
			bucketDelete(ctx, t, bucket, f.Delete.Name)
		default:
			t.Fatal("unspecified kind")
		}
	}
}

func toExpectedAllMap(have map[string][]string) map[string]*privatev1.BlobClonerTestCase_Step_Expectation_Files {
	if have == nil {
		return nil
	}

	formattedHave := make(map[string]*privatev1.BlobClonerTestCase_Step_Expectation_Files)
	for etag, files := range have {
		formattedHave[etag] = &privatev1.BlobClonerTestCase_Step_Expectation_Files{
			Files: files,
		}
	}

	return formattedHave
}

func toInfos(have []info) []*privatev1.BlobClonerTestCase_Step_Expectation_Info {
	if have == nil {
		return nil
	}

	infos := make([]*privatev1.BlobClonerTestCase_Step_Expectation_Info, len(have))
	for idx, info := range have {
		infos[idx] = &privatev1.BlobClonerTestCase_Step_Expectation_Info{
			Etag: info.etag,
			File: info.file,
		}
	}

	return infos
}

func readTestCase(tb testing.TB, data []byte) *privatev1.BlobClonerTestCase {
	tb.Helper()

	tc := &privatev1.BlobClonerTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
