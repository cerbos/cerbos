// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestLoad(t *testing.T) {
	fsDir := test.PathToDir(t, filepath.Join("schema", "fs"))
	mgrs := mkMgrs(t, fsDir)

	testCases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name: "schema_with_relative_refs",
			url:  "cerbos:///customer_relative.json",
		},
		{
			name: "schema_with_absolute_refs",
			url:  "cerbos:///customer_absolute.json",
		},
		{
			name:    "schema_with_bad_refs",
			url:     "cerbos:///customer_bad.json",
			wantErr: true,
		},
		{
			name:    "invalid schema",
			url:     "cerbos:///invalid.json",
			wantErr: true,
		},
		{
			name:    "non_existent_schema",
			url:     "cerbos:///blah.json",
			wantErr: true,
		},
		{
			name: "schema_in_subdir",
			url:  "cerbos:///subdir/customer_absolute.json",
		},
		{
			name: "schema_from_file_url",
			url:  fmt.Sprintf("file://%s", filepath.ToSlash(filepath.Join(fsDir, schema.Directory, "customer_absolute.json"))),
		},
	}

	for storeName, mgr := range mgrs {
		for _, tc := range testCases {
			tc := tc
			testName := fmt.Sprintf("%s-%s", tc.name, storeName)
			t.Run(testName, func(t *testing.T) {
				err := mgr.CheckSchema(context.Background(), tc.url)
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			})
		}
	}
}

func TestValidate(t *testing.T) {
	testCases := test.LoadTestCases(t, filepath.Join("schema", "test_cases"))

	for _, enforcement := range []schema.Enforcement{schema.EnforcementWarn, schema.EnforcementReject} {
		enforcement := enforcement
		t.Run(fmt.Sprintf("enforcement=%s", enforcement), func(t *testing.T) {
			store := mkStore(t)
			conf := &schema.Conf{Enforcement: enforcement}
			mgr := schema.NewWithConf(context.Background(), store, conf)

			for _, tcase := range testCases {
				tcase := tcase
				t.Run(tcase.Name, func(t *testing.T) {
					tc := readTestCase(t, tcase.Input)

					have, err := mgr.Validate(context.Background(), tc.SchemaRefs, tc.Input)
					if tc.WantError {
						require.Error(t, err)
						return
					}

					require.Equal(t, conf.Enforcement == schema.EnforcementReject, have.Reject)
					require.Len(t, have.Errors, len(tc.WantValidationErrors))

					if len(tc.WantValidationErrors) > 0 {
						wantErrs := &privatev1.ValidationErrContainer{Errors: tc.WantValidationErrors}
						haveErrs := &privatev1.ValidationErrContainer{Errors: have.Errors.SchemaErrors()}

						require.Empty(t, cmp.Diff(wantErrs, haveErrs,
							protocmp.Transform(),
							protocmp.SortRepeated(cmpValidationError),
						))
					}
				})
			}
		})
	}

	t.Run(fmt.Sprintf("enforcement=%s", schema.EnforcementNone), func(t *testing.T) {
		for _, tcase := range testCases {
			tcase := tcase
			t.Run(tcase.Name, func(t *testing.T) {
				tc := readTestCase(t, tcase.Input)
				store := mkStore(t)
				conf := &schema.Conf{Enforcement: schema.EnforcementNone}
				mgr := schema.NewWithConf(context.Background(), store, conf)

				have, err := mgr.Validate(context.Background(), tc.SchemaRefs, tc.Input)
				require.NoError(t, err)
				require.False(t, have.Reject)
				require.Empty(t, have.Errors)
			})
		}
	})
}

func TestCache(t *testing.T) {
	store := mkStore(t)
	conf := &schema.Conf{Enforcement: schema.EnforcementReject}
	mgr := schema.NewWithConf(context.Background(), store, conf)

	s, ok := mgr.(storage.Subscriber)
	require.True(t, ok)

	tc := &privatev1.SchemaTestCase{}
	test.ReadSingleTestCase(t, filepath.Join("schema", "test_cases", "case_00.yaml"), tc)

	checkValid := func(t *testing.T) {
		t.Helper()

		have, err := mgr.Validate(context.Background(), tc.SchemaRefs, tc.Input)
		require.NoError(t, err)
		require.Empty(t, have.Errors)
	}

	t.Run("delete_schema", func(t *testing.T) {
		s.OnStorageEvent(genEvents(storage.EventDeleteSchema, tc.SchemaRefs)...)
		checkValid(t)
	})

	t.Run("add_schema", func(t *testing.T) {
		s.OnStorageEvent(genEvents(storage.EventAddOrUpdateSchema, tc.SchemaRefs)...)
		checkValid(t)
	})
}

func genEvents(kind storage.EventKind, schemas *policyv1.Schemas) []storage.Event {
	return []storage.Event{
		{Kind: kind, SchemaFile: strings.TrimPrefix(schemas.PrincipalSchema.Ref, schema.URLScheme+"/")},
		{Kind: kind, SchemaFile: strings.TrimPrefix(schemas.ResourceSchema.Ref, schema.URLScheme+"/")},
	}
}

func readTestCase(t *testing.T, data []byte) *privatev1.SchemaTestCase {
	t.Helper()

	tc := &privatev1.SchemaTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func mkStore(t *testing.T) *disk.Store {
	t.Helper()

	fsDir := test.PathToDir(t, filepath.Join("schema", "fs"))
	fsys := os.DirFS(fsDir)

	index, err := index.Build(context.Background(), fsys)
	require.NoError(t, err)

	return disk.NewFromIndexWithConf(index, &disk.Conf{})
}

func cmpValidationError(a, b *schemav1.ValidationError) bool {
	if a.Source == b.Source {
		return a.Path < b.Path
	}
	return a.Source < b.Source
}

func mkMgrs(t *testing.T, fsDir string) map[string]schema.Manager {
	t.Helper()
	mgrs := make(map[string]schema.Manager)

	schemasDir := test.PathToDir(t, filepath.Join("schema", "fs", schema.Directory))
	fsys := os.DirFS(fsDir)
	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	// Create mgr with disk store
	idx, err := index.Build(ctx, fsys)
	require.NoError(t, err)
	diskStore := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	diskMgr := schema.NewWithConf(ctx, diskStore, &schema.Conf{Enforcement: schema.EnforcementReject})

	// Create mgr with sqlite3 store
	var sqlite3Store storage.MutableStore
	sqlite3Store, err = sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: "file::memory:?_fk=true"})
	require.NoError(t, err)
	test.AddSchemasToStore(t, schemasDir, sqlite3Store)
	require.NoError(t, err)
	sqlite3Mgr := schema.NewWithConf(ctx, sqlite3Store, &schema.Conf{Enforcement: schema.EnforcementReject})

	// Add each created store to mgrs map
	mgrs[disk.DriverName] = diskMgr
	mgrs[sqlite3.DriverName] = sqlite3Mgr

	return mgrs
}
