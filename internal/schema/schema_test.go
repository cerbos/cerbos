// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

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
		t.Run(storeName, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					_, err := mgr.LoadSchema(t.Context(), tc.url)
					if tc.wantErr {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
				})
			}
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := test.LoadTestCases(t, filepath.Join("schema", "test_cases"))

	for _, enforcement := range []schema.Enforcement{schema.EnforcementWarn, schema.EnforcementReject} {
		t.Run(fmt.Sprintf("enforcement=%s", enforcement), func(t *testing.T) {
			store := mkStore(t)
			conf := schema.NewConf(enforcement)
			mgr := schema.NewFromConf(t.Context(), store, conf)

			for _, tcase := range testCases {
				t.Run(tcase.Name, func(t *testing.T) {
					tc := readTestCase(t, tcase.Input)

					have, err := validate(mgr, tc)

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
			t.Run(tcase.Name, func(t *testing.T) {
				tc := readTestCase(t, tcase.Input)
				store := mkStore(t)
				conf := schema.NewConf(schema.EnforcementNone)
				mgr := schema.NewFromConf(t.Context(), store, conf)

				have, err := validate(mgr, tc)
				require.NoError(t, err)
				require.False(t, have.Reject)
				require.Empty(t, have.Errors)
			})
		}
	})
}

func validate(mgr schema.Manager, tc *privatev1.SchemaTestCase) (*schema.ValidationResult, error) {
	switch tc.Input.(type) {
	case *privatev1.SchemaTestCase_CheckInput:
		return mgr.ValidateCheckInput(context.Background(), tc.SchemaRefs, tc.GetCheckInput())
	case *privatev1.SchemaTestCase_PlanResourcesInput:
		return mgr.ValidatePlanResourcesInput(context.Background(), tc.SchemaRefs, tc.GetPlanResourcesInput())
	default:
		panic(fmt.Errorf("unexpected test case input %T", tc.Input))
	}
}

func TestCache(t *testing.T) {
	fsDir := test.PathToDir(t, filepath.Join("schema", "fs"))
	fsys := afero.NewCopyOnWriteFs(afero.FromIOFS{FS: os.DirFS(fsDir)}, afero.NewMemMapFs())

	index, err := index.Build(t.Context(), afero.NewIOFS(fsys))
	require.NoError(t, err)

	store := disk.NewFromIndexWithConf(index, &disk.Conf{})
	conf := schema.NewConf(schema.EnforcementReject)
	mgr := schema.NewFromConf(t.Context(), store, conf)

	s, ok := mgr.(storage.Subscriber)
	require.True(t, ok)

	// stash the schema contents for later use
	schemaBytes, err := afero.ReadFile(fsys, filepath.Join(schema.Directory, "complex_object.json"))
	require.NoError(t, err)

	t.Run("change_contents", func(t *testing.T) {
		schemaFile := filepath.Join(schema.Directory, "complex_object.json")
		schemaURL := fmt.Sprintf("%s:///complex_object.json", schema.URLScheme)

		// control test (everything is as it should be)
		_, err := mgr.LoadSchema(t.Context(), schemaURL)
		require.NoError(t, err)

		// write rubbish to file
		require.NoError(t, afero.WriteFile(fsys, schemaFile, []byte("blah"), 0o644))
		s.OnStorageEvent(storage.Event{Kind: storage.EventAddOrUpdateSchema, SchemaFile: "complex_object.json"})
		_, err = mgr.LoadSchema(t.Context(), schemaURL)
		require.Error(t, err)

		// reset
		require.NoError(t, afero.WriteFile(fsys, schemaFile, schemaBytes, 0o644))
		s.OnStorageEvent(storage.Event{Kind: storage.EventAddOrUpdateSchema, SchemaFile: "complex_object.json"})
		_, err = mgr.LoadSchema(t.Context(), schemaURL)
		require.NoError(t, err)
	})

	t.Run("add_and_delete", func(t *testing.T) {
		schemaFile := filepath.Join(schema.Directory, "wibble.json")
		schemaURL := fmt.Sprintf("%s:///wibble.json", schema.URLScheme)

		// control test
		_, err = mgr.LoadSchema(t.Context(), schemaURL)
		require.Error(t, err)

		// add file
		require.NoError(t, afero.WriteFile(fsys, schemaFile, schemaBytes, 0o644))
		s.OnStorageEvent(storage.Event{Kind: storage.EventAddOrUpdateSchema, SchemaFile: "wibble.json"})
		_, err = mgr.LoadSchema(t.Context(), schemaURL)
		require.NoError(t, err)

		// delete file
		require.NoError(t, fsys.Remove(schemaFile))
		s.OnStorageEvent(storage.Event{Kind: storage.EventDeleteSchema, SchemaFile: "wibble.json"})
		_, err = mgr.LoadSchema(t.Context(), schemaURL)
		require.Error(t, err)
	})
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

	index, err := index.Build(t.Context(), fsys)
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
	ctx, cancelFunc := context.WithCancel(t.Context())
	t.Cleanup(cancelFunc)

	// Create mgr with disk store
	idx, err := index.Build(ctx, fsys)
	require.NoError(t, err)
	diskStore := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	diskMgr := schema.NewFromConf(ctx, diskStore, schema.NewConf(schema.EnforcementReject))

	// Create mgr with sqlite3 store
	sqlite3Store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: "file::memory:?_fk=true"})
	require.NoError(t, err)
	test.AddSchemasToStore(t, schemasDir, sqlite3Store)
	sqlite3Mgr := schema.NewFromConf(ctx, sqlite3Store, schema.NewConf(schema.EnforcementReject))

	// Add each created store to mgrs map
	mgrs[disk.DriverName] = diskMgr
	mgrs[sqlite3.DriverName] = sqlite3Mgr

	return mgrs
}
