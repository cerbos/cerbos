// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestValidate(t *testing.T) {
	testCases := test.LoadTestCases(t, "schema")

	for _, enforcement := range []schema.Enforcement{schema.EnforcementWarn, schema.EnforcementReject} {
		enforcement := enforcement
		t.Run(fmt.Sprintf("enforcement=%s", enforcement), func(t *testing.T) {
			for _, tcase := range testCases {
				tcase := tcase
				t.Run(tcase.Name, func(t *testing.T) {
					tc := readTestCase(t, tcase.Input)
					store := mkStore(t, mkFS(t, tc.Schema))
					conf := &schema.Conf{Enforcement: enforcement}
					mgr, err := schema.NewWithConf(context.Background(), store, conf)

					if tc.InvalidSchema {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)

					have, err := mgr.Validate(context.Background(), tc.Input)
					if tc.WantError {
						require.Error(t, err)
						return
					}

					require.Equal(t, conf.Enforcement == schema.EnforcementReject, have.Reject)

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
				store := mkStore(t, mkFS(t, tc.Schema))
				conf := &schema.Conf{Enforcement: schema.EnforcementNone}
				mgr, err := schema.NewWithConf(context.Background(), store, conf)
				require.NoError(t, err)

				have, err := mgr.Validate(context.Background(), tc.Input)
				require.NoError(t, err)
				require.False(t, have.Reject)
				require.Empty(t, have.Errors)
			})
		}
	})
}

func TestSchemaUpdate(t *testing.T) {
	for _, enforcement := range []schema.Enforcement{schema.EnforcementWarn, schema.EnforcementReject} {
		enforcement := enforcement
		t.Run(fmt.Sprintf("enforcement=%s", enforcement), func(t *testing.T) {
			tc := &privatev1.SchemaTestCase{}
			test.ReadSingleTestCase(t, "schema/case_00.yaml", tc)

			fs := mkFS(t, tc.Schema)
			store := mkStore(t, fs)
			conf := &schema.Conf{Enforcement: enforcement}
			mgr, err := schema.NewWithConf(context.Background(), store, conf)
			require.NoError(t, err)

			s, ok := mgr.(storage.Subscriber)
			require.True(t, ok)

			checkValid := func() {
				have, err := mgr.Validate(context.Background(), tc.Input)
				require.NoError(t, err)
				require.Empty(t, have.Errors)
			}

			// Control test
			checkValid()

			// Signal schema deletion
			s.OnStorageEvent(storage.Event{Kind: storage.EventDeleteSchema})
			checkValid()

			// Signal schema addition
			s.OnStorageEvent(storage.Event{Kind: storage.EventAddOrUpdateSchema})
			checkValid()
		})
	}
}

func readTestCase(t *testing.T, data []byte) *privatev1.SchemaTestCase {
	t.Helper()

	tc := &privatev1.SchemaTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func mkStore(t *testing.T, fs afero.Fs) *disk.Store {
	t.Helper()

	index, err := index.Build(context.Background(), afero.NewIOFS(fs))
	require.NoError(t, err)

	return disk.NewFromIndexWithConf(index, &disk.Conf{})
}

func mkFS(t *testing.T, s *schemav1.Schema) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()

	buf := new(bytes.Buffer)
	require.NoError(t, util.WriteYAML(buf, s))
	require.NoError(t, afero.WriteReader(fs, filepath.Join(schema.Directory, schema.File), buf))

	return fs
}

func cmpValidationError(a, b *schemav1.ValidationError) bool {
	if a.Source == b.Source {
		return a.Path < b.Path
	}
	return a.Source < b.Source
}
