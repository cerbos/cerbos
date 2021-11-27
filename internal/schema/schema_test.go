// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestValidate(t *testing.T) {
	testCases := test.LoadTestCases(t, "schema")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			store := mkStore(t, tc.Schema)
			conf := &schema.Conf{Enforcement: schema.EnforcementReject}
			mgr, err := schema.NewWithConf(context.Background(), store, conf)

			if tc.InvalidSchema {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			have := mgr.Validate(context.Background(), tc.Input)
			if tc.WantError || len(tc.WantValidationErrors) > 0 {
				require.Error(t, have)
			} else {
				require.NoError(t, have)
				return
			}

			if len(tc.WantValidationErrors) > 0 {
				var haveErr schema.ValidationErrorList
				require.True(t, errors.As(have, &haveErr))

				wantErrs := &privatev1.ValidationErrContainer{Errors: tc.WantValidationErrors}
				haveErrs := &privatev1.ValidationErrContainer{Errors: haveErr.SchemaErrors()}

				require.Empty(t, cmp.Diff(wantErrs, haveErrs,
					protocmp.Transform(),
					protocmp.SortRepeated(cmpValidationError),
				))
			}
		})
	}
}

func readTestCase(t *testing.T, data []byte) *privatev1.SchemaTestCase {
	t.Helper()

	tc := &privatev1.SchemaTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func mkStore(t *testing.T, s *schemav1.Schema) *disk.Store {
	t.Helper()

	fs := afero.NewMemMapFs()

	buf := new(bytes.Buffer)
	require.NoError(t, util.WriteYAML(buf, s))
	require.NoError(t, afero.WriteReader(fs, filepath.Join(schema.Directory, schema.File), buf))

	index, err := index.Build(context.Background(), afero.NewIOFS(fs))
	require.NoError(t, err)

	return disk.NewFromIndexWithConf(index, &disk.Conf{})
}

func cmpValidationError(a, b *schemav1.ValidationError) bool {
	if a.Source == b.Source {
		return a.Path < b.Path
	}
	return a.Source < b.Source
}
