// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestBuildIndexWithDisk(t *testing.T) {
	dir := test.PathToDir(t, "store")

	idx, err := Build(context.Background(), os.DirFS(dir))
	require.NoError(t, err)
	require.NotNil(t, idx)

	idxImpl, ok := idx.(*index)
	require.True(t, ok)

	defer idx.Clear() //nolint:errcheck

	t.Run("check_contents", func(t *testing.T) {
		data := idxImpl.Inspect()
		require.Len(t, data, 9)

		rp1 := filepath.Join("resource_policies", "policy_01.yaml")
		rp2 := filepath.Join("resource_policies", "policy_02.yaml")
		rp3 := filepath.Join("resource_policies", "policy_03.yaml")
		rp4 := filepath.Join("resource_policies", "policy_04.yaml")
		pp := filepath.Join("principal_policies", "policy_01.yaml")
		drCommon := filepath.Join("derived_roles", "common_roles.yaml")
		dr1 := filepath.Join("derived_roles", "derived_roles_01.yaml")
		dr2 := filepath.Join("derived_roles", "derived_roles_02.yaml")
		dr3 := filepath.Join("derived_roles", "derived_roles_03.yaml")

		require.Contains(t, data, rp1)
		require.Len(t, data[rp1].Dependencies, 2)
		require.Contains(t, data[rp1].Dependencies, dr1)
		require.Empty(t, data[rp1].References)

		require.Contains(t, data, rp2)
		require.Len(t, data[rp2].Dependencies, 0)

		require.Contains(t, data, rp3)
		require.Len(t, data[rp3].Dependencies, 1)
		require.Contains(t, data[rp3].Dependencies, dr3)
		require.Empty(t, data[rp3].References)

		require.Contains(t, data, rp4)
		require.Len(t, data[rp4].Dependencies, 1)
		require.Contains(t, data[rp3].Dependencies, dr3)
		require.Empty(t, data[rp3].References)

		require.Contains(t, data, pp)
		require.Empty(t, data[pp].Dependencies)
		require.Empty(t, data[pp].References)

		require.Contains(t, data, drCommon)
		require.Empty(t, data[drCommon].Dependencies)
		require.Len(t, data[drCommon].References, 1)

		require.Contains(t, data, dr1)
		require.Empty(t, data[dr1].Dependencies)
		require.Len(t, data[dr1].References, 1)
		require.Contains(t, data[dr1].References, rp1)

		require.Contains(t, data, dr2)
		require.Empty(t, data[dr2].Dependencies)
		require.Len(t, data[dr2].References, 1)
		require.Contains(t, data[dr2].References, rp1)

		require.Contains(t, data, dr3)
		require.Empty(t, data[dr3].Dependencies)
		require.Len(t, data[dr3].References, 1)
		require.Contains(t, data[dr3].References, rp3)
	})

	t.Run("add_empty", func(t *testing.T) {
		_, err := idx.AddOrUpdate(Entry{})
		require.ErrorIs(t, err, ErrInvalidEntry)
	})

	t.Run("add_new", func(t *testing.T) {
		rp := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("x", "x")))
		path := "x.yaml"

		evt, err := idx.AddOrUpdate(Entry{File: path, Policy: rp})
		require.NoError(t, err)
		require.Equal(t, rp.ID, evt.PolicyID)
		require.Equal(t, storage.EventAddOrUpdatePolicy, evt.Kind)

		data := idxImpl.Inspect()
		require.Contains(t, data, path)
	})
}

func TestBuildIndex(t *testing.T) {
	testCases := test.LoadTestCases(t, "index")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			fs := toFS(t, tc)

			_, haveErr := Build(context.Background(), fs)
			switch {
			case tc.WantErrJson != "":
				errList := new(BuildError)
				require.True(t, errors.As(haveErr, &errList))

				haveErrJSON, err := json.Marshal(errList)
				require.NoError(t, err)

				haveErrJSONStr := string(bytes.ReplaceAll(haveErrJSON, []byte{0xc2, 0xa0}, []byte{0x20}))
				wantErrJSONStr := strings.ReplaceAll(tc.WantErrJson, "\u00a0", " ")

				require.JSONEq(t, wantErrJSONStr, haveErrJSONStr)
			case tc.WantErr != "":
				require.EqualError(t, haveErr, tc.WantErr)
			default:
				require.NoError(t, haveErr)
			}
		})
	}
}

func readTestCase(t *testing.T, data []byte) *privatev1.IndexBuilderTestCase {
	t.Helper()

	tc := &privatev1.IndexBuilderTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func toFS(t *testing.T, tc *privatev1.IndexBuilderTestCase) fs.FS {
	t.Helper()

	fs := afero.NewMemMapFs()

	for file, data := range tc.Files {
		dir := filepath.Dir(file)
		require.NoError(t, fs.MkdirAll(dir, 0o764))

		f, err := fs.Create(file)
		require.NoError(t, err)

		_, err = io.Copy(f, strings.NewReader(data))
		require.NoError(t, err)

		require.NoError(t, f.Close())
	}

	return afero.NewIOFS(fs)
}
