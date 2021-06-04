// Copyright 2021 Zenauth Ltd.

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

	cerbosdevv1 "github.com/cerbos/cerbos/internal/genpb/cerbosdev/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestBuildIndexWithDisk(t *testing.T) {
	dir := test.PathToDir(t, "store")

	idx, err := Build(context.Background(), os.DirFS(dir), WithMemoryCache())
	require.NoError(t, err)
	require.NotNil(t, idx)

	idxImpl, ok := idx.(*index)
	require.True(t, ok)

	defer idx.Clear() //nolint:errcheck

	data := idxImpl.Inspect()
	require.Len(t, data, 3)

	rp := filepath.Join("resource_policies", "policy_01.yaml")
	pp := filepath.Join("principal_policies", "policy_01.yaml")
	dr := filepath.Join("derived_roles", "derived_roles_01.yaml")

	require.Contains(t, data, rp)
	require.Len(t, data[rp].Dependencies, 1)
	require.Contains(t, data[rp].Dependencies, dr)
	require.Empty(t, data[rp].References)

	require.Contains(t, data, pp)
	require.Empty(t, data[pp].Dependencies)
	require.Empty(t, data[pp].References)

	require.Contains(t, data, dr)
	require.Empty(t, data[dr].Dependencies)
	require.Len(t, data[dr].References, 1)
	require.Contains(t, data[dr].References, rp)
}

func TestBuildIndex(t *testing.T) {
	testCases := test.LoadTestCases(t, "index")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			fs := toFS(t, tc)

			_, haveErr := Build(context.Background(), fs, WithMemoryCache())
			switch {
			case tc.WantErrJson != "":
				errList := new(BuildError)
				require.True(t, errors.As(haveErr, &errList))

				/*
					f, _ := os.Create(fmt.Sprintf("/home/cell/tmp/%s.json", tcase.Name))
					defer f.Close()
					encoder := json.NewEncoder(f)
					encoder.SetIndent("", "  ")
					encoder.Encode(errList)
				*/

				haveErrJSON, err := json.Marshal(errList)
				require.NoError(t, err)

				require.JSONEq(t, tc.WantErrJson, string(haveErrJSON))
			case tc.WantErr != "":
				require.EqualError(t, haveErr, tc.WantErr)
			default:
				require.NoError(t, haveErr)
			}
		})
	}
}

func readTestCase(t *testing.T, data []byte) *cerbosdevv1.IndexBuilderTestCase {
	t.Helper()

	tc := &cerbosdevv1.IndexBuilderTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func toFS(t *testing.T, tc *cerbosdevv1.IndexBuilderTestCase) fs.FS {
	t.Helper()

	fs := afero.NewMemMapFs()

	for file, data := range tc.Files {
		dir := filepath.Dir(file)
		require.NoError(t, fs.MkdirAll(dir, 0764))

		f, err := fs.Create(file)
		require.NoError(t, err)

		_, err = io.Copy(f, strings.NewReader(data))
		require.NoError(t, err)

		require.NoError(t, f.Close())
	}

	return afero.NewIOFS(fs)
}
