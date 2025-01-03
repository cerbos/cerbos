// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos/internal/util"
)

func TestReadJSONOrYAML(t *testing.T) {
	testCases := []struct {
		input   string
		wantErr bool
	}{
		{
			input: "single_yaml.yaml",
		},
		{
			input: "single_json.json",
		},
		{
			input:   "multiple_yaml1.yaml",
			wantErr: true,
		},
		{
			input:   "multiple_yaml2.yaml",
			wantErr: true,
		},
		{
			input:   "invalid.yaml",
			wantErr: true,
		},
		{
			input:   "multiple_json.json",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tc.input))
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close })

			var m structpb.Struct
			err = util.ReadJSONOrYAML(f, &m)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, m.AsMap())
		})
	}
}
