// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package epdp

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

func TestListCandidates(t *testing.T) {
	testCases := []struct {
		testFile       string
		files          []string
		expectedLength int
		expectedList   []string
	}{
		{
			testFile: "descendants.txt",
			files: []string{
				"purchase_order.yaml",
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
			expectedLength: 2,
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
			},
		},
		{
			testFile: "nometadata.txt",
			files: []string{
				"purchase_order.yaml",
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
			expectedLength: 3,
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
				"resource.purchase_order.vdefault/regional.uk",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testFile, func(t *testing.T) {
			fsys := test.ExtractTxtArchiveToFS(t, filepath.Join("testdata", testCase.testFile))
			pl := policyLoader{fsys: fsys}

			candidates, err := listCandidates(context.Background(), pl.loadPolicy, testCase.files...)
			require.NoError(t, err)

			require.Len(t, candidates, testCase.expectedLength)
			have := make([]string, len(candidates))
			for i, c := range candidates {
				require.NotEmpty(t, c.policyKey, "policy key must be provided by the policy test input")
				have[i] = c.policyKey
			}
			require.ElementsMatch(t, have, testCase.expectedList)
		})
	}
}

type policyLoader struct {
	fsys fs.FS
}

func (pl policyLoader) loadPolicy(_ context.Context, name string) (*policy.Wrapper, error) {
	f, err := pl.fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file: %w", err)
	}

	p, err := policy.ReadPolicy(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	wp := policy.Wrap(p)
	return &wp, nil
}
