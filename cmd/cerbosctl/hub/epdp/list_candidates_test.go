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
		testFile     string
		files        []string
		expectedList []string
	}{
		{
			testFile: "all_have_metadata.txt",
			files: []string{
				"purchase_order.yaml",
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
				"resource.purchase_order.vdefault/regional.uk",
			},
		},
		{
			testFile: "ancestor_not_in_repo.txt",
			files: []string{
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
			expectedList: []string{
				"resource.purchase_order.vdefault/regional",
			},
		},
		{
			testFile: "ancestors.txt",
			files: []string{
				"purchase_order.yaml",
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
			},
		},
		{
			testFile: "ancestors_not_in_repo.txt",
			files: []string{
				"regional/uk/purchase_order.yaml",
			},
			expectedList: []string{
				"resource.purchase_order.vdefault/regional.uk",
			},
		},
		{
			testFile: "descendant_observed_first.txt",
			files: []string{
				"regional/purchase_order.yaml",
				"purchase_order.yaml",
			},
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
			},
		},
		{
			testFile: "irrelevant_metadata.txt",
			files: []string{
				"purchase_order.yaml",
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
				"resource.purchase_order.vdefault/regional.uk",
			},
		},
		{
			testFile: "no_metadata.txt",
			files: []string{
				"purchase_order.yaml",
				"regional/purchase_order.yaml",
				"regional/uk/purchase_order.yaml",
			},
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

			have := make([]string, 0, len(candidates))
			for policyKey := range candidates {
				have = append(have, policyKey)
			}

			require.Len(t, testCase.expectedList, len(candidates))
			require.ElementsMatch(t, testCase.expectedList, have)
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
