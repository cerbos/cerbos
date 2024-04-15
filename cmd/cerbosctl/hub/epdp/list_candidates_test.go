// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package epdp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/test"
)

func TestListCandidates(t *testing.T) {
	testCases := []struct {
		testFile     string
		expectedErr  string
		expectedList []string
	}{
		{
			testFile: "all_have_metadata.txt",
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
				"resource.purchase_order.vdefault/regional.uk",
			},
		},
		{
			testFile:    "ancestor_not_in_repo.txt",
			expectedErr: "failed to build index: failed to build index: missing imports=0, missing scopes=1, duplicate definitions=0, load failures=0",
		},
		{
			testFile: "ancestors.txt",
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
			},
		},
		{
			testFile: "descendant_observed_first.txt",
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
			},
		},
		{
			testFile: "irrelevant_metadata.txt",
			expectedList: []string{
				"resource.purchase_order.vdefault",
				"resource.purchase_order.vdefault/regional",
				"resource.purchase_order.vdefault/regional.uk",
			},
		},
		{
			testFile: "no_metadata.txt",
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
			candidates, err := listCandidates(context.Background(), fsys)
			if testCase.expectedErr != "" {
				require.ErrorContains(t, err, "failed to build index: failed to build index: missing imports=0, missing scopes=1, duplicate definitions=0, load failures=0")
			} else {
				require.NoError(t, err)
			}
			require.Len(t, testCase.expectedList, len(candidates))

			have := make([]string, 0, len(candidates))
			for policyKey, policyID := range candidates {
				require.NotEmpty(t, policyID, "policyID should not be empty")
				have = append(have, policyKey)
			}

			require.ElementsMatch(t, testCase.expectedList, have)
		})
	}
}
