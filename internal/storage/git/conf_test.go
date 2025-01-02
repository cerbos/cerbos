// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package git_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage/git"
)

func TestGitProtocolAndURL(t *testing.T) {
	testCases := []struct {
		name      string
		config    map[string]any
		wantURL   string
		wantError bool
	}{
		{
			name: "protocol_matches_url",
			config: map[string]any{
				"storage": map[string]any{
					"driver": "git",
					"git": map[string]any{
						"protocol": "https",
						"url":      "https://github.com/user/repo.git",
					},
				},
			},
			wantURL: "https://github.com/user/repo.git",
		},
		{
			name: "protocol_does_not_match_url",
			config: map[string]any{
				"storage": map[string]any{
					"driver": "git",
					"git": map[string]any{
						"protocol": "https",
						"url":      "http://github.com/user/repo.git",
					},
				},
			},
			wantError: true,
		},
		{
			name: "protocol_missing_from_url",
			config: map[string]any{
				"storage": map[string]any{
					"driver": "git",
					"git": map[string]any{
						"protocol": "https",
						"url":      "github.com/user/repo.git",
					},
				},
			},
			wantURL: "https://github.com/user/repo.git",
		},
		{
			name: "ssh",
			config: map[string]any{
				"storage": map[string]any{
					"driver": "git",
					"git": map[string]any{
						"protocol": "ssh",
						"url":      "github.com:user/repo.git",
					},
				},
			},
			wantURL: "github.com:user/repo.git",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wrapper, err := config.WrapperFromMap(tc.config)
			require.NoError(t, err)

			conf := &git.Conf{}
			if tc.wantError {
				require.Error(t, wrapper.GetSection(conf))
				return
			}

			require.NoError(t, wrapper.GetSection(conf))
			require.Equal(t, tc.wantURL, conf.URL)
		})
	}
}
