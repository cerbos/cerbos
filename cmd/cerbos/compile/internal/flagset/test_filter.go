// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"github.com/cerbos/cerbos/internal/verify"
)

type TestFilter []string

func (tf TestFilter) ToFilterConfig() (*verify.FilterConfig, error) {
	if len(tf) == 0 {
		return nil, nil
	}

	var result *verify.FilterConfig
	for _, f := range tf {
		parsed, err := verify.ParseFilterConfig(f)
		if err != nil {
			return nil, err
		}
		result = result.Merge(parsed)
	}

	return result, nil
}
