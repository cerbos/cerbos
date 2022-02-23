// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

const MaxIDPerReq = 25

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
