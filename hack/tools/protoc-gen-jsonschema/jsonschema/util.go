// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

func Boolean(value bool) *bool {
	return &value
}

func Size(value uint64) *uint64 {
	return &value
}

func String(value string) *string {
	return &value
}
