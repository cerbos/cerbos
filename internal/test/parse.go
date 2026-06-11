// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package test

import (
	"bytes"
	"testing"

	"github.com/cerbos/cerbos/internal/parser"
	"github.com/stretchr/testify/require"
)

func Parse[T any, M parser.ProtoMessage[T]](tb testing.TB, b []byte, opts ...parser.UnmarshalOpt) M {
	tb.Helper()
	results, _, err := parser.Unmarshal[T, M](bytes.NewReader(b), opts...)
	require.NoError(tb, err)
	require.Len(tb, results, 1)
	return results[0]
}
