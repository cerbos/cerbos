// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package parser

import "github.com/cerbos/cerbos/internal/parser"

func Unmarshal[T any, M parser.ProtoMessage[T]](contents []byte) ([]M, error) {
	message, _, err := parser.UnmarshalBytes[T, M](contents)
	return message, err
}
