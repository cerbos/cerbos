// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package tracing

func PolicyFQN(_ string) struct{} {
	return struct{}{}
}
