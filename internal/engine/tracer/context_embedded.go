// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package tracer

func Start(sink Sink) Context {
	return noopContext{}
}
