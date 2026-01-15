// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package logging

import "context"

type Logger struct{}

func NewLogger(string) *Logger {
	return &Logger{}
}

func FromContext(context.Context) *Logger {
	return &Logger{}
}

// Add any missing required stub methods here
func (*Logger) Debug(...any)          {}
func (*Logger) Debugw(string, ...any) {}
func (*Logger) Debugf(string, ...any) {}
func (*Logger) Warn(string, ...any)   {}
func (*Logger) Warnw(string, ...any)  {}
func (*Logger) Info(...any)           {}

func String(string, string) any {
	return nil
}

func Strings(string, []string) any {
	return nil
}

func Error(error) any {
	return nil
}

func Uint32(string, uint32) any {
	return nil
}
