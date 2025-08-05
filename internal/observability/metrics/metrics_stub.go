// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package metrics

import (
	"context"
)

func KindKey(string) string   { return "" }
func DriverKey(string) string { return "" }

func CompileDuration() any { return nil }

func IndexCRUDCount() any             { return nil }
func IndexEntryCount() any            { return nil }
func StorePollCount() any             { return nil }
func StoreSyncErrorCount() any        { return nil }
func StoreLastSuccessfulRefresh() any { return nil }

func Record(context.Context, ...any) {}
func RecordDuration2[T any](any, func() (T, error)) (T, error) {
	var zero T
	return zero, nil
}

func Inc(context.Context, ...any) {}
func Add(context.Context, ...any) {}
