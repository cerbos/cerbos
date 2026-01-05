// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"reflect"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

func ToStructPB(v any) (*structpb.Value, error) {
	val, err := structpb.NewValue(v)
	if err == nil {
		return val, nil
	}

	if t, ok := v.(time.Time); ok {
		return structpb.NewStringValue(t.Format(time.RFC3339)), nil
	}

	vv := reflect.ValueOf(v)
	switch vv.Kind() {
	case reflect.Array, reflect.Slice:
		arr := make([]any, vv.Len())
		for i := range vv.Len() {
			el := vv.Index(i)
			// TODO (cell) Recurse
			arr[i] = el.Interface()
		}

		return structpb.NewValue(arr)
	case reflect.Map:
		if vv.Type().Key().Kind() == reflect.String {
			m := make(map[string]any)

			iter := vv.MapRange()
			for iter.Next() {
				m[iter.Key().String()] = iter.Value().Interface()
			}

			return structpb.NewValue(m)
		}
	default:
		return nil, err
	}

	return nil, err
}
