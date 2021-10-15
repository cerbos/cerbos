// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"reflect"

	"google.golang.org/protobuf/types/known/structpb"
)

func ToStructPB(v interface{}) (*structpb.Value, error) {
	val, err := structpb.NewValue(v)
	if err == nil {
		return val, nil
	}

	vv := reflect.ValueOf(v)
	switch vv.Kind() {
	case reflect.Array, reflect.Slice:
		arr := make([]interface{}, vv.Len())
		for i := 0; i < vv.Len(); i++ {
			el := vv.Index(i)
			// TODO (cell) Recurse
			arr[i] = el.Interface()
		}

		return structpb.NewValue(arr)
	case reflect.Map:
		if vv.Type().Key().Kind() == reflect.String {
			m := make(map[string]interface{})

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
