// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// NewCustomCELTypeAdapter provides a CEL type adaptor than can deal with json.Number values returned by Rego.
func NewCustomCELTypeAdapter() ref.TypeAdapter {
	return &jsonNumberAdapter{
		adapter: types.DefaultTypeAdapter,
	}
}

type jsonNumberAdapter struct {
	adapter ref.TypeAdapter
}

func (jna *jsonNumberAdapter) NativeToValue(value interface{}) ref.Val {
	if jsonNum, ok := value.(json.Number); ok {
		// try to read the number as an int
		i, err := jsonNum.Int64()
		if err == nil {
			return types.Int(i)
		}

		// try to read the number as a float
		f, err := jsonNum.Float64()
		if err == nil {
			return types.Double(f)
		}

		return types.UnsupportedRefValConversionErr(jsonNum)
	}

	return jna.adapter.NativeToValue(value)
}
