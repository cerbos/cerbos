// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/stretchr/testify/require"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/conditions/types"
)

type Exports struct {
	Bytes         []byte               `cel:"bytes"`
	Duration      time.Duration        `cel:"duration"`
	Fallible      func() (bool, error) `cel:"fallible"`
	Infallible    func() int           `cel:"infallible"`
	Message       *enginev1.Principal  `cel:"message"`
	Slice         []string             `cel:"slice"`
	StructPointer *Example             `cel:"struct_pointer"`
	Timestamp     time.Time            `cel:"timestamp"`
	Uint          uint                 `cel:"uint"`
	Ignored       string
	ignored       string `cel:"ignored"`
}

type Example struct {
	Map map[string]float64 `cel:"map"`
}

func TestStructTypeProvider(t *testing.T) {
	exports := types.NewStructType(Exports{})

	env, err := conditions.NewEnv(
		cel.Types(&enginev1.Principal{}),
		cel.VariableDecls(decls.NewVariable("x", exports.Type)),
		types.StructTypes(exports, types.NewStructType(Example{})),
	)
	require.NoError(t, err, "Failed to create CEL environment")

	ast, issues := env.Compile(`[x.bytes, x.duration, x.fallible, x.infallible, x.message.id, x.slice, x.struct_pointer.map["hello"], x.timestamp, x.uint]`)
	require.NoError(t, issues.Err(), "Failed to compile CEL expression")

	program, err := env.Program(ast)
	require.NoError(t, err, "Failed to create CEL program")

	timestamp := time.Now()

	result, _, err := program.Eval(map[string]any{
		"x": Exports{
			Bytes:         []byte("🥝"),
			Duration:      5 * time.Minute,
			Fallible:      func() (bool, error) { return true, nil },
			Infallible:    func() int { return 42 },
			Message:       &enginev1.Principal{Id: "123"},
			Slice:         []string{"foo", "bar"},
			StructPointer: &Example{Map: map[string]float64{"hello": 99.9}},
			Timestamp:     timestamp,
			Uint:          9001,
		},
	})
	require.NoError(t, err, "Failed to evaluate CEL program")

	out, err := result.ConvertToNative(reflect.TypeFor[[]any]())
	require.NoError(t, err, "Failed to convert result to native slice")
	require.Equal(t, []any{
		[]byte("🥝"),
		5 * time.Minute,
		true,
		int64(42),
		"123",
		[]string{"foo", "bar"},
		float64(99.9),
		timestamp,
		uint64(9001),
	}, out)
}
