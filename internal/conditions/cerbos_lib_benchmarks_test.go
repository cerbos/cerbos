// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/conditions"
)

func BenchmarkSetOps(b *testing.B) {
	functionsList := []string{
		"hasIntersection",
		"sets.intersects",
		"isSubset",
		"sets.contains",
	}

	for _, functionName := range functionsList {
		for _, count := range []int{1, 5, 50, 100} {
			expr := generateExpr(functionName, count)
			b.Run(fmt.Sprintf("%s_%d", functionName, count), func(b *testing.B) {
				env, err := cel.NewEnv(
					cel.ExtendedValidations(),
					conditions.CerbosCELLib(),
					ext.Sets(),
				)
				require.NoError(b, err)
				ast, issues := env.Compile(expr)
				require.NoError(b, issues.Err())

				prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CustomDecorator(conditions.CacheFriendlyTimeDecorator()))
				require.NoError(b, err)

				b.ResetTimer()
				b.ReportAllocs()
				for b.Loop() {
					result, _, err := prg.Eval(cel.NoVars())
					require.NoError(b, err)
					resultBool := result.Value().(bool)
					require.Equal(b, true, resultBool)
				}
			})

			b.Run(fmt.Sprintf("%s_%d_folded", functionName, count), func(b *testing.B) {
				ast, issues := conditions.Compile(expr)
				require.NoError(b, issues.Err())

				prg, err := conditions.StdEnv.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CustomDecorator(conditions.CacheFriendlyTimeDecorator()))
				require.NoError(b, err)

				b.ResetTimer()
				b.ReportAllocs()
				for b.Loop() {
					result, _, err := prg.Eval(cel.NoVars())
					require.NoError(b, err)
					require.Equal(b, true, result.Value())
				}
			})
		}
	}
}

func generateExpr(function string, size int) string {
	lhs := make([]string, size)
	for i := range size {
		lhs[i] = fmt.Sprintf("'%05d'", i)
	}
	rhs := make([]string, size)
	copy(rhs, lhs)

	rnd := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	rnd.Shuffle(len(rhs), func(i, j int) { rhs[i], rhs[j] = rhs[j], rhs[i] })
	return fmt.Sprintf("%s([%s], [%s])", function, strings.Join(lhs, ","), strings.Join(rhs, ","))
}
