// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func BenchmarkIntersect50(b *testing.B) {
	benchmarkIntersect(b, 50)
}

func BenchmarkIntersect25(b *testing.B) {
	benchmarkIntersect(b, 25)
}

func BenchmarkIntersect15(b *testing.B) {
	benchmarkIntersect(b, 15)
}

func BenchmarkIntersect5(b *testing.B) {
	benchmarkIntersect(b, 5)
}

func benchmarkIntersect(b *testing.B, size int) {
	b.Helper()
	expr := generateExpr(size)
	prg := prepareProgram(b, expr)

	for b.Loop() {
		_, _, err := prg.Eval(cel.NoVars())
		require.NoError(b, err)
	}
}

func generateExpr(size int) string {
	lhs := make([]string, size)
	for i := range size {
		lhs[i] = fmt.Sprintf("'%05d'", i)
	}
	rhs := make([]string, size)
	copy(rhs, lhs)

	rnd := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	rnd.Shuffle(len(rhs), func(i, j int) { rhs[i], rhs[j] = rhs[j], rhs[i] })
	return fmt.Sprintf("intersect([%s], [%s])", strings.Join(lhs, ","), strings.Join(rhs, ","))
}

func prepareProgram(tb testing.TB, expr string) cel.Program {
	tb.Helper()
	is := require.New(tb)
	env, err := cel.NewEnv(CerbosCELLib())
	is.NoError(err)
	ast, issues := env.Compile(expr)
	is.NoError(issues.Err())

	prg, err := env.Program(ast, cel.CustomDecorator(newTimeDecorator(time.Now)))
	is.NoError(err)
	return prg
}
