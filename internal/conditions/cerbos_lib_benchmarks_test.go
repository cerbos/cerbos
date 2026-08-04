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
	"github.com/google/cel-go/ext"
	"github.com/stretchr/testify/require"
)

const (
	cerbosFuncIntersect = "hasIntersection"
	extFuncIntersect    = "sets.intersects"
)

func BenchmarkExtIntersect5(b *testing.B) {
	benchmarkFunc(b, extFuncIntersect, 5)
}

func BenchmarkIntersect5(b *testing.B) {
	benchmarkFunc(b, cerbosFuncIntersect, 5)
}

func BenchmarkExtIntersect50(b *testing.B) {
	benchmarkFunc(b, extFuncIntersect, 50)
}

func BenchmarkIntersect50(b *testing.B) {
	benchmarkFunc(b, cerbosFuncIntersect, 50)
}

const (
	cerbosFuncIsSubset = "isSubset"
	extFuncIsSubset    = "sets.contains"
)

func BenchmarkExtIsSubset5(b *testing.B) {
	benchmarkFunc(b, extFuncIsSubset, 5)
}

func BenchmarkIsSubset5(b *testing.B) {
	benchmarkFunc(b, cerbosFuncIsSubset, 5)
}

func BenchmarkExtIsSubset50(b *testing.B) {
	benchmarkFunc(b, extFuncIsSubset, 50)
}

func BenchmarkIsSubset50(b *testing.B) {
	benchmarkFunc(b, cerbosFuncIsSubset, 50)
}

func benchmarkFunc(b *testing.B, function string, size int) {
	b.Helper()
	expr := generateExpr(function, size)
	prg := prepareProgram(b, expr)

	for b.Loop() {
		_, _, err := prg.Eval(cel.NoVars())
		require.NoError(b, err)
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

func prepareProgram(tb testing.TB, expr string) cel.Program {
	tb.Helper()
	is := require.New(tb)
	env, err := cel.NewEnv(
		CerbosCELLib(),
		ext.Sets(),
	)
	is.NoError(err)
	ast, issues := env.Compile(expr)
	is.NoError(issues.Err())

	smo, err := ext.NewSetMembershipOptimizer()
	is.NoError(err)

	staticOptimizer, err := cel.NewStaticOptimizer(smo)
	is.NoError(err)

	optimizedAST, issues := staticOptimizer.Optimize(env, ast)
	is.NoError(issues.Err())

	prg, err := env.Program(optimizedAST, cel.CustomDecorator(newTimeDecorator(time.Now)))
	is.NoError(err)
	return prg
}
