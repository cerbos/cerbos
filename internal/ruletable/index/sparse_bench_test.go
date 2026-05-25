// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// TEMPORARY prototype measurement — compares dense vs sparse principal dimension
// (query latency + index retention). Delete after the go/no-go decision.
package index_test

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/stretchr/testify/require"
)

// buildScatteredPrincipalIndex mimics the loadtest shape: 1000 principals (each
// in 2 bindings) scattered across a ~23k-binding universe by filler resource
// rows, so each principal's binding IDs reach high positions (wide bitmaps).
func buildScatteredPrincipalIndex(tb testing.TB) *index.Index {
	tb.Helper()
	const (
		numPrincipals        = 1000
		bindingsPerPrincipal = 2
		fillerResources      = 21000
	)
	rules := make([]*runtimev1.RuleTable_RuleRow, 0, numPrincipals*bindingsPerPrincipal+fillerResources)
	for p := range numPrincipals {
		principal := fmt.Sprintf("user_%05d", p)
		for range bindingsPerPrincipal {
			rules = append(rules, &runtimev1.RuleTable_RuleRow{
				OriginFqn:  namer.PrincipalPolicyFQN(principal, "default", ""),
				PolicyKind: policyv1.Kind_KIND_PRINCIPAL,
				Principal:  principal,
				ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
				Effect:     effectv1.Effect_EFFECT_ALLOW,
				Version:    "default",
				Params:     &runtimev1.RuleTable_RuleRow_Params{},
			})
		}
	}
	for r := range fillerResources {
		res := fmt.Sprintf("res_%05d", r)
		rules = append(rules, &runtimev1.RuleTable_RuleRow{
			OriginFqn:  namer.ResourcePolicyFQN(res, "default", ""),
			PolicyKind: policyv1.Kind_KIND_RESOURCE,
			Resource:   res,
			Role:       "viewer",
			ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
			Effect:     effectv1.Effect_EFFECT_ALLOW,
			Version:    "default",
			Params:     &runtimev1.RuleTable_RuleRow_Params{},
		})
	}
	rng := rand.New(rand.NewPCG(42, 99)) //nolint:gosec
	rng.Shuffle(len(rules), func(i, j int) { rules[i], rules[j] = rules[j], rules[i] })

	impl := index.New()
	require.NoError(tb, impl.IndexRules(rules))
	return impl
}

func BenchmarkQueryByPrincipal(b *testing.B) {
	impl := buildScatteredPrincipalIndex(b)
	var buf []*index.Binding
	b.ReportAllocs()
	for b.Loop() {
		buf = impl.Query("default", "", "", "view", nil, policyv1.Kind_KIND_PRINCIPAL, "user_00500", buf[:0])
	}
	if len(buf) == 0 {
		b.Fatal("expected matches for principal query")
	}
}

// BenchmarkQueryByPrincipalMiss is the common principal-policy case: a query for
// a principal that has no principal policy. resource+roles are supplied (as the
// real check path does), so it exercises whether the principal early-exit runs
// before the resource/role glob lookups.
func BenchmarkQueryByPrincipalMiss(b *testing.B) {
	impl := buildScatteredPrincipalIndex(b)
	var buf []*index.Binding
	b.ReportAllocs()
	for b.Loop() {
		buf = impl.Query("default", "res_00001", "", "view", []string{"viewer"}, policyv1.Kind_KIND_PRINCIPAL, "user_99999", buf[:0])
	}
	if len(buf) != 0 {
		b.Fatal("expected no matches for absent principal")
	}
}

func TestPrincipalIndexRetention(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	impl := buildScatteredPrincipalIndex(t)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	t.Logf("index retained: %d KB (HeapAlloc delta)", (int64(after.HeapAlloc)-int64(before.HeapAlloc))/1024)
	runtime.KeepAlive(impl)
}
