// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

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

func principalRow(principal string) *runtimev1.RuleTable_RuleRow {
	return &runtimev1.RuleTable_RuleRow{
		OriginFqn:  namer.PrincipalPolicyFQN(principal, "default", ""),
		PolicyKind: policyv1.Kind_KIND_PRINCIPAL,
		Principal:  principal,
		ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:     effectv1.Effect_EFFECT_ALLOW,
		Version:    "default",
		Params:     &runtimev1.RuleTable_RuleRow_Params{},
	}
}

func resourceRow(resource, role string) *runtimev1.RuleTable_RuleRow {
	return &runtimev1.RuleTable_RuleRow{
		OriginFqn:  namer.ResourcePolicyFQN(resource, "default", ""),
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
		Resource:   resource,
		Role:       role,
		ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:     effectv1.Effect_EFFECT_ALLOW,
		Version:    "default",
		Params:     &runtimev1.RuleTable_RuleRow_Params{},
	}
}

// TestQueryMaterialisesLazyDimension exercises the end-to-end Query path on a
// value that must materialise lazily.
func TestQueryMaterialisesLazyDimension(t *testing.T) {
	const target = 300

	rules := make([]*runtimev1.RuleTable_RuleRow, 0, target+30)
	for i := range target {
		rules = append(rules, resourceRow("shared_doc", fmt.Sprintf("role_%04d", i)))
	}
	for i := range 30 { // a different resource the query must exclude
		rules = append(rules, resourceRow("other_doc", fmt.Sprintf("role_%04d", i)))
	}
	// Shuffle so the binding IDs scatter into a wide bitmap.
	rng := rand.New(rand.NewPCG(7, 11)) //nolint:gosec
	rng.Shuffle(len(rules), func(i, j int) { rules[i], rules[j] = rules[j], rules[i] })

	impl := index.New()
	require.NoError(t, impl.IndexRules(rules))

	count := func() int {
		return len(impl.Query("default", "shared_doc", "", "view", nil, policyv1.Kind_KIND_RESOURCE, "", nil))
	}
	require.Equal(t, target, count(), "first query materialises the lazy literal")
	require.Equal(t, target, count(), "cached re-query returns the same")
}

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
			rules = append(rules, principalRow(principal))
		}
	}
	for r := range fillerResources {
		rules = append(rules, resourceRow(fmt.Sprintf("res_%05d", r), "viewer"))
	}
	rng := rand.New(rand.NewPCG(42, 99)) //nolint:gosec
	rng.Shuffle(len(rules), func(i, j int) { rules[i], rules[j] = rules[j], rules[i] })

	impl := index.New()
	require.NoError(tb, impl.IndexRules(rules))
	return impl
}

func BenchmarkQueryByPrincipalHit(b *testing.B) {
	impl := buildScatteredPrincipalIndex(b)
	var buf []*index.Binding
	b.ReportAllocs()
	for b.Loop() {
		buf = impl.Query("default", "", "", "view", nil, policyv1.Kind_KIND_PRINCIPAL, "user_00500", buf[:0])
	}
	if len(buf) == 0 {
		b.Fatal("expected matches")
	}
}

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

// BenchmarkQueryByPrincipalParallel measures concurrent-read contention on the
// lazy dimension after warm-up (the common steady state — the materialise lock
// is taken once per value, exercised separately by the -race test).
func BenchmarkQueryByPrincipalParallel(b *testing.B) {
	impl := buildScatteredPrincipalIndex(b)
	impl.Query("default", "", "", "view", nil, policyv1.Kind_KIND_PRINCIPAL, "user_00500", nil) // warm
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var buf []*index.Binding
		for pb.Next() {
			buf = impl.Query("default", "", "", "view", nil, policyv1.Kind_KIND_PRINCIPAL, "user_00500", buf[:0])
		}
		_ = buf
	})
}

func TestPrincipalIndexRetention(t *testing.T) {
	t.Skip()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	impl := buildScatteredPrincipalIndex(t)
	impl.Compact()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	t.Logf("index retained: %d KB (HeapAlloc delta, all cold/unqueried)", (int64(after.HeapAlloc)-int64(before.HeapAlloc))/1024)
	runtime.KeepAlive(impl)
}
