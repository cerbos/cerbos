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

// TestLazyDensityRegimes builds an index mixing very sparse (K≈1–2) and dense
// (K≈300) principal and resource values, and checks that queries return the
// exact bindings regardless of density — i.e. lazy materialisation is correct in
// both regimes.
func TestLazyDensityRegimes(t *testing.T) {
	const (
		sparsePrincipals = 200
		sparseResources  = 200
		denseCardinality = 300
	)

	rules := make([]*runtimev1.RuleTable_RuleRow, 0, sparsePrincipals+sparseResources+2*denseCardinality)
	for p := range sparsePrincipals {
		rules = append(rules, principalRow(fmt.Sprintf("user_%05d", p))) // K=1 each
	}
	for r := range sparseResources {
		rules = append(rules, resourceRow(fmt.Sprintf("res_%05d", r), "viewer")) // K=1 each
	}
	// Dense principal and dense resource, each with denseCardinality bindings.
	for i := range denseCardinality {
		rules = append(rules, principalRow("power_user"))
		rules = append(rules, resourceRow("shared_doc", fmt.Sprintf("role_%04d", i)))
	}

	// Shuffle so IDs scatter (wide bitmaps), independent of insertion grouping.
	rng := rand.New(rand.NewPCG(7, 11)) //nolint:gosec
	rng.Shuffle(len(rules), func(i, j int) { rules[i], rules[j] = rules[j], rules[i] })

	impl := index.New()
	require.NoError(t, impl.IndexRules(rules))

	query := func(resource, principal string, roles []string, kind policyv1.Kind) int {
		return len(impl.Query("default", resource, "", "view", roles, kind, principal, nil))
	}

	// Sparse principal -> 1 binding; dense principal -> denseCardinality (deduped
	// by the sorted-ID set, so the repeated "power_user" rows collapse correctly).
	require.Equal(t, 1, query("", "user_00100", nil, policyv1.Kind_KIND_PRINCIPAL))
	require.Equal(t, denseCardinality, query("", "power_user", nil, policyv1.Kind_KIND_PRINCIPAL))

	// Sparse resource -> 1 binding; dense resource -> denseCardinality.
	require.Equal(t, 1, query("res_00100", "", nil, policyv1.Kind_KIND_RESOURCE))
	require.Equal(t, denseCardinality, query("shared_doc", "", nil, policyv1.Kind_KIND_RESOURCE))

	// Re-query (now hot/cached) must return identical results.
	require.Equal(t, denseCardinality, query("shared_doc", "", nil, policyv1.Kind_KIND_RESOURCE))
	require.Equal(t, denseCardinality, query("", "power_user", nil, policyv1.Kind_KIND_PRINCIPAL))
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
