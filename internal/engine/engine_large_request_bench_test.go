// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

// Shape of a reported production workload: 120 resource policies, 5 role
// policies, a single CheckResources request with 180 resources x ~500 actions.
const (
	lrNumKinds          = 40  // kinds with resource policies
	lrNumRequestedKinds = 10  // kinds referenced by the request (and by role policies)
	lrNumActions        = 500 // actions per resource
	lrActionsPerRule    = 100 // actions per resource policy rule
	lrNumRolePolicies   = 5
	lrRolePolicyActions = 100 // allowActions per role policy rule
	lrNumResources      = 180
	lrRoleScope         = "acme"
	lrLeafScope         = "acme.ou"
)

func BenchmarkCheckLargeRequest(b *testing.B) {
	policyDir := generateLargeRequestPolicies(b)
	eval := mkRuleTable(b, policyDir)
	inputs := mkLargeRequestInputs(b)

	// Warm-up
	result, err := eval.Check(b.Context(), inputs)
	require.NoError(b, err)
	require.Len(b, result, lrNumResources)

	var allow, deny int
	for _, out := range result {
		require.Len(b, out.Actions, lrNumActions)
		for _, ae := range out.Actions {
			if ae.GetEffect() == effectv1.Effect_EFFECT_ALLOW {
				allow++
			} else {
				deny++
			}
		}
	}
	require.Positive(b, allow)
	require.Positive(b, deny)
	b.Logf("effects per request: allow=%d deny=%d", allow, deny)

	b.ReportAllocs()
	for b.Loop() {
		result, err := eval.Check(b.Context(), inputs)
		if err != nil {
			b.Fatal(err)
		}
		if len(result) != lrNumResources {
			b.Fatalf("unexpected number of results: %d", len(result))
		}
	}
}

func lrKind(i int) string {
	return fmt.Sprintf("kind_%02d", i)
}

func lrAction(i int) string {
	return fmt.Sprintf("action_%03d", i)
}

func lrActions(from, to int) []string {
	actions := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		actions = append(actions, lrAction(i))
	}
	return actions
}

func generateLargeRequestPolicies(b *testing.B) string {
	b.Helper()

	outputDir := b.TempDir()

	resTmpl, err := template.ParseFiles(filepath.Join("testdata", "large_request_resource_policy.yaml.gotmpl"))
	require.NoError(b, err)

	roleTmpl, err := template.ParseFiles(filepath.Join("testdata", "large_request_role_policy.yaml.gotmpl"))
	require.NoError(b, err)

	var actionChunks [][]string
	for i := 0; i < lrNumActions; i += lrActionsPerRule {
		actionChunks = append(actionChunks, lrActions(i, min(i+lrActionsPerRule, lrNumActions)))
	}

	// Every kind has root, lrRoleScope and lrLeafScope policies: 40 x 3 = 120 resource policies.
	n := 0
	for k := range lrNumKinds {
		for _, scope := range []string{"", lrRoleScope, lrLeafScope} {
			data := struct {
				Kind         string
				Scope        string
				ActionChunks [][]string
			}{Kind: lrKind(k), Scope: scope, ActionChunks: actionChunks}
			require.NoError(b, writeTemplate(filepath.Join(outputDir, fmt.Sprintf("resource_%03d.yaml", n)), resTmpl, data))
			n++
		}
	}

	kinds := make([]string, lrNumRequestedKinds)
	for k := range lrNumRequestedKinds {
		kinds[k] = lrKind(k)
	}

	for r := range lrNumRolePolicies {
		from := (r * lrRolePolicyActions) % lrNumActions
		data := struct {
			Role    string
			Scope   string
			Kinds   []string
			Actions []string
		}{Role: fmt.Sprintf("ou_admin_%d", r), Scope: lrRoleScope, Kinds: kinds, Actions: lrActions(from, from+lrRolePolicyActions)}
		require.NoError(b, writeTemplate(filepath.Join(outputDir, fmt.Sprintf("role_%d.yaml", r)), roleTmpl, data))
	}

	return outputDir
}

func writeTemplate(path string, tmpl *template.Template, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func mkLargeRequestInputs(b *testing.B) []*enginev1.CheckInput {
	b.Helper()

	principalAttr, err := structpb.NewValue([]any{
		map[string]any{"role": "organizational-unit-admin", "position": "ou=sales,dc=acme"},
		map[string]any{"role": "viewer", "position": "ou=hr,dc=acme"},
	})
	require.NoError(b, err)

	principalAttrs := map[string]*structpb.Value{"contextRoles": principalAttr}

	actions := lrActions(0, lrNumActions)
	inputs := make([]*enginev1.CheckInput, lrNumResources)
	for i := range lrNumResources {
		// Make the condition true for half of the requests.
		position := fmt.Sprintf("ou=team_%d,ou=hr,dc=acme", i)
		if i%2 == 0 {
			position = fmt.Sprintf("ou=team_%d,ou=sales,dc=acme", i)
		}

		scope := lrLeafScope
		if (i/2)%2 == 1 {
			scope = lrRoleScope
		}

		principal := &enginev1.Principal{
			Id:    "user",
			Roles: []string{"member", fmt.Sprintf("ou_admin_%d", i%lrNumRolePolicies)},
			Attr:  principalAttrs,
		}

		inputs[i] = &enginev1.CheckInput{
			RequestId: "req",
			Resource: &enginev1.Resource{
				Id:            fmt.Sprintf("resource_%d", i),
				Kind:          lrKind(i % lrNumRequestedKinds),
				PolicyVersion: "default",
				Scope:         scope,
				Attr:          map[string]*structpb.Value{"position": structpb.NewStringValue(position)},
			},
			Principal: principal,
			Actions:   actions,
		}
	}

	return inputs
}
