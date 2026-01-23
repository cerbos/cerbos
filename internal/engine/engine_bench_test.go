// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
)

const numScopes = 2000

func BenchmarkEvaluator(b *testing.B) {
	policyDir := generatePolicies(b)
	evaluator := mkRuleTable(b, policyDir)
	b.ReportAllocs()
	b.ResetTimer()
	//nolint: gosec
	for b.Loop() {
		idx := rand.Intn(numScopes)
		idxStr := strconv.Itoa(idx)
		role := "role_" + idxStr + "_" + strconv.Itoa(rand.Intn(10))
		scope := ""
		if idx > 0 {
			scope = "org_" + idxStr
		}

		result, err := evaluator.Check(b.Context(), []*enginev1.CheckInput{
			{
				Resource: &enginev1.Resource{
					Id:            "resource_" + idxStr,
					Kind:          "endpoint",
					PolicyVersion: "1",
					Scope:         scope,
				},
				Principal: &enginev1.Principal{
					Id:    "user",
					Roles: []string{role},
				},
				Actions: []string{"ViewReports", "DeleteReports"},
			},
		})
		require.NoError(b, err)
		require.Len(b, result, 1)
		require.Equal(b, effectv1.Effect_EFFECT_ALLOW, result[0].Actions["ViewReports"].GetEffect())
		require.Equal(b, effectv1.Effect_EFFECT_DENY, result[0].Actions["DeleteReports"].GetEffect())
	}
}

func generatePolicies(b *testing.B) string {
	b.Helper()

	outputDir := b.TempDir()

	tmpl, err := template.ParseFiles(filepath.Join("testdata", "policy_template.yaml.gotmpl"))
	require.NoError(b, err)

	for i := range numScopes {
		require.NoError(b, writePolicy(outputDir, i, tmpl))
	}

	return outputDir
}

func writePolicy(outputDir string, i int, tmpl *template.Template) error {
	f, err := os.Create(filepath.Join(outputDir, fmt.Sprintf("policy_%04d.yaml", i)))
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, struct{ N int }{N: i})
}

func mkRuleTable(b *testing.B, policyDir string) evaluator.Evaluator {
	b.Helper()

	ctx, cancelFunc := context.WithCancel(b.Context())
	b.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: policyDir})
	require.NoError(b, err)

	protoRT := ruletable.NewProtoRuletable()

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(b, err)

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	evalConf.Globals = map[string]any{"environment": "test"}

	err = ruletable.LoadPolicies(ctx, protoRT, compiler, evalConf.DefaultPolicyVersion)
	require.NoError(b, err)

	err = ruletable.LoadSchemas(ctx, protoRT, store)
	require.NoError(b, err)

	idx := index.NewMem()
	rt, err := ruletable.NewRuleTable(idx, protoRT)
	require.NoError(b, err)

	eval, err := rt.Evaluator(evalConf, schema.NewConf(schema.EnforcementWarn))
	require.NoError(b, err)

	return eval
}
