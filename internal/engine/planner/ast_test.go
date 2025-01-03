// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/testing/protocmp"

	"google.golang.org/protobuf/encoding/protojson"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/util"
)

//go:embed testdata/ast_build_expr.yaml
var astBuildExprBlob []byte

type (
	exOp = enginev1.PlanResourcesFilter_Expression_Operand
)

func getExpectedExpressions(t *testing.T) map[string]*exOp {
	t.Helper()

	var raw map[string]json.RawMessage
	err := yaml.Unmarshal(astBuildExprBlob, &raw)
	require.NoError(t, err)
	res := make(map[string]*exOp, len(raw))
	for k, v := range raw {
		expected := new(exOp)
		b, err := v.MarshalJSON()
		require.NoError(t, err)
		err = util.ReadJSONOrYAML(bytes.NewReader(b), expected)
		require.NoError(t, err, string(b))
		res[k] = expected
	}

	return res
}

func Test_buildExpr(t *testing.T) {
	parse := func(s string) *exprpb.Expr {
		ast, iss := conditions.StdEnv.Parse(s)
		require.Nil(t, iss, iss.Err())
		ex, err := cel.AstToParsedExpr(ast)
		require.NoError(t, err)
		return ex.Expr
	}

	for k, v := range getExpectedExpressions(t) {
		name := k
		want := v
		t.Run(name, func(t *testing.T) {
			is := require.New(t)
			acc := new(exOp)
			err := buildExpr(parse(k), acc)
			is.NoError(err)

			is.Empty(cmp.Diff(want, acc, protocmp.Transform()), "unexpected expression: %s", protojson.Format(acc))
		})
	}
}
