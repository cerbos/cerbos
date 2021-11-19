package engine

import (
	"fmt"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/parser"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"testing"
)

func Test_evaluateCondition(t *testing.T) {
	type args struct {
		expr      string
		input     *requestv1.ListResourcesRequest
	}
	tests := []struct {
		args           args
		wantExpression string
	}{
		{
			args: args{
				expr: "false",
				input: &requestv1.ListResourcesRequest{},
			},
			wantExpression: "false",
		},
		{
			args: args{
				expr: "P.attr.authenticated",
				input: &requestv1.ListResourcesRequest{
					Principal:    &enginev1.Principal{
						Attr:          map[string]*structpb.Value{"authenticated": {Kind: &structpb.Value_BoolValue{BoolValue: true}}},
					},
				},
			},
			wantExpression: "true",
		},
		{
			args: args{
				expr: "R.attr.owner == P.attr.name",
				input: &requestv1.ListResourcesRequest{
					Principal:    &enginev1.Principal{
						Attr:          map[string]*structpb.Value{"name": {Kind: &structpb.Value_StringValue{StringValue: "harry"}}},
					},
				},
			},
			wantExpression: `R.attr.owner == "harry"`,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("Expr:%q", tt.args.expr), func(t *testing.T) {
			is := require.New(t)
			ast, iss := conditions.StdEnv.Compile(tt.args.expr)
			is.Nil(iss, "Error is %s", iss.Err())
			checkedExpr, err := cel.AstToCheckedExpr(ast)
			c := &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{
				Original: tt.args.expr,
				Checked: checkedExpr,
			}}}
			got, err := evaluateCondition(c, tt.args.input)
			is.NoError(err)
			if tt.wantExpression != "" {
				expression := got.GetExpression()
				is.NotNil(expression)
				source, err := parser.Unparse(expression.Expr, expression.SourceInfo)
				is.NoError(err)
				is.Equal(tt.wantExpression, source)
			}
		})
	}
}
