package wasm

import (
	"fmt"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"golang.org/x/exp/slices"
	"io"
	"errors"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
)

var (
	ErrUnsupportedOperator  = errors.New("unsupported non-binary operator")
	ErrUnsupportedExpr      = errors.New("unsupported expression kind")
	ErrUnsupportedConstant  = errors.New("unsupported constant")
	ErrUnsupportedCondition = errors.New("unsupported condition")
)

func renderExpr(w io.Writer, e *exprpb.Expr) error {
	f0 := func(format string, a ...any) {
		fmt.Fprintf(w, format, a...)
	}
	//	*Expr_ConstExpr
	//	*Expr_IdentExpr
	//	*Expr_SelectExpr
	//	*Expr_CallExpr
	switch expr := e.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		if !isBinaryOp(expr) {
			return ErrUnsupportedOperator
		}
		e := expr.CallExpr
		renderExpr(w, e.Args[0])
		f0(" == ")
		renderExpr(w, e.Args[1])
	case *exprpb.Expr_SelectExpr:
		renderExpr(w, expr.SelectExpr.Operand)
		f0(".%s", expr.SelectExpr.Field)
	case *exprpb.Expr_IdentExpr:
		f0(expr.IdentExpr.Name)
	case *exprpb.Expr_ConstExpr:
		return renderConstExpr(w, expr.ConstExpr)
	default:
		return fmt.Errorf("%T: %w", expr, ErrUnsupportedExpr)
	}

	return nil
}

var binaryOps = []string{"_==_"}
var mapOps = map[string]string{
	"_==_": "==",
}

func isBinaryOp(e *exprpb.Expr_CallExpr) bool {
	if e != nil && e.CallExpr != nil {
		c := e.CallExpr
		return c.Target == nil && len(c.Args) == 2 && slices.Contains(binaryOps, c.Function)
	}
	return false
}

func renderConstExpr(w io.Writer, c *exprpb.Constant) error {
	var a any
	switch v := c.ConstantKind.(type) {
	case *exprpb.Constant_BoolValue:
		a = v.BoolValue
	case *exprpb.Constant_DoubleValue:
		a = v.DoubleValue
	case *exprpb.Constant_Int64Value:
		a = v.Int64Value
	case *exprpb.Constant_NullValue:
		fmt.Fprintf(w, "null")
		return nil
	case *exprpb.Constant_StringValue:
		a = v.StringValue
	case *exprpb.Constant_Uint64Value:
		a = v.Uint64Value
	default:
		return fmt.Errorf("%v: %w", c, ErrUnsupportedConstant)
	}
	fmt.Fprintf(w, "%#v", a)
	return nil
}

func renderCondition(w io.Writer, condition *runtimev1.Condition) error {
	f0 := func(format string, a ...any) { // no indentation
		fmt.Fprintf(w, format, a...)
	}
	switch c := condition.Op.(type) {
	case *runtimev1.Condition_Expr:
		return renderExpr(w, c.Expr.Checked.Expr)
	case *runtimev1.Condition_All:
		n := len(c.All.Expr)
		for i := 0; i < n-1; i++ {
			f0("(")
			renderCondition(w, c.All.Expr[i])
			f0(") && ")
		}
		if n > 1 {
			f0("(")
		}
		renderCondition(w, c.All.Expr[n-1])
		if n > 1 {
			f0(")")
		}
	default:
		return fmt.Errorf("%T: %w", c, ErrUnsupportedCondition)
	}

	return nil
}
