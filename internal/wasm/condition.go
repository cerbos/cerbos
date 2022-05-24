package wasm

import (
	"fmt"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"golang.org/x/exp/slices"
	"io"
	"errors"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"strings"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/iancoleman/strcase"
)

var (
	ErrUnsupportedOperator         = errors.New("unsupported non-binary operator")
	ErrUnsupportedExpr             = errors.New("unsupported expression kind")
	ErrUnsupportedConstant         = errors.New("unsupported constant")
	ErrUnsupportedCondition        = errors.New("unsupported condition")
	ErrUnsupportedSelectExpression = errors.New("unsupported select expression")
)

type conditionTranspiler struct {
	schema *Schema
}

func (r *conditionTranspiler) renderExpr(w io.Writer, e *exprpb.Expr) (err error) {
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
		err = r.renderExpr(w, e.Args[0])
		if err != nil {
			return err
		}
		f0(" %s ", mapOps[expr.CallExpr.Function])
		err = r.renderExpr(w, e.Args[1])
		if err != nil {
			return err
		}
	case *exprpb.Expr_SelectExpr:
		var names []string
		e := expr
	loop:
		for e != nil {
			names = append(names, e.SelectExpr.Field)
			switch et := e.SelectExpr.Operand.ExprKind.(type) {
			case *exprpb.Expr_IdentExpr:
				names = append(names, et.IdentExpr.Name)
				e = nil
			case *exprpb.Expr_SelectExpr:
				e = et
			default:
				break loop
			}
		}

		if e == nil {
			// This is a compound "a.b.c" variable

			n := len(names)
			if n < 2 {
				return fmt.Errorf("unexpected # of fragments %v: %w", names, ErrUnsupportedSelectExpression)
			}

			var fi []*Field
			var sb strings.Builder

			switch s := names[n-1]; s {
			case conditions.CELRequestIdent:
				sb.WriteString(s)
				sb.WriteString(".")
				switch s := names[n-2]; s {
				case "principal":
					sb.WriteString(s)
					fi = r.schema.Principal
				case "resource":
					sb.WriteString(s)
					fi = r.schema.Resource
				default:
					return fmt.Errorf(`expected "request.principal" or "request.resource": %w`, ErrUnsupportedSelectExpression)
				}
				sb.WriteString(".")
				n -= 2
			case "R":
				sb.WriteString(conditions.CELRequestIdent)
				sb.WriteString(".")
				sb.WriteString(conditions.CELResourceField)
				sb.WriteString(".")
				fi = r.schema.Resource
				n--
			case "P":
				sb.WriteString(conditions.CELRequestIdent)
				sb.WriteString(".")
				sb.WriteString(conditions.CELPrincipalField)
				sb.WriteString(".")
				fi = r.schema.Principal
				n--
			default:
				return fmt.Errorf("unexpected start %v: %w", names, ErrUnsupportedSelectExpression)
			}
			if n-1 < 0 {
				return ErrUnsupportedSelectExpression
			}
			if names[n-1] == "attr" {
				sb.WriteString("attr.")
				if n != 2 {
					return ErrUnsupportedSelectExpression
				}
				i := slices.IndexFunc(fi, func(f *Field) bool { return f.Name == names[n-2] })
				if i < 0 {
					return fmt.Errorf("unable to find the field in the schema: %v", names)
				}
				sb.WriteString(strcase.ToSnake(names[0]))
				if !fi[i].Required {
					sb.WriteString(".unwrap_or(Default::default())")
				}
			} else {
				sb.WriteString(strcase.ToSnake(names[n-1]))
			}
			f0("%s", sb.String())
		} else {
			return fmt.Errorf("%T: %w", e.SelectExpr.Operand.ExprKind, ErrUnsupportedSelectExpression)
		}
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

func (r *conditionTranspiler) renderCondition(w io.Writer, condition *runtimev1.Condition) error {
	f0 := func(format string, a ...any) { // no indentation
		fmt.Fprintf(w, format, a...)
	}
	switch c := condition.Op.(type) {
	case *runtimev1.Condition_Expr:
		return r.renderExpr(w, c.Expr.Checked.Expr)
	case *runtimev1.Condition_All:
		n := len(c.All.Expr)
		for i := 0; i < n-1; i++ {
			f0("(")
			r.renderCondition(w, c.All.Expr[i])
			f0(") && ")
		}
		if n > 1 {
			f0("(")
		}
		r.renderCondition(w, c.All.Expr[n-1])
		if n > 1 {
			f0(")")
		}
	default:
		return fmt.Errorf("%T: %w", c, ErrUnsupportedCondition)
	}

	return nil
}
