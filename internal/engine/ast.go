// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/parser"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

const (
	Equals             = "eq"
	NotEquals          = "ne"
	GreaterThan        = "gt"
	GreaterThanOrEqual = "ge"
	LessThan           = "lt"
	LessThanOrEqual    = "le"
	In                 = "in"
	List               = "newList"
	Add                = "add"
	Field              = "field"
	Index              = "index"
)

var ErrUnknownOperator = errors.New("unknown operator")

func opFromCLE(fn string) (string, error) {
	switch fn {
	case operators.Equals:
		return Equals, nil
	case operators.NotEquals:
		return NotEquals, nil
	case operators.Greater:
		return GreaterThan, nil
	case operators.GreaterEquals:
		return GreaterThanOrEqual, nil
	case operators.Less:
		return LessThan, nil
	case operators.LessEquals:
		return LessThanOrEqual, nil
	case operators.In:
		return In, nil
	case operators.Add:
		return Add, nil
	case operators.Index:
		return Index, nil
	default:
		return fn, ErrUnknownOperator
	}
}

func updateIds(e *exprpb.Expr) {
	var n int64

	var impl func(e *exprpb.Expr)
	impl = func(e *exprpb.Expr) {
		if e == nil {
			return
		}
		n++
		e.Id = n
		switch e := e.ExprKind.(type) {
		case *exprpb.Expr_SelectExpr:
			impl(e.SelectExpr.Operand)
		case *exprpb.Expr_CallExpr:
			impl(e.CallExpr.Target)
			for _, arg := range e.CallExpr.Args {
				impl(arg)
			}
		case *exprpb.Expr_StructExpr:
			for _, entry := range e.StructExpr.Entries {
				impl(entry.GetMapKey())
				impl(entry.GetValue())
			}
		case *exprpb.Expr_ComprehensionExpr:
			ce := e.ComprehensionExpr
			impl(ce.IterRange)
			impl(ce.AccuInit)
			impl(ce.LoopStep)
			impl(ce.LoopCondition)
			impl(ce.Result)
		case *exprpb.Expr_ListExpr:
			for _, element := range e.ListExpr.Elements {
				impl(element)
			}
		}
	}
	impl(e)
}

func replaceVars(e **exprpb.Expr, vars map[string]*exprpb.Expr) (err error) {
	var r func(e *exprpb.Expr) *exprpb.Expr
	r = func(e *exprpb.Expr) *exprpb.Expr {
		if e == nil {
			return nil
		}
		switch e := e.ExprKind.(type) {
		case *exprpb.Expr_SelectExpr:
			ident := e.SelectExpr.Operand.GetIdentExpr()
			if ident != nil && (ident.Name == conditions.CELVariablesAbbrev || ident.Name == conditions.CELVariablesIdent) {
				if v, ok := vars[e.SelectExpr.Field]; ok {
					return v
				}
				err = multierr.Append(err, fmt.Errorf("unknown variable %q", e.SelectExpr.Field))
			} else {
				e.SelectExpr.Operand = r(e.SelectExpr.Operand)
			}
		case *exprpb.Expr_CallExpr:
			e.CallExpr.Target = r(e.CallExpr.Target)
			for i, arg := range e.CallExpr.Args {
				e.CallExpr.Args[i] = r(arg)
			}
		case *exprpb.Expr_StructExpr:
			for _, entry := range e.StructExpr.Entries {
				if k, ok := entry.KeyKind.(*exprpb.Expr_CreateStruct_Entry_MapKey); ok {
					k.MapKey = r(k.MapKey)
				}
				entry.Value = r(entry.Value)
			}
		case *exprpb.Expr_ComprehensionExpr:
			ce := e.ComprehensionExpr
			ce.IterRange = r(ce.IterRange)
			ce.AccuInit = r(ce.AccuInit)
			ce.LoopStep = r(ce.LoopStep)
			ce.LoopCondition = r(ce.LoopCondition)
			// ce.Result seems to be always an identifier, so isn't necessary to process
		case *exprpb.Expr_ListExpr:
			for i, element := range e.ListExpr.Elements {
				e.ListExpr.Elements[i] = r(element)
			}
		}
		return e
	}

	*e = r(*e)
	updateIds(*e)

	return err
}

func String(expr *enginev1.ResourcesQueryPlanOutput_Node) (source string, err error) {
	if expr == nil {
		return "", nil
	}
	switch node := expr.Node.(type) {
	case *enginev1.ResourcesQueryPlanOutput_Node_Expression:
		expr := node.Expression
		source, err = parser.Unparse(expr.Expr, expr.SourceInfo)
		if err != nil {
			return "", err
		}
	case *enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation:
		op := enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(node.LogicalOperation.Operator)]
		s := make([]string, 0, len(node.LogicalOperation.Nodes))
		for _, n := range node.LogicalOperation.Nodes {
			source, err = String(n)
			if err != nil {
				return "", err
			}
			s = append(s, source)
		}

		source = strings.Join(s, " "+strings.TrimPrefix(op, "OPERATOR_")+" ")
	}

	return "(" + source + ")", nil
}

func convert(expr *enginev1.ResourcesQueryPlanOutput_Node, acc *responsev1.ResourcesQueryPlanResponse_Condition_Operand) error {
	type (
		ExprOp = responsev1.ResourcesQueryPlanResponse_Expression_Operand
		Co     = responsev1.ResourcesQueryPlanResponse_Condition
		CoOp   = responsev1.ResourcesQueryPlanResponse_Condition_Operand
		CoOpCo = responsev1.ResourcesQueryPlanResponse_Condition_Operand_Condition
		CoOpEx = responsev1.ResourcesQueryPlanResponse_Condition_Operand_Expression
	)

	switch node := expr.Node.(type) {
	case *enginev1.ResourcesQueryPlanOutput_Node_Expression:
		eop := new(ExprOp)
		err := buildExpr(node.Expression.Expr, eop)
		if err != nil {
			return err
		}
		acc.Node = &CoOpEx{
			Expression: eop.GetExpression(),
		}
	case *enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation:
		c := &CoOpCo{
			Condition: &Co{
				Operator: enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(node.LogicalOperation.Operator)],
				Nodes:    make([]*CoOp, len(node.LogicalOperation.Nodes)),
			},
		}
		for i, n := range node.LogicalOperation.Nodes {
			c.Condition.Nodes[i] = &CoOp{}
			err := convert(n, c.Condition.Nodes[i])
			if err != nil {
				return err
			}
		}
		acc.Node = c
	}

	return nil
}

func buildExpr(expr *exprpb.Expr, acc *responsev1.ResourcesQueryPlanResponse_Expression_Operand) error {
	type (
		Expr        = responsev1.ResourcesQueryPlanResponse_Expression
		ExprOp      = responsev1.ResourcesQueryPlanResponse_Expression_Operand
		ExprOpExpr  = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Expression
		ExprOpValue = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Value
		ExprOpVar   = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Variable
	)

	switch expr := expr.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		fn, _ := opFromCLE(expr.CallExpr.Function)
		e := Expr{
			Operator: fn,
			Operands: make([]*ExprOp, len(expr.CallExpr.Args)),
		}
		eoe := ExprOpExpr{
			Expression: &e,
		}
		for i, arg := range expr.CallExpr.Args {
			eoe.Expression.Operands[i] = &ExprOp{}
			err := buildExpr(arg, eoe.Expression.Operands[i])
			if err != nil {
				return err
			}
		}
		acc.Node = &eoe
	case *exprpb.Expr_ConstExpr:
		value, err := visitConst(expr.ConstExpr)
		if err != nil {
			return err
		}
		acc.Node = &ExprOpValue{Value: value}
	case *exprpb.Expr_IdentExpr:
		acc.Node = &ExprOpVar{Variable: expr.IdentExpr.Name}
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

		var sb strings.Builder
		for i := len(names) - 1; i >= 0; i-- {
			sb.WriteString(names[i])
			if i > 0 {
				sb.WriteString(".")
			}
		}
		if e == nil {
			acc.Node = &ExprOpVar{Variable: sb.String()}
		} else {
			op := new(ExprOp)
			err := buildExpr(e.SelectExpr.Operand, op)
			if err != nil {
				return err
			}
			acc.Node = &ExprOpExpr{
				Expression: &Expr{
					Operator: Field,
					Operands: []*ExprOp{
						op,
						{Node: &ExprOpVar{Variable: sb.String()}},
					},
				},
			}
		}
	case *exprpb.Expr_ListExpr:
		ok := true
		for _, e := range expr.ListExpr.Elements {
			if _, ok = e.ExprKind.(*exprpb.Expr_ConstExpr); !ok {
				break
			}
		}
		if ok { // only values in list, so acc.Node is a list of values
			listValue := structpb.ListValue{Values: make([]*structpb.Value, len(expr.ListExpr.Elements))}
			for i, e := range expr.ListExpr.Elements {
				value, err := visitConst(e.ExprKind.(*exprpb.Expr_ConstExpr).ConstExpr)
				if err != nil {
					return err
				}
				listValue.Values[i] = value
			}
			acc.Node = &ExprOpValue{Value: structpb.NewListValue(&listValue)}
		} else {
			// list of expressions
			operands := make([]*ExprOp, len(expr.ListExpr.Elements))
			for i := range operands {
				operands[i] = new(ExprOp)
				err := buildExpr(expr.ListExpr.Elements[i], operands[i])
				if err != nil {
					return err
				}
			}
			acc.Node = &ExprOpExpr{Expression: &Expr{Operator: List, Operands: operands}}
		}
	default:
		return fmt.Errorf("unsupported expression: %v", expr)
	}

	return nil
}

func visitConst(c *exprpb.Constant) (*structpb.Value, error) {
	switch v := c.ConstantKind.(type) {
	case *exprpb.Constant_BoolValue:
		return structpb.NewValue(v.BoolValue)
	case *exprpb.Constant_BytesValue:
		return structpb.NewValue(v.BytesValue)
	case *exprpb.Constant_DoubleValue:
		return structpb.NewValue(v.DoubleValue)
	case *exprpb.Constant_Int64Value:
		return structpb.NewValue(v.Int64Value)
	case *exprpb.Constant_NullValue:
		return structpb.NewValue(v.NullValue)
	case *exprpb.Constant_StringValue:
		return structpb.NewValue(v.StringValue)
	case *exprpb.Constant_Uint64Value:
		return structpb.NewValue(v.Uint64Value)
	default:
		return nil, fmt.Errorf("unsupported constant: %v", c)
	}
}
