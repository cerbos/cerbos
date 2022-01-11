// Copyright 2021-2022 Zenauth Ltd.
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

const (
	Or                 = "or"
	And                = "and"
	Not                = "not"
	Equals             = "eq"
	NotEquals          = "ne"
	GreaterThan        = "gt"
	GreaterThanOrEqual = "ge"
	LessThan           = "lt"
	LessThanOrEqual    = "le"
	In                 = "in"
	List               = "list"
	Struct             = "struct"
	Add                = "add"
	SetField           = "set-field"
	GetField           = "get-field"
	Index              = "index"
	Comprehension      = "loop"
	LoopStep           = "loop-step"
	LoopCondition      = "loop-condition"
	LoopResult         = "loop-result"
	LoopAccuInit       = "loop-accu-init"
	LoopIterRange      = "loop-iter-range"
	LoopIterVar        = "loop-iter-var"
	LoopAccuVar        = "loop-accu-var"
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

func replaceVars(e *exprpb.Expr, vars map[string]*exprpb.Expr) (output *exprpb.Expr, err error) {
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
					return proto.Clone(v).(*exprpb.Expr)
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

	output, ok := proto.Clone(e).(*exprpb.Expr)
	if !ok {
		return nil, fmt.Errorf("failed to clone an expression: %v", e)
	}
	output = r(output)
	updateIds(output)

	return output, err
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

		if node.LogicalOperation.Operator == enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_NOT {
			op = enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_AND)]
		}
		source = strings.Join(s, " "+strings.TrimPrefix(op, "OPERATOR_")+" ")

		if node.LogicalOperation.Operator == enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_NOT {
			if len(node.LogicalOperation.Nodes) == 1 {
				source = "NOT " + source
			} else {
				source = "NOT (" + source + ")"
			}
		}
	}

	return "(" + source + ")", nil
}

func convert(expr *enginev1.ResourcesQueryPlanOutput_Node, acc *responsev1.ResourcesQueryPlanResponse_Expression_Operand) error {
	type (
		Expr        = responsev1.ResourcesQueryPlanResponse_Expression
		ExprOp      = responsev1.ResourcesQueryPlanResponse_Expression_Operand
		ExprOpExpr  = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Expression
		ExprOpValue = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Value
		ExprOpVar   = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Variable
	)

	if expr == nil || expr.Node == nil {
		return nil
	}

	switch node := expr.Node.(type) {
	case *enginev1.ResourcesQueryPlanOutput_Node_Expression:
		err := buildExpr(node.Expression.Expr, acc)
		if err != nil {
			return err
		}
	case *enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation:
		operands := make([]*ExprOp, len(node.LogicalOperation.Nodes))
		for i, n := range node.LogicalOperation.Nodes {
			operands[i] = new(ExprOp)
			err := convert(n, operands[i])
			if err != nil {
				return err
			}
		}
		var operation string
		switch node.LogicalOperation.Operator {
		case enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_AND:
			operation = And
		case enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_OR:
			operation = Or
		case enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_NOT:
			operation = Not
		default:
			if name, ok := enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(node.LogicalOperation.Operator)]; ok {
				return fmt.Errorf("unknown logical operator: %v", name)
			}

			return fmt.Errorf("unknown logical operator: %v", node.LogicalOperation.Operator)
		}
		acc.Node = mkExprOpExpr(operation, operands...)
	}

	return nil
}

func mkExprOpExpr(op string, args ...*responsev1.ResourcesQueryPlanResponse_Expression_Operand) *responsev1.ResourcesQueryPlanResponse_Expression_Operand_Expression {
	return &responsev1.ResourcesQueryPlanResponse_Expression_Operand_Expression{
		Expression: &responsev1.ResourcesQueryPlanResponse_Expression{Operator: op, Operands: args},
	}
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
		var offset int
		if expr.CallExpr.Target != nil {
			offset++
		}
		operands := make([]*ExprOp, len(expr.CallExpr.Args)+offset)
		if expr.CallExpr.Target != nil {
			operands[0] = new(ExprOp)
			err := buildExpr(expr.CallExpr.Target, operands[0])
			if err != nil {
				return err
			}
		}

		for i, arg := range expr.CallExpr.Args {
			operands[i+offset] = new(ExprOp)
			err := buildExpr(arg, operands[i+offset])
			if err != nil {
				return err
			}
		}
		acc.Node = mkExprOpExpr(fn, operands...)
	case *exprpb.Expr_ConstExpr:
		value, err := visitConst(expr.ConstExpr)
		if err != nil {
			return err
		}
		acc.Node = &ExprOpValue{Value: value}
	case *exprpb.Expr_IdentExpr:
		acc.Node = &ExprOpVar{Variable: expr.IdentExpr.Name}
	case *exprpb.Expr_SelectExpr:
		if expr.SelectExpr.TestOnly {
			acc.Node = &ExprOpValue{Value: structpb.NewBoolValue(true)}
			break
		}
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
			var sb strings.Builder
			for i := len(names) - 1; i >= 0; i-- {
				sb.WriteString(names[i])
				if i > 0 {
					sb.WriteString(".")
				}
			}
			// This is a compound "a.b.c" variable
			acc.Node = &ExprOpVar{Variable: sb.String()}
		} else {
			op := new(ExprOp)
			err := buildExpr(expr.SelectExpr.Operand, op)
			if err != nil {
				return err
			}
			acc.Node = mkExprOpExpr(GetField, op, &ExprOp{Node: &ExprOpVar{Variable: expr.SelectExpr.Field}})
		}
	case *exprpb.Expr_ListExpr:
		x := expr.ListExpr
		ok := true
		for _, e := range x.Elements {
			if _, ok = e.ExprKind.(*exprpb.Expr_ConstExpr); !ok {
				break
			}
		}
		if ok { // only values in list, so acc.Node is a list of values
			listValue := structpb.ListValue{Values: make([]*structpb.Value, len(x.Elements))}
			for i, e := range x.Elements {
				value, err := visitConst(e.ExprKind.(*exprpb.Expr_ConstExpr).ConstExpr)
				if err != nil {
					return err
				}
				listValue.Values[i] = value
			}
			acc.Node = &ExprOpValue{Value: structpb.NewListValue(&listValue)}
		} else {
			// list of expressions
			operands := make([]*ExprOp, len(x.Elements))
			for i := range operands {
				operands[i] = new(ExprOp)
				err := buildExpr(x.Elements[i], operands[i])
				if err != nil {
					return err
				}
			}
			acc.Node = mkExprOpExpr(List, operands...)
		}
	case *exprpb.Expr_StructExpr:
		x := expr.StructExpr
		operands := make([]*ExprOp, len(x.Entries))
		for i, entry := range x.Entries {
			k, v := new(ExprOp), new(ExprOp)
			switch entry := entry.KeyKind.(type) {
			case *exprpb.Expr_CreateStruct_Entry_MapKey:
				err := buildExpr(entry.MapKey, k)
				if err != nil {
					return err
				}
			case *exprpb.Expr_CreateStruct_Entry_FieldKey:
				k.Node = &ExprOpValue{Value: structpb.NewStringValue(entry.FieldKey)}
			}
			err := buildExpr(entry.Value, v)
			if err != nil {
				return err
			}
			operands[i] = new(ExprOp)
			operands[i].Node = mkExprOpExpr(SetField, k, v)
		}
		acc.Node = mkExprOpExpr(Struct, operands...)
	case *exprpb.Expr_ComprehensionExpr:
		x := expr.ComprehensionExpr
		var operands []*ExprOp

		for _, r := range []struct {
			x *exprpb.Expr
			n string
			v string
		}{
			{n: LoopStep, x: x.LoopStep},
			{n: LoopCondition, x: x.LoopCondition},
			{n: LoopResult, x: x.Result},
			{n: LoopAccuInit, x: x.AccuInit},
			{n: LoopIterRange, x: x.IterRange},
			{n: LoopIterVar, v: x.IterVar},
			{n: LoopAccuVar, v: x.AccuVar},
		} {
			op := new(ExprOp)
			if r.x != nil {
				err := buildExpr(r.x, op)
				if err != nil {
					return err
				}
			} else if r.v != "" {
				op.Node = &ExprOpVar{Variable: r.v}
			}
			operands = append(operands, &ExprOp{Node: mkExprOpExpr(r.n, op)})
		}
		acc.Node = mkExprOpExpr(Comprehension, operands...)
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
