// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/common/operators"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
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
	Sub                = "sub"
	Mult               = "mult"
	Div                = "div"
	Mod                = "mod"
	SetField           = "set-field"
	GetField           = "get-field"
	Index              = "index"
	All                = "all"
	Filter             = "filter"
	Exists             = "exists"
	ExistsOne          = "exists_one"
	Map                = "map"
	Lambda             = "lambda"
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
	case operators.Subtract:
		return Sub, nil
	case operators.Multiply:
		return Mult, nil
	case operators.Divide:
		return Div, nil
	case operators.Modulo:
		return Mod, nil
	case operators.Index:
		return Index, nil
	case operators.LogicalNot:
		return Not, nil
	default:
		return fn, ErrUnknownOperator
	}
}

func updateIds(e *exprpb.Expr) {
	var n int64
	ids := make(map[*exprpb.Expr]int64)

	var impl func(e *exprpb.Expr)
	impl = func(e *exprpb.Expr) {
		if e == nil {
			return
		}
		if id, ok := ids[e]; ok {
			e.Id = id
		} else {
			n++
			ids[e] = n
			e.Id = n
		}

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
					//nolint:forcetypeassert
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

func convert(expr *enginev1.PlanResourcesAst_Node, acc *enginev1.PlanResourcesFilter_Expression_Operand) error {
	type (
		Expr        = enginev1.PlanResourcesFilter_Expression
		ExprOp      = enginev1.PlanResourcesFilter_Expression_Operand
		ExprOpExpr  = enginev1.PlanResourcesFilter_Expression_Operand_Expression
		ExprOpValue = enginev1.PlanResourcesFilter_Expression_Operand_Value
		ExprOpVar   = enginev1.PlanResourcesFilter_Expression_Operand_Variable
	)

	if expr == nil || expr.Node == nil {
		return nil
	}

	switch node := expr.Node.(type) {
	case *enginev1.PlanResourcesAst_Node_Expression:
		err := buildExpr(node.Expression.Expr, acc)
		if err != nil {
			return err
		}
	case *enginev1.PlanResourcesAst_Node_LogicalOperation:
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
		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_AND:
			operation = And
		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_OR:
			operation = Or
		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT:
			operation = Not
		default:
			if name, ok := enginev1.PlanResourcesAst_LogicalOperation_Operator_name[int32(node.LogicalOperation.Operator)]; ok {
				return fmt.Errorf("unknown logical operator: %v", name)
			}

			return fmt.Errorf("unknown logical operator: %v", node.LogicalOperation.Operator)
		}
		acc.Node = mkExprOpExpr(operation, operands...)
	}

	return nil
}

func mkExprOpExpr(op string, args ...*enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand_Expression {
	return &enginev1.PlanResourcesFilter_Expression_Operand_Expression{
		Expression: &enginev1.PlanResourcesFilter_Expression{Operator: op, Operands: args},
	}
}

func buildExpr(expr *exprpb.Expr, acc *enginev1.PlanResourcesFilter_Expression_Operand) error {
	type (
		Expr        = enginev1.PlanResourcesFilter_Expression
		ExprOp      = enginev1.PlanResourcesFilter_Expression_Operand
		ExprOpExpr  = enginev1.PlanResourcesFilter_Expression_Operand_Expression
		ExprOpValue = enginev1.PlanResourcesFilter_Expression_Operand_Value
		ExprOpVar   = enginev1.PlanResourcesFilter_Expression_Operand_Variable
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
		var operator string
		var step *exprpb.Expr_CallExpr
		var ok bool
		if step, ok = x.LoopStep.ExprKind.(*exprpb.Expr_CallExpr); !ok {
			return fmt.Errorf("expected loop-step expression type CallExpr, got: %T", x.LoopStep.ExprKind)
		}
		var le *exprpb.Expr
		switch step.CallExpr.Function {
		case operators.LogicalAnd:
			operator = All
			le = step.CallExpr.Args[1]
		case operators.LogicalOr:
			operator = Exists
			le = step.CallExpr.Args[1]
		case operators.Add:
			operator = Map
			if elements := step.CallExpr.Args[1].GetListExpr().GetElements(); len(elements) > 0 {
				le = elements[0]
			}
		case operators.Conditional:
			switch x.AccuInit.ExprKind.(type) {
			case *exprpb.Expr_ListExpr:
				operator = Filter
			case *exprpb.Expr_ConstExpr:
				operator = ExistsOne
			default:
				return fmt.Errorf("expected loop-accu-init expression type ConstExpr or ListExpr, got: %T", x.AccuInit.ExprKind)
			}
			le = step.CallExpr.Args[0]
		default:
			return fmt.Errorf("unexpected loop-step function: %q", step.CallExpr.Function)
		}
		lambda := new(ExprOp)
		err := buildExpr(le, lambda)
		if err != nil {
			return err
		}
		_, ok = lambda.Node.(*ExprOpExpr)
		if !ok {
			return fmt.Errorf("expect expression, got %T", lambda.Node)
		}

		op := new(ExprOp)
		err = buildExpr(x.IterRange, op)
		if err != nil {
			return err
		}

		acc.Node = mkExprOpExpr(operator, op,
			&ExprOp{Node: mkExprOpExpr(Lambda, lambda, &ExprOp{Node: &ExprOpVar{Variable: x.IterVar}})})
	default:
		return fmt.Errorf("buildExpr: unsupported expression: %v", expr)
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

func toFilter(plan *enginev1.PlanResourcesAst_Node) (*enginev1.PlanResourcesFilter, error) {
	filter := &enginev1.PlanResourcesFilter{
		Kind:      enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
		Condition: new(enginev1.PlanResourcesFilter_Expression_Operand),
	}

	if err := convert(plan, filter.Condition); err != nil {
		return nil, err
	}

	return normaliseFilter(filter), nil
}

func normaliseFilter(filter *enginev1.PlanResourcesFilter) *enginev1.PlanResourcesFilter {
	filter.Condition = normaliseFilterExprOp(filter.Condition)

	if filter.Condition == nil {
		filter.Kind = enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED
		return filter
	}

	if filter.Condition.Node == nil {
		filter.Condition = nil
		filter.Kind = enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED
		return filter
	}

	if b, ok := asBoolValue(filter.Condition); ok {
		filter.Condition = nil
		if b {
			filter.Kind = enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED
		} else {
			filter.Kind = enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED
		}
	}

	return filter
}

func normaliseFilterExprOp(cond *enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	if cond == nil {
		return nil
	}

	switch t := cond.Node.(type) {
	case *enginev1.PlanResourcesFilter_Expression_Operand_Expression:
		return normaliseFilterExprOpExpr(t)
	case *enginev1.PlanResourcesFilter_Expression_Operand_Value:
		return cond
	case *enginev1.PlanResourcesFilter_Expression_Operand_Variable:
		return normaliseFilterExprOpVar(t)
	}

	return cond
}

//nolint: nestif
func normaliseFilterExprOpExpr(expr *enginev1.PlanResourcesFilter_Expression_Operand_Expression) *enginev1.PlanResourcesFilter_Expression_Operand {
	var logicalOperator string
	if expr.Expression.Operator == And || expr.Expression.Operator == Or || expr.Expression.Operator == Not {
		logicalOperator = expr.Expression.Operator
	}

	operands := make([]*enginev1.PlanResourcesFilter_Expression_Operand, 0, len(expr.Expression.Operands))
	for _, op := range expr.Expression.Operands {
		normalOp := normaliseFilterExprOp(op)
		if normalOp == nil {
			continue
		}

		if logicalOperator != "" {
			if boolVal, ok := asBoolValue(normalOp); ok {
				switch {
				case logicalOperator == And && boolVal:
					// Ignore literal true values because they don't matter
					continue
				case logicalOperator == Or && !boolVal:
					// Ignore literal false values because they don't matter
					continue
				case logicalOperator == And && !boolVal:
					// A literal false makes the whole AND expression return false
					return &enginev1.PlanResourcesFilter_Expression_Operand{
						Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
							Value: structpb.NewBoolValue(false),
						},
					}
				case logicalOperator == Or && boolVal:
					// A literal true makes the whole OR expression return true
					return &enginev1.PlanResourcesFilter_Expression_Operand{
						Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
							Value: structpb.NewBoolValue(true),
						},
					}
				}
			}
		}

		operands = append(operands, normalOp)
	}

	// AND or OR of a single value is the value itself
	if logicalOperator != "" {
		switch len(operands) {
		case 0:
			// because all true operands were removed, the result simplifies to true (true && true == true)
			if logicalOperator == And {
				return &enginev1.PlanResourcesFilter_Expression_Operand{
					Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
						Value: structpb.NewBoolValue(true),
					},
				}
			}

			// because all false operands were removed, the result simplifies to false (false || false == false)
			if logicalOperator == Or {
				return &enginev1.PlanResourcesFilter_Expression_Operand{
					Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
						Value: structpb.NewBoolValue(false),
					},
				}
			}
			return nil
		case 1:
			// AND or OR of a single value is the value itself
			if logicalOperator == And || logicalOperator == Or {
				return operands[0]
			}

			// NOT of a single bool value
			if logicalOperator == Not {
				if boolVal, ok := asBoolValue(operands[0]); ok {
					return &enginev1.PlanResourcesFilter_Expression_Operand{
						Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
							Value: structpb.NewBoolValue(!boolVal),
						},
					}
				}
			}
		}
	}

	expr.Expression.Operands = operands
	return &enginev1.PlanResourcesFilter_Expression_Operand{Node: expr}
}

func normaliseFilterExprOpVar(v *enginev1.PlanResourcesFilter_Expression_Operand_Variable) *enginev1.PlanResourcesFilter_Expression_Operand {
	if v == nil {
		return nil
	}

	v.Variable = conditions.ExpandAbbrev(v.Variable)
	return &enginev1.PlanResourcesFilter_Expression_Operand{Node: v}
}

func asBoolValue(op *enginev1.PlanResourcesFilter_Expression_Operand) (bool, bool) {
	if op == nil {
		return false, false
	}

	if v := op.GetValue(); v != nil {
		if _, ok := v.Kind.(*structpb.Value_BoolValue); ok {
			return v.GetBoolValue(), true
		}
	}

	return false, false
}

func filterToString(filter *enginev1.PlanResourcesFilter) string {
	switch filter.Kind {
	case enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED:
		return "(true)"
	case enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED:
		return "(false)"
	case enginev1.PlanResourcesFilter_KIND_CONDITIONAL:
		b := new(strings.Builder)
		filterExprOpToString(b, filter.Condition)
		return b.String()
	default:
		return ""
	}
}

func filterExprOpToString(b *strings.Builder, cond *enginev1.PlanResourcesFilter_Expression_Operand) {
	if cond == nil {
		return
	}

	switch t := cond.Node.(type) {
	case *enginev1.PlanResourcesFilter_Expression_Operand_Expression:
		filterExprOpExprToString(b, t.Expression)
	case *enginev1.PlanResourcesFilter_Expression_Operand_Value:
		if val, err := protojson.Marshal(t.Value); err != nil {
			b.WriteString("<ERROR>")
		} else {
			b.Write(val)
		}
	case *enginev1.PlanResourcesFilter_Expression_Operand_Variable:
		b.WriteString(t.Variable)
	}
}

func filterExprOpExprToString(b *strings.Builder, expr *enginev1.PlanResourcesFilter_Expression) {
	if expr == nil {
		return
	}

	b.WriteString("(")
	b.WriteString(expr.Operator)
	b.WriteString(" ")

	numSpaces := len(expr.Operands) - 1
	for i, op := range expr.Operands {
		filterExprOpToString(b, op)
		if i < numSpaces {
			b.WriteString(" ")
		}
	}

	b.WriteString(")")
}
