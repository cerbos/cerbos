// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"errors"
	"fmt"
	"github.com/google/cel-go/common/ast"
	"sort"
	"strings"

	"github.com/google/cel-go/common/operators"
	"github.com/tidwall/pretty"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/cerbos/cerbos/internal/util"
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
	TransformMap       = "transformMap"
	TransformMapEntry  = "transformMapEntry"
	TransformList      = "transformList"
	Exists             = "exists"
	ExistsOne          = "exists_one"
	Map                = "map"
	Lambda             = "lambda"
	If                 = "if"
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
	case operators.LogicalAnd:
		return And, nil
	case operators.LogicalOr:
		return Or, nil
	case operators.LogicalNot:
		return Not, nil
	case operators.Conditional:
		return If, nil
	default:
		return fn, ErrUnknownOperator
	}
}

type replaceVarsFunc func(e *exprpb.Expr) (output *exprpb.Expr, matched bool, err error)

func replaceVarsGen(e *exprpb.Expr, f replaceVarsFunc) (output *exprpb.Expr, err error) {
	var r func(e *exprpb.Expr) *exprpb.Expr

	r = func(e *exprpb.Expr) *exprpb.Expr {
		if e == nil {
			return nil
		}

		switch ex := e.ExprKind.(type) {
		case *exprpb.Expr_SelectExpr:
			var e1 *exprpb.Expr
			var matched bool

			e1, matched, err = f(e)
			if err != nil {
				break
			}
			if matched {
				return e1
			}
			ex.SelectExpr.Operand = r(ex.SelectExpr.Operand)
		case *exprpb.Expr_CallExpr:
			ex.CallExpr.Target = r(ex.CallExpr.Target)
			for i, arg := range ex.CallExpr.Args {
				ex.CallExpr.Args[i] = r(arg)
			}
		case *exprpb.Expr_StructExpr:
			for _, entry := range ex.StructExpr.Entries {
				if k, ok := entry.KeyKind.(*exprpb.Expr_CreateStruct_Entry_MapKey); ok {
					k.MapKey = r(k.MapKey)
				}
				entry.Value = r(entry.Value)
			}
		case *exprpb.Expr_ComprehensionExpr:
			ce := ex.ComprehensionExpr
			ce.IterRange = r(ce.IterRange)
			ce.AccuInit = r(ce.AccuInit)
			ce.LoopStep = r(ce.LoopStep)
			ce.LoopCondition = r(ce.LoopCondition)
			// ce.Result seems to be always an identifier, so isn't necessary to process
		case *exprpb.Expr_ListExpr:
			for i, element := range ex.ListExpr.Elements {
				ex.ListExpr.Elements[i] = r(element)
			}
		}
		return e
	}

	output, ok := proto.Clone(e).(*exprpb.Expr)
	if !ok {
		return nil, fmt.Errorf("failed to clone an expression: %v", e)
	}
	output = r(output)
	internal.UpdateIDs(output)

	return output, err
}

type replaceVarsFunc2 func(e ast.Expr) (output ast.Expr, matched bool, err error)

func replaceVarsGen2(e ast.Expr, f replaceVarsFunc2) (output ast.Expr, err error) {
	var r func(e ast.Expr) ast.Expr

	r = func(e ast.Expr) ast.Expr {
		if e == nil {
			return nil
		}

		switch e.Kind() {
		case ast.SelectKind:
			ex := e.AsSelect()
			var e1 ast.Expr
			var matched bool

			e1, matched, err = f(e)
			if err != nil {
				break
			}
			if matched {
				return e1
			}
			return &selectExprOverride{
				e,
				&selectExpr{ex, r(ex.Operand())},
			}
		case ast.CallKind:
			ex := e.AsCall()
			args := make([]ast.Expr, len(ex.Args()))
			for i, arg := range ex.Args() {
				args[i] = r(arg)
			}
			return &callExprOverride{e, &callExpr{
				target: ex.Target(),
				args:   args,
			}}
		case ast.MapKind:
			ex := e.AsMap()
			entries := make([]ast.EntryExpr, len(ex.Entries()))
			for i, entry := range ex.Entries() {
				me := entry.AsMapEntry()

				mapEntry := &mapEntry{
					MapEntry: me,
					key:      r(me.Key()),
					value:    r(me.Value()),
				}
				entries[i] = &entryExpr{entry, mapEntry, nil}
			}
			return &mapExprOverride{e, &mapExpr{ex, entries}}
		case ast.StructKind:
			ex := e.AsStruct()
			entries := make([]ast.EntryExpr, len(ex.Fields()))
			for i, entry := range ex.Fields() {
				sf := entry.AsStructField()

				structField := &structField{
					StructField: sf,
					name:        sf.Name(),
					value:       r(sf.Value()),
				}
				entries[i] = &entryExpr{entry, nil, structField}
			}
			return &structExprOverride{e, &structExpr{ex, entries}}
		case ast.ComprehensionKind:
			ex := e.AsComprehension()
			ce := &comprehensionExpr{
				ComprehensionExpr: ex,
				iterRange:         r(ex.IterRange()),
				accuInit:          r(ex.AccuInit()),
				loopCondition:     r(ex.LoopCondition()),
				loopStep:          r(ex.LoopStep()),
				// ce.Result seems to be always an identifier, so isn't necessary to process
				//result:            r(ex.Result()),
			}
			return &comprehensionExprOverride{e, ce}
		case ast.ListKind:
			ex := e.AsList()
			elements := make([]ast.Expr, len(ex.Elements()))
			for i, element := range ex.Elements() {
				elements[i] = r(element)
			}
			return &listExprOverride{e, &listExpr{ex, elements}}
		}
		return e
	}

	output = r(e)
	output.RenumberIDs(internal.NewIDGen().Remap)

	return output, err
}

// This functions wraps references to known resource attributes in an `id` function call, which simply returns its argument.
// E.g. Replace R.attr.field1 with id(R.attr.field1) iif R.attr.field1 is passed in the request to the Query Planner API.
// This trick is necessary to evaluate expression like `P.attr.struct1[R.attr.field1]`, otherwise CEL tries to use `R.attr.field1`
// as a qualifier for `P.attr.struct1` and produces the error https://github.com/cerbos/cerbos/issues/1340
func replaceResourceVals(e ast.Expr, vals map[string]*structpb.Value) (output ast.Expr, err error) {
	return replaceVarsGen2(e, func(ex ast.Expr) (output ast.Expr, matched bool, err error) {
		if e.Kind() != ast.SelectKind {
			return nil, false, nil
		}
		sel := ex.AsSelect()

		field := sel.FieldName()
		if _, ok := vals[field]; ok {
			sel = sel.Operand().AsSelect()
			if sel.FieldName() != conditions.CELAttrField {
				return nil, false, nil
			}
			// match R.attr.<field>
			ident := sel.Operand().AsIdent()
			if sel.Operand().Kind() == ast.IdentKind && ident == conditions.CELResourceAbbrev {
				fact := ast.NewExprFactory()
				return fact.NewCall(0, conditions.IDFn, ex), true, nil
			}
			if sel.Operand().Kind() == ast.SelectKind || sel.Operand().AsSelect().FieldName() != conditions.CELResourceField {
				return nil, false, nil
			}
			sel = sel.Operand().AsSelect()
			ident = sel.Operand().AsIdent()
			// match request.resource.attr.<field>
			if sel.Operand().Kind() == ast.IdentKind && ident == conditions.CELRequestIdent {
				fact := ast.NewExprFactory()
				return fact.NewCall(0, conditions.IDFn, ex), true, nil
			}
		}
		return nil, false, nil
	})
}

func replaceVarsProto(e *exprpb.Expr, vars map[string]*exprpb.Expr) (output *exprpb.Expr, err error) {
	return replaceVarsGen(e, func(ex *exprpb.Expr) (output *exprpb.Expr, matched bool, err error) {
		se, ok := ex.ExprKind.(*exprpb.Expr_SelectExpr)
		if !ok {
			return nil, false, nil
		}
		sel := se.SelectExpr
		ident := sel.Operand.GetIdentExpr()
		if ident != nil && (ident.Name == conditions.CELVariablesAbbrev || ident.Name == conditions.CELVariablesIdent) {
			matched = true
			if e1, ok := vars[sel.Field]; ok {
				//nolint:forcetypeassert
				output = proto.Clone(e1).(*exprpb.Expr)
			} else {
				err = multierr.Append(err, fmt.Errorf("unknown variable %q", sel.Field))
			}
		}
		return
	})
}

func replaceVars(e ast.Expr, vars map[string]ast.Expr) (output ast.Expr, err error) {
	return replaceVarsGen2(e, func(ex ast.Expr) (output ast.Expr, matched bool, err error) {
		if ex.Kind() != ast.StructKind {
			return nil, false, nil
		}
		sel := ex.AsSelect()
		ident := sel.Operand().AsIdent()
		if sel.Operand().Kind() == ast.IdentKind && (ident == conditions.CELVariablesAbbrev || ident == conditions.CELVariablesIdent) {
			matched = true
			if e1, ok := vars[sel.FieldName()]; ok {
				fact := ast.NewExprFactory()
				output = fact.CopyExpr(e1)
			} else {
				err = multierr.Append(err, fmt.Errorf("unknown variable %q", sel.FieldName()))
			}
		}
		return
	})
}

func convert(expr *enginev1.PlanResourcesAst_Node, acc *enginev1.PlanResourcesFilter_Expression_Operand) error {
	type ExprOp = enginev1.PlanResourcesFilter_Expression_Operand

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

func mkConstStringExpr(s string) *exprpb.Expr {
	return &exprpb.Expr{
		ExprKind: &exprpb.Expr_ConstExpr{
			ConstExpr: &exprpb.Constant{
				ConstantKind: &exprpb.Constant_StringValue{
					StringValue: s,
				},
			},
		},
	}
}

func structKeys(x *exprpb.Expr_CreateStruct) []*exprpb.Expr {
	type element struct {
		*exprpb.Expr
		SortKey string
	}

	elems := make([]element, len(x.Entries))
	for i, entry := range x.Entries {
		var expr *exprpb.Expr

		switch e := entry.KeyKind.(type) {
		case *exprpb.Expr_CreateStruct_Entry_MapKey:
			expr = e.MapKey
		case *exprpb.Expr_CreateStruct_Entry_FieldKey:
			expr = mkConstStringExpr(e.FieldKey)
		}

		elems[i] = element{
			Expr:    expr,
			SortKey: (&exprpb.Expr{ExprKind: expr.ExprKind}).String(), // sort by expression, ignoring AST node id
		}
	}

	sort.Slice(elems, func(i, j int) bool {
		return elems[i].SortKey < elems[j].SortKey
	})

	exprs := make([]*exprpb.Expr, len(elems))
	for i, elem := range elems {
		exprs[i] = elem.Expr
	}

	return exprs
}

func mkExprOpExpr(op string, args ...*enginev1.PlanResourcesFilter_Expression_Operand) *exprOpExpr {
	return &enginev1.PlanResourcesFilter_Expression_Operand_Expression{
		Expression: &enginev1.PlanResourcesFilter_Expression{Operator: op, Operands: args},
	}
}

func buildExpr(expr *exprpb.Expr, acc *enginev1.PlanResourcesFilter_Expression_Operand) error {
	return buildExprImpl(expr, acc, nil)
}

type (
	exprOp      = enginev1.PlanResourcesFilter_Expression_Operand
	exprOpExpr  = enginev1.PlanResourcesFilter_Expression_Operand_Expression
	exprOpValue = enginev1.PlanResourcesFilter_Expression_Operand_Value
	exprOpVar   = enginev1.PlanResourcesFilter_Expression_Operand_Variable
)

func buildExprImpl(cur *exprpb.Expr, acc *enginev1.PlanResourcesFilter_Expression_Operand, parent *exprpb.Expr) error {
	switch expr := cur.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		fn, _ := opFromCLE(expr.CallExpr.Function)
		var offset int
		if expr.CallExpr.Target != nil {
			offset++
		}
		operands := make([]*exprOp, len(expr.CallExpr.Args)+offset)
		if expr.CallExpr.Target != nil {
			operands[0] = new(exprOp)
			err := buildExprImpl(expr.CallExpr.Target, operands[0], cur)
			if err != nil {
				return err
			}
		}

		for i, arg := range expr.CallExpr.Args {
			operands[i+offset] = new(exprOp)
			err := buildExprImpl(arg, operands[i+offset], cur)
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
		acc.Node = &exprOpValue{Value: value}
	case *exprpb.Expr_IdentExpr:
		acc.Node = &exprOpVar{Variable: expr.IdentExpr.Name}
	case *exprpb.Expr_SelectExpr:
		if expr.SelectExpr.TestOnly {
			acc.Node = &exprOpValue{Value: structpb.NewBoolValue(true)}
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
			acc.Node = &exprOpVar{Variable: sb.String()}
		} else {
			op := new(exprOp)
			err := buildExprImpl(expr.SelectExpr.Operand, op, cur)
			if err != nil {
				return err
			}
			acc.Node = mkExprOpExpr(GetField, op, &exprOp{Node: &exprOpVar{Variable: expr.SelectExpr.Field}})
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
			acc.Node = &exprOpValue{Value: structpb.NewListValue(&listValue)}
		} else {
			// list of expressions
			operands := make([]*exprOp, len(x.Elements))
			for i := range operands {
				operands[i] = new(exprOp)
				err := buildExprImpl(x.Elements[i], operands[i], cur)
				if err != nil {
					return err
				}
			}
			acc.Node = mkExprOpExpr(List, operands...)
		}
	case *exprpb.Expr_StructExpr:
		x := expr.StructExpr
		if c := parent.GetCallExpr(); c != nil {
			// convert struct to a list, if it is a key membership test operation
			const nArgs = 2
			const rhsIndex = 1 // right-hand side arg index
			if c.Function == operators.In && len(c.Args) == nArgs && c.Args[rhsIndex] == cur {
				list := internal.MkListExprProto(structKeys(x))
				err := buildExprImpl(list, acc, parent)
				if err != nil {
					return err
				}
				return nil
			}
		}
		operands := make([]*exprOp, len(x.Entries))
		for i, entry := range x.Entries {
			k, v := new(exprOp), new(exprOp)
			switch entry := entry.KeyKind.(type) {
			case *exprpb.Expr_CreateStruct_Entry_MapKey:
				err := buildExprImpl(entry.MapKey, k, cur)
				if err != nil {
					return err
				}
			case *exprpb.Expr_CreateStruct_Entry_FieldKey:
				k.Node = &exprOpValue{Value: structpb.NewStringValue(entry.FieldKey)}
			}
			err := buildExprImpl(entry.Value, v, cur)
			if err != nil {
				return err
			}
			operands[i] = new(exprOp)
			operands[i].Node = mkExprOpExpr(SetField, k, v)
		}
		acc.Node = mkExprOpExpr(Struct, operands...)
	case *exprpb.Expr_ComprehensionExpr:
		lambdaAst, err := buildLambdaAST(expr.ComprehensionExpr)
		if err != nil {
			return err
		}
		acc.Node, err = lambdaAst.mkNode(cur)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("buildExprImpl: unsupported expression: %v", expr)
	}

	return nil
}

func (lambdaAst *lambdaAST) mkNode(cur *exprpb.Expr) (*exprOpExpr, error) {
	lambda, err := buildLambdaExprOp(lambdaAst.expr, cur)
	if err != nil {
		return nil, err
	}
	lambda2, err := buildLambdaExprOp(lambdaAst.expr2, cur)
	if err != nil {
		return nil, err
	}
	lambdaArgs := []*exprOp{lambda}
	if lambda2 != nil {
		lambdaArgs = append(lambdaArgs, lambda2)
	}
	lambdaArgs = append(lambdaArgs, &exprOp{Node: &exprOpVar{Variable: lambdaAst.iterVar}})
	if lambdaAst.iterVar2 != "" {
		lambdaArgs = append(lambdaArgs, &exprOp{Node: &exprOpVar{Variable: lambdaAst.iterVar2}})
	}
	target, err := lambdaAst.buildIterRangeOp(cur)
	if err != nil {
		return nil, err
	}
	return mkExprOpExpr(lambdaAst.operator, target, &exprOp{Node: mkExprOpExpr(Lambda, lambdaArgs...)}), nil
}

func (lambdaAst *lambdaAST) buildIterRangeOp(cur *exprpb.Expr) (*exprOp, error) {
	ir := lambdaAst.iterRange
	if x, ok := ir.ExprKind.(*exprpb.Expr_StructExpr); ok && !canOperateOnStruct(lambdaAst.operator) {
		ir = internal.MkListExprProto(structKeys(x.StructExpr))
	}
	irExprOp := new(exprOp)
	err := buildExprImpl(ir, irExprOp, cur)
	return irExprOp, err
}

func buildLambdaExprOp(expr, cur *exprpb.Expr) (*exprOp, error) {
	if expr == nil {
		return nil, nil
	}
	lambda := new(exprOp)
	err := buildExprImpl(expr, lambda, cur)
	if err != nil {
		return nil, err
	}
	if _, ok := lambda.Node.(*exprOpExpr); !ok {
		if _, ok = lambda.Node.(*exprOpVar); !ok {
			return nil, fmt.Errorf("expected expression or variable, got %T", lambda.Node)
		}
	}
	return lambda, nil
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
		return structpb.NewNullValue(), nil
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

var (
	falseExprOpValue = &enginev1.PlanResourcesFilter_Expression_Operand{
		Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
			Value: structpb.NewBoolValue(false),
		},
	}
	trueExprOpValue = &enginev1.PlanResourcesFilter_Expression_Operand{
		Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
			Value: structpb.NewBoolValue(true),
		},
	}
)

func normaliseFilterExprOpExpr(expr *enginev1.PlanResourcesFilter_Expression_Operand_Expression) *enginev1.PlanResourcesFilter_Expression_Operand {
	if expr.Expression.Operator == In && len(expr.Expression.Operands) == 2 {
		if s := normaliseInExpr(expr); s != nil {
			return s
		}
	}

	var logicalOperator string
	var operandHashes map[uint64]struct{}
	if expr.Expression.Operator == And || expr.Expression.Operator == Or || expr.Expression.Operator == Not {
		logicalOperator = expr.Expression.Operator

		if logicalOperator != Not {
			operandHashes = make(map[uint64]struct{}, len(expr.Expression.Operands))
		}
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
					return falseExprOpValue
				case logicalOperator == Or && boolVal:
					// A literal true makes the whole OR expression return true
					return trueExprOpValue
				}
			}
		}

		if operandHashes != nil {
			opHash := util.HashPB(op, nil)
			if _, ok := operandHashes[opHash]; ok {
				// Ignore repeated values in and/or
				continue
			}
			operandHashes[opHash] = struct{}{}
		}

		operands = append(operands, normalOp)
	}

	// AND or OR of a single value is the value itself
	//nolint:nestif
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

// normaliseInExpr normalises an IN expression in place.
// If the return value is nil, then the expression can be simplified further by other normalisers.
func normaliseInExpr(expr *enginev1.PlanResourcesFilter_Expression_Operand_Expression) *enginev1.PlanResourcesFilter_Expression_Operand {
	if v := expr.Expression.Operands[1].GetValue(); v != nil {
		switch vt := v.Kind.(type) {
		case *structpb.Value_StructValue:
			mapVals := vt.StructValue.Fields
			switch len(mapVals) {
			case 0:
				return falseExprOpValue
			case 1:
				var keyVal *structpb.Value
				for k := range mapVals {
					keyVal = structpb.NewStringValue(k)
				}
				expr.Expression.Operator = Equals
				expr.Expression.Operands[1] = &enginev1.PlanResourcesFilter_Expression_Operand{
					Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
						Value: keyVal,
					},
				}
			}

		case *structpb.Value_ListValue:
			listVals := vt.ListValue.Values
			switch len(listVals) {
			case 0:
				return falseExprOpValue
			case 1:
				expr.Expression.Operator = Equals
				expr.Expression.Operands[1] = &enginev1.PlanResourcesFilter_Expression_Operand{
					Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{
						Value: listVals[0],
					},
				}
			}
		default:
			// operand is not a list or map so convert it to a EQ
			expr.Expression.Operator = Equals
		}
	}

	return nil
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
			b.Write(pretty.UglyInPlace(val))
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

func canOperateOnStruct(op string) bool {
	return op == TransformMap || op == TransformMapEntry || op == TransformList
}
