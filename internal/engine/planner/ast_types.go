package planner

import (
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types/ref"
)

// callExprOverride implements the override for CallExpr
type callExprOverride struct {
	ast.Expr
	o ast.CallExpr
}

func (e *callExprOverride) AsCall() ast.CallExpr {
	return e.o
}

// comprehensionExprOverride implements the override for ComprehensionExpr
type comprehensionExprOverride struct {
	ast.Expr
	o ast.ComprehensionExpr
}

func (e *comprehensionExprOverride) AsComprehension() ast.ComprehensionExpr {
	return e.o
}

// identExprOverride implements the override for ident string
type identExprOverride struct {
	ast.Expr
	o string
}

func (e *identExprOverride) AsIdent() string {
	return e.o
}

// literalExprOverride implements the override for ref.Val
type literalExprOverride struct {
	ast.Expr
	o ref.Val
}

func (e *literalExprOverride) AsLiteral() ref.Val {
	return e.o
}

// listExprOverride implements the override for ListExpr
type listExprOverride struct {
	ast.Expr
	o ast.ListExpr
}

func (e *listExprOverride) AsList() ast.ListExpr {
	return e.o
}

// mapExprOverride implements the override for MapExpr
type mapExprOverride struct {
	ast.Expr
	o ast.MapExpr
}

func (e *mapExprOverride) AsMap() ast.MapExpr {
	return e.o
}

// selectExprOverride implements the override for SelectExpr
type selectExprOverride struct {
	ast.Expr
	o *selectExpr
}

func (e *selectExprOverride) AsSelect() ast.SelectExpr {
	return e.o
}

// structExprOverride implements the override for StructExpr
type structExprOverride struct {
	ast.Expr
	o ast.StructExpr
}

func (e *structExprOverride) AsStruct() ast.StructExpr {
	return e.o
}

// Call expression implementation
type callExpr struct {
	ast.CallExpr
	target ast.Expr
	args   []ast.Expr
}

func (e *callExpr) Target() ast.Expr {
	return e.target
}

func (e *callExpr) Args() []ast.Expr {
	return e.args
}

// List expression implementation
type listExpr struct {
	ast.ListExpr
	elements []ast.Expr
}

func (e *listExpr) Elements() []ast.Expr {
	return e.elements
}

// Select expression implementation
type selectExpr struct {
	ast.SelectExpr
	operand ast.Expr
}

func (e *selectExpr) Operand() ast.Expr {
	return e.operand
}

type entryExpr struct {
	ast.EntryExpr
	mapEntry    *mapEntry
	structField *structField
}

func (e *entryExpr) MapEntry() ast.MapEntry {
	return e.mapEntry
}

func (e *entryExpr) StructField() *structField {
	return e.structField
}

// Map expression implementation
type mapExpr struct {
	ast.MapExpr
	entries []ast.EntryExpr
}

func (e *mapExpr) Entries() []ast.EntryExpr {
	return e.entries
}

func (e *mapExpr) Size() int {
	return len(e.entries)
}

// Map entry implementation
type mapEntry struct {
	ast.MapEntry
	key   ast.Expr
	value ast.Expr
}

func (e *mapEntry) Key() ast.Expr {
	return e.key
}

func (e *mapEntry) Value() ast.Expr {
	return e.value
}

// Struct expression implementation
type structExpr struct {
	ast.StructExpr
	fields []ast.EntryExpr
}

func (e *structExpr) Fields() []ast.EntryExpr {
	return e.fields
}

// Struct field implementation
type structField struct {
	ast.StructField
	name  string
	value ast.Expr
}

func (f *structField) Name() string {
	return f.name
}

func (f *structField) Value() ast.Expr {
	return f.value
}

// Comprehension expression implementation
type comprehensionExpr struct {
	ast.ComprehensionExpr
	iterRange     ast.Expr
	accuInit      ast.Expr
	loopCondition ast.Expr
	loopStep      ast.Expr
	result        ast.Expr
}

func (e *comprehensionExpr) IterRange() ast.Expr {
	return e.iterRange
}

func (e *comprehensionExpr) AccuInit() ast.Expr {
	return e.accuInit
}

func (e *comprehensionExpr) LoopCondition() ast.Expr {
	return e.loopCondition
}

func (e *comprehensionExpr) LoopStep() ast.Expr {
	return e.loopStep
}

func (e *comprehensionExpr) Result() ast.Expr {
	return e.result
}
