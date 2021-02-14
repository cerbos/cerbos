package pscript

import (
	"fmt"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
)

type ComparisonOp int

const (
	OpEq ComparisonOp = iota
	OpNeq
	OpGt
	OpLt
	OpGte
	OpLte
)

var operatorMap = map[string]ComparisonOp{
	"==": OpEq,
	"!=": OpNeq,
	">":  OpGt,
	"<":  OpLt,
	">=": OpGte,
	"<=": OpLte,
}

func (op *ComparisonOp) Capture(s []string) error {
	o, ok := operatorMap[strings.ToUpper(s[0])]
	if !ok {
		return fmt.Errorf("unknown operator [%s]", s[0])
	}

	*op = o
	return nil
}

func (op ComparisonOp) String() string {
	switch op {
	case OpEq:
		return "=="
	case OpNeq:
		return "!="
	case OpGt:
		return ">"
	case OpGte:
		return ">="
	case OpLt:
		return "<"
	case OpLte:
		return "<="
	default:
		return fmt.Sprintf("[ERR: unknown comparison op %d]", op)
	}
}

type Bool bool

func (b *Bool) Capture(values []string) error {
	*b = values[0] == "true"
	return nil
}

type Expr struct {
	Reference  string      `@Reference`
	Membership *Membership `("IN" @@`
	Comparison *Comparison `| @@ )`
}

type Comparison struct {
	Op      ComparisonOp `@ComparisonOp`
	Operand Term         `@@`
}

type Membership struct {
	Reference *string   `@Reference`
	Set       []*Scalar `| "{" ( @@ ( "," @@ )* )? "}"`
}

type Term struct {
	Reference *string `@Reference`
	Scalar    *Scalar `| @@`
	Expr      *Expr   `| "(" @@ ")"`
}

type Scalar struct {
	Str    *string  `@String`
	Number *float64 `| @Number `
	Bool   *Bool    `| @Bool`
}

func (s *Scalar) String() string {
	switch {
	case s.Str != nil:
		return fmt.Sprintf("\"%s\"", *s.Str)
	case s.Number != nil:
		return fmt.Sprintf("%f", *s.Number)
	case s.Bool != nil:
		return fmt.Sprintf("%t", *s.Bool)
	default:
		return "[ERR: unknown scalar type]"
	}
}

var (
	pscriptLexer = stateful.MustSimple([]stateful.Rule{
		{"String", `"[^"]*"`, nil},
		{"Number", `\d+(?:\.\d+)?`, nil},
		{"Bool", `(?:true|false)`, nil},
		{"Reference", `\$[a-zA-Z][a-zA-Z0-9_\-]*(?:\.[a-zA-Z0-9_\-]+)*`, nil},
		{"ComparisonOp", `(?:==|!=|\<=|\>=|\<|\>)`, nil},
		{"MembershipOp", "IN", nil},
		{"punctuation", `,`, nil},
		{"brackets", `[{}]`, nil},
		{"whitespace", `\s+`, nil},
	})

	parser = participle.MustBuild(&Expr{},
		participle.Lexer(pscriptLexer),
		participle.Unquote("String"),
		participle.UseLookahead(2),
	)
)

func Parse(exprStr string) (*Expr, error) {
	var expr Expr
	if err := parser.ParseString("", exprStr, &expr); err != nil {
		return nil, fmt.Errorf("failed to parse expression [%s]: %w", exprStr, err)
	}

	return &expr, nil
}
