// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"strconv"
	"strings"

	participle "github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"google.golang.org/protobuf/types/known/structpb"
)

func NewParser() (*participle.Parser, error) {
	lex, err := lexer.New(lexer.Rules{
		"Root": {
			{Name: "Number", Pattern: `\d+(\.\d+)*`},
			{Name: "Boolean", Pattern: `(true|false)`},
			{Name: "String", Pattern: `"[^"]*"`},
			{Name: "Ident", Pattern: `[a-zA-Z]\w*`},
			{Name: "Operator", Pattern: `=`},
			{Name: "Sep", Pattern: `[,:]`},
			{Name: "Whitespace", Pattern: `\s+`},
			{Name: "ListStart", Pattern: `\[`, Action: lexer.Push("List")},
			{Name: "ObjectStart", Pattern: `\{`, Action: lexer.Push("Object")},
			{Name: "ExprStart", Pattern: `\$\(`, Action: lexer.Push("Expr")},
		},
		"List": {
			lexer.Include("Root"),
			{Name: "ListEnd", Pattern: `\]`, Action: lexer.Pop()},
		},
		"Object": {
			lexer.Include("Root"),
			{Name: "ObjectEnd", Pattern: `\}`, Action: lexer.Pop()},
		},
		"Expr": {
			{Name: "AnyExceptParen", Pattern: `[^()]+`},
			{Name: "LParen", Pattern: `\(`, Action: lexer.Push("Expr")},
			{Name: "RParen", Pattern: `\)`, Action: lexer.Pop()},
		},
		"InsideParen": {
			lexer.Include("Expr"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create lexer: %w", err)
	}

	parser, err := participle.Build(&REPLDirective{},
		participle.Lexer(lex),
		participle.Elide("Whitespace"),
		participle.Unquote(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	return parser, nil
}

//nolint:govet
type REPLDirective struct {
	Exit  bool          `parser:"@('q'|'quit'|'exit')"`
	Reset bool          `parser:"| @'reset'"`
	Vars  bool          `parser:"| @'vars'"`
	Help  bool          `parser:"| @('h' | 'help')"`
	Let   *LetDirective `parser:"| @@"`
}

//nolint:govet
type LetDirective struct {
	Name  string `parser:"'let' @Ident"`
	Value *Value `parser:"'=' @@"`
}

type Value struct {
	Bool       *Boolean    `parser:"@Boolean"`
	Number     *float64    `parser:"| @Number"`
	String     *string     `parser:"| @String"`
	Collection *Collection `parser:"| @@"`
	Expr       *Expr       `parser:"| '$(' @@ ')'"`
}

type Boolean bool

func (b *Boolean) Capture(values []string) error {
	v, err := strconv.ParseBool(values[0])
	if err != nil {
		return err
	}

	*b = Boolean(v)
	return nil
}

//nolint:govet
type Collection struct {
	List      bool        `parser:"@'['"`
	ListItems []*Value    `parser:"( @@ (',' @@)* )* ']'"`
	Map       bool        `parser:"| @'{'"`
	MapItems  []*KeyValue `parser:"( @@ (',' @@)* )* '}'"`
}

//nolint:govet
type KeyValue struct {
	Key   string `parser:"@String"`
	Value *Value `parser:"':' @@"`
}

func (v *Value) ToProto() *structpb.Value {
	switch {
	case v == nil:
		return structpb.NewNullValue()
	case v.Bool != nil:
		return structpb.NewBoolValue(bool(*v.Bool))
	case v.Number != nil:
		return structpb.NewNumberValue(*v.Number)
	case v.String != nil:
		return structpb.NewStringValue(*v.String)
	case v.Collection != nil && v.Collection.List:
		list := make([]*structpb.Value, len(v.Collection.ListItems))
		for i, item := range v.Collection.ListItems {
			list[i] = item.ToProto()
		}
		return structpb.NewListValue(&structpb.ListValue{Values: list})
	case v.Collection != nil && v.Collection.Map:
		fields := make(map[string]*structpb.Value, len(v.Collection.MapItems))
		for _, f := range v.Collection.MapItems {
			fields[f.Key] = f.Value.ToProto()
		}
		return structpb.NewStructValue(&structpb.Struct{Fields: fields})
	}

	return structpb.NewNullValue()
}

type Expr string

func (e *Expr) Parse(lex *lexer.PeekingLexer) error {
	var eb strings.Builder
	var tok lexer.Token

	parenCount := 1

loop:
	for parenCount > 0 {
		var err error
		tok, err = lex.Peek(0)
		if err != nil {
			return err
		}

		if tok.EOF() {
			break loop
		}

		switch tok.Value {
		case "(":
			parenCount++
		case ")":
			parenCount--

			if parenCount == 0 {
				break loop
			}
		}
		eb.WriteString(tok.Value)

		if _, err := lex.Next(); err != nil {
			return err
		}
	}

	if parenCount > 0 {
		return participle.Errorf(tok.Pos, "invalid expression")
	}

	*e = Expr(strings.TrimSpace(eb.String()))
	return nil
}
