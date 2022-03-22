// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	participle "github.com/alecthomas/participle/v2"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types/ref"
	"github.com/peterh/liner"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	errExit        = errors.New("exit")
	errInvalidExpr = errors.New("invalid expr")
)

const (
	commentPrefix   = '#'
	directivePrefix = ':'
	lastResult      = "_"
	prompt          = "-> "
)

type REPL struct {
	variables map[string]interface{}
	reader    *liner.State
	env       *cel.Env
	parser    *participle.Parser
	printer   *printer.Printer
}

func NewREPL(reader *liner.State, printer *printer.Printer) (*REPL, error) {
	parser, err := NewParser()
	if err != nil {
		return nil, err
	}

	repl := &REPL{
		reader:  reader,
		parser:  parser,
		printer: printer,
	}

	return repl, repl.reset()
}

func (r *REPL) Loop() error {
	for {
		line, err := r.reader.Prompt(prompt)
		if err != nil && !errors.Is(err, io.EOF) {
			r.printErr("Failed to read input", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch line[0] {
		case directivePrefix:
			if err := r.processDirective(line[1:]); err != nil {
				if errors.Is(err, errExit) {
					return nil
				}

				r.printErr("Failed to parse directive", err)
			}
		case commentPrefix:
			continue
		default:
			if err := r.processExpr(line); err != nil {
				r.printErr("Failed to evaluate expression", err)
			}
		}
	}
}

func (r *REPL) processDirective(line string) error {
	var directive REPLDirective
	if err := r.parser.ParseString("", line, &directive); err != nil {
		return fmt.Errorf("invalid directive %q: %w", line, err)
	}

	switch {
	case directive.Exit:
		return errExit
	case directive.Reset:
		return r.reset()
	case directive.Let != nil:
		return r.let(directive.Let.Name, directive.Let.Value)
	default:
		return fmt.Errorf("unknown directive %q", line)
	}
}

func (r *REPL) let(name string, v *Value) error {
	var value interface{}
	var tpe *exprpb.Type

	switch {
	case v == nil:
		tpe = decls.Null

	case v.Expr != nil:
		val, err := r.evalExpr(string(*v.Expr))
		if err != nil {
			return fmt.Errorf("failed to evaluate expression: %w", err)
		}

		value = val.Value()
		tpe = decls.Dyn

	case v.Bool != nil:
		value = bool(*v.Bool)
		tpe = decls.Bool

	case v.Number != nil:
		if math.Trunc(*v.Number) == *v.Number {
			tpe = decls.Int
			value = int64(*v.Number)
		} else {
			tpe = decls.Double
			value = *v.Number
		}

	case v.String != nil:
		tpe = decls.String
		value = *v.String

	case v.Collection != nil && v.Collection.List:
		tpe = decls.NewObjectType("google.protobuf.ListValue")

		list := make([]*structpb.Value, len(v.Collection.ListItems))
		for i, item := range v.Collection.ListItems {
			list[i] = item.ToProto()
		}
		value = structpb.NewListValue(&structpb.ListValue{Values: list})

	case v.Collection != nil && v.Collection.Map:
		tpe = decls.NewObjectType("google.protobuf.Struct")

		fields := make(map[string]*structpb.Value, len(v.Collection.MapItems))
		for _, f := range v.Collection.MapItems {
			fields[f.Key] = f.Value.ToProto()
		}
		value = structpb.NewStructValue(&structpb.Struct{Fields: fields})
	}

	env, err := r.env.Extend(cel.Declarations(decls.NewVar(name, tpe)))
	if err != nil {
		return fmt.Errorf("failed to add variable to environment: %w", err)
	}

	r.env = env
	r.variables[name] = value

	r.printJSON(map[string]interface{}{name: value})

	return nil
}

func (r *REPL) reset() error {
	env, err := conditions.StdEnv.Extend(cel.Declarations(decls.NewVar(lastResult, decls.Dyn)))
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	r.env = env
	r.variables = map[string]interface{}{lastResult: nil}

	return nil
}

func (r *REPL) processExpr(line string) error {
	val, err := r.evalExpr(line)
	if err != nil {
		return err
	}

	r.printJSON(map[string]interface{}{lastResult: val})

	r.variables[lastResult] = val.Value()

	return nil
}

func (r *REPL) evalExpr(expr string) (ref.Val, error) {
	ast, err := r.compileExpr(expr)
	if err != nil {
		return nil, err
	}

	val, _, err := conditions.Eval(r.env, ast, r.variables)
	if err != nil {
		return nil, err
	}

	return val, nil
}

func (r *REPL) compileExpr(expr string) (*cel.Ast, error) {
	celAST, issues := r.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		src := common.NewTextSource(expr)
		for _, ce := range issues.Errors() {
			r.print(colored.ErrorMsg(ce.ToDisplayString(src)))
		}
		return nil, errInvalidExpr
	}

	return celAST, nil
}

func (r *REPL) print(format string, args ...interface{}) {
	r.printer.Printf(format, args...)
	r.printer.Println()
}

func (r *REPL) printJSON(obj interface{}) {
	r.printer.PrintJSON(obj, false)
	r.printer.Println()
}

func (r *REPL) printErr(msg string, err error) {
	r.printer.Println(colored.ErrorMsg(fmt.Sprintf("Error: %s", msg)))
	if err != nil {
		r.printer.Printf(" %v\n", err)
	}
	r.printer.Println()
}
