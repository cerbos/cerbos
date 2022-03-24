// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	participle "github.com/alecthomas/participle/v2"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/peterh/liner"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	errExit        = errors.New("exit")
	errInvalidExpr = errors.New("invalid expr")

	listType = reflect.TypeOf([]interface{}{})
	mapType  = reflect.TypeOf(map[string]interface{}{})
)

const (
	commentPrefix   = '#'
	directivePrefix = ':'
	lastResult      = "_"
	prompt          = "-> "

	banner = `
                  __              
  ________  _____/ /_  ____  _____
 / ___/ _ \/ ___/ __ \/ __ \/ ___/
/ /__/  __/ /  / /_/ / /_/ (__  ) 
\___/\___/_/  /_.___/\____/____/  

`
)

type REPL struct {
	vars    variables
	decls   map[string]*exprpb.Decl
	reader  *liner.State
	parser  *participle.Parser
	printer *printer.Printer
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
	r.printer.Println(banner)
	r.printer.Println(fmt.Sprintf("Type %s to get help", colored.REPLCmd(":help")))
	r.printer.Println()

	for {
		line, err := r.reader.Prompt(prompt)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, liner.ErrPromptAborted) {
				continue
			}

			r.printErr("Failed to read input", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		r.reader.AppendHistory(line)

		switch line[0] {
		case directivePrefix:
			if err := r.processDirective(line[1:]); err != nil {
				if errors.Is(err, errExit) {
					return nil
				}

				if !errors.Is(err, errInvalidExpr) {
					r.printErr("Failed to process directive", err)
				}
			}
		case commentPrefix:
			continue
		default:
			if err := r.processExpr(lastResult, line); err != nil && !errors.Is(err, errInvalidExpr) {
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
	case directive.Vars:
		for name, value := range r.vars {
			r.printResult(name, value)
		}
		return nil
	case directive.Help:
		return r.help()
	case directive.Let != nil:
		return r.processExpr(directive.Let.Name, directive.Let.Expr)
	default:
		return fmt.Errorf("unknown directive %q", line)
	}
}

func (r *REPL) reset() error {
	r.vars = variables{lastResult: types.NullValue}
	r.decls = map[string]*exprpb.Decl{lastResult: decls.NewVar(lastResult, decls.Dyn)}

	return nil
}

func (r *REPL) help() error {
	r.printer.Println("HELP")
	r.printer.Println()
	return nil
}

func (r *REPL) processExpr(name, expr string) error {
	val, tpe, err := r.evalExpr(expr)
	if err != nil {
		return err
	}

	r.printResult(name, val)
	r.vars[name] = val
	r.decls[name] = decls.NewVar(name, tpe)

	return nil
}

func (r *REPL) evalExpr(expr string) (ref.Val, *exprpb.Type, error) {
	env, err := r.mkEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create environment: %w", err)
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		src := common.NewTextSource(expr)
		for _, ce := range issues.Errors() {
			r.print(colored.REPLError(ce.ToDisplayString(src)))
		}
		r.printer.Println()

		return nil, nil, errInvalidExpr
	}

	val, _, err := conditions.Eval(env, ast, r.vars)
	if err != nil {
		return nil, nil, err
	}

	tpe := decls.Dyn
	if t, ok := env.TypeProvider().FindType(val.Type().TypeName()); ok {
		tpe = t
	}

	return val, tpe, nil
}

func (r *REPL) mkEnv() (*cel.Env, error) {
	decls := make([]*exprpb.Decl, len(r.decls))
	i := 0
	for _, d := range r.decls {
		decls[i] = d
		i++
	}

	return conditions.StdEnv.Extend(cel.Declarations(decls...))
}

func (r *REPL) print(format string, args ...interface{}) {
	r.printer.Printf(format, args...)
	r.printer.Println()
}

func (r *REPL) printResult(name string, value ref.Val) {
	r.printer.Printf("%s = ", colored.REPLVar(name))

	if types.IsPrimitiveType(value) {
		r.printJSON(value.Value())
		return
	}

	switch value.Type() {
	case types.MapType:
		if v, err := value.ConvertToNative(mapType); err == nil {
			r.printJSON(v)
			return
		}
	case types.ListType:
		if v, err := value.ConvertToNative(listType); err == nil {
			r.printJSON(v)
			return
		}
	}

	r.printer.Printf("%+v\n", value.Value())
	r.printer.Println()
}

func (r *REPL) printJSON(obj interface{}) {
	if err := r.printer.PrintJSON(obj, false); err != nil {
		r.printer.Println("<...>")
	}
	r.printer.Println()
}

func (r *REPL) printErr(msg string, err error) {
	r.printer.Println(colored.REPLError(fmt.Sprintf("Error: %s", msg)))
	if err != nil {
		r.printer.Printf(" %v\n", err)
	}
	r.printer.Println()
}

// variables is a type that provides the interpreter.Activation interface
type variables map[string]ref.Val

func (v variables) ResolveName(name string) (interface{}, bool) {
	val, ok := v[name]
	return val, ok
}

func (v variables) Parent() interpreter.Activation {
	return nil
}
