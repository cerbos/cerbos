// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	_ "embed"

	participle "github.com/alecthomas/participle/v2"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	//go:embed banner.txt
	banner string
	//go:embed help.txt
	helpText string

	errExit        = errors.New("exit")
	errInvalidExpr = errors.New("invalid expr")

	listType = reflect.TypeOf([]interface{}{})
	mapType  = reflect.TypeOf(map[string]interface{}{})
)

const (
	commentPrefix   = '#'
	directivePrefix = ':'
	prompt          = "-> "
)

type REPL struct {
	vars        variables
	decls       map[string]*exprpb.Decl
	reader      *liner.State
	parser      *participle.Parser
	printer     *printer.Printer
	typeAdapter ref.TypeAdapter
}

func NewREPL(reader *liner.State, printer *printer.Printer) (*REPL, error) {
	parser, err := NewParser()
	if err != nil {
		return nil, err
	}

	repl := &REPL{
		reader:      reader,
		parser:      parser,
		printer:     printer,
		typeAdapter: conditions.StdEnv.TypeAdapter(),
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
			if err := r.processExpr(lastResultVar, line); err != nil && !errors.Is(err, errInvalidExpr) {
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
		prefix, _, _ := strings.Cut(directive.Let.Name, ".")
		if _, ok := specialVars[prefix]; ok {
			return r.setSpecialVar(directive.Let.Name, directive.Let.Expr)
		}
		return r.processExpr(directive.Let.Name, directive.Let.Expr)
	default:
		return fmt.Errorf("unknown directive %q", line)
	}
}

func (r *REPL) reset() error {
	r.vars, r.decls = resetVarsAndDecls()

	return nil
}

func (r *REPL) help() error {
	r.printer.Println(helpText)
	r.printer.Println()
	return nil
}

func (r *REPL) setSpecialVar(name, value string) error {
	switch name {
	case lastResultVar:
		return fmt.Errorf("%s is a read-only variable", lastResultVar)

	case conditions.CELRequestIdent:
		request := &enginev1.CheckInput{}
		if err := protojson.Unmarshal([]byte(value), request); err != nil {
			return fmt.Errorf("failed to unmarhsal JSON as %q: %w", name, err)
		}

		requestVal := r.typeAdapter.NativeToValue(request)
		r.printResult(name, requestVal)

		r.vars[conditions.CELRequestIdent] = requestVal
		r.vars[conditions.CELPrincipalAbbrev] = r.typeAdapter.NativeToValue(request.Principal)
		r.vars[conditions.CELResourceAbbrev] = r.typeAdapter.NativeToValue(request.Resource)

	case conditions.CELPrincipalAbbrev, qualifiedPrincipal:
		request, err := getCheckInput(r.vars)
		if err != nil {
			return err
		}

		principal := &enginev1.Principal{}
		if err := protojson.Unmarshal([]byte(value), principal); err != nil {
			return fmt.Errorf("failed to unmarhsal JSON as %q: %w", name, err)
		}

		request.Principal = principal

		principalVal := r.typeAdapter.NativeToValue(request.Principal)
		r.printResult(name, principalVal)

		r.vars[conditions.CELRequestIdent] = r.typeAdapter.NativeToValue(request)
		r.vars[conditions.CELPrincipalAbbrev] = principalVal
		r.vars[conditions.CELResourceAbbrev] = r.typeAdapter.NativeToValue(request.Resource)

	case conditions.CELResourceAbbrev, qualifiedResource:
		request, err := getCheckInput(r.vars)
		if err != nil {
			return err
		}

		resource := &enginev1.Resource{}
		if err := protojson.Unmarshal([]byte(value), resource); err != nil {
			return fmt.Errorf("failed to unmarhsal JSON as %q: %w", name, err)
		}

		request.Resource = resource

		resourceVal := r.typeAdapter.NativeToValue(request.Resource)
		r.printResult(name, resourceVal)

		r.vars[conditions.CELRequestIdent] = r.typeAdapter.NativeToValue(request)
		r.vars[conditions.CELPrincipalAbbrev] = r.typeAdapter.NativeToValue(request.Principal)
		r.vars[conditions.CELResourceAbbrev] = resourceVal

	case conditions.CELVariablesIdent, conditions.CELVariablesAbbrev:
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return fmt.Errorf("failed to unmarshal JSON as %q: %w", name, err)
		}

		varsVal := r.typeAdapter.NativeToValue(v)
		r.printResult(name, varsVal)

		r.vars[conditions.CELVariablesIdent] = varsVal
		r.vars[conditions.CELVariablesAbbrev] = varsVal

	default:
		return fmt.Errorf("setting %q is unsupported", name)
	}

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

	goVal := value.Value()
	if v, ok := goVal.(proto.Message); ok {
		r.printer.PrintProtoJSON(v, false)
	} else {
		r.printJSON(goVal)
	}

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
