// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
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
	secondaryPrompt = "> "
)

type REPL struct {
	vars     variables
	decls    map[string]*exprpb.Decl
	reader   *liner.State
	parser   *participle.Parser
	output   Output
	toRefVal func(interface{}) ref.Val
}

func NewREPL(reader *liner.State, output Output) (*REPL, error) {
	parser, err := NewParser()
	if err != nil {
		return nil, err
	}

	repl := &REPL{
		reader:   reader,
		parser:   parser,
		output:   output,
		toRefVal: conditions.StdEnv.TypeAdapter().NativeToValue,
	}

	return repl, repl.reset()
}

func (r *REPL) Loop() error {
	r.output.Println(banner)
	r.output.Println(fmt.Sprintf("Type %s to get help", colored.REPLCmd(":help")))
	r.output.Println()

	for {
		input := r.readInput()
		if input == "" {
			continue
		}

		r.reader.AppendHistory(input)
		if err := r.handleInput(input); err != nil {
			if errors.Is(err, errExit) {
				return nil
			}

			if !errors.Is(err, errInvalidExpr) {
				r.output.PrintErr("Failed to process input", err)
			}
		}
	}
}

func (r *REPL) readInput() string {
	var input strings.Builder
	currPrompt := prompt

	for {
		line, err := r.reader.Prompt(currPrompt)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, liner.ErrPromptAborted) {
				return ""
			}

			r.output.PrintErr("Failed to read input", err)
			return ""
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return input.String()
		}

		if strings.HasSuffix(line, "\\") {
			input.WriteString(strings.TrimSuffix(line, "\\"))
			input.WriteString(" ")
			currPrompt = secondaryPrompt
		} else {
			input.WriteString(line)
			return input.String()
		}
	}
}

func (r *REPL) handleInput(input string) error {
	switch input[0] {
	case directivePrefix:
		return r.processDirective(input[1:])
	case commentPrefix:
		return nil
	default:
		return r.processExpr(lastResultVar, input)
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
		return r.showVars()
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
	r.output.Println()

	return nil
}

func (r *REPL) help() error {
	r.output.Println(helpText)
	r.output.Println()
	return nil
}

func (r *REPL) showVars() error {
	varNames := make([]string, len(r.vars))
	i := 0
	for name := range r.vars {
		varNames[i] = name
		i++
	}

	sort.Strings(varNames)
	for _, name := range varNames {
		r.output.PrintResult(name, r.vars[name])
	}

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

		requestVal := r.toRefVal(request)
		r.output.PrintResult(name, requestVal)

		r.vars[conditions.CELRequestIdent] = requestVal
		r.vars[conditions.CELPrincipalAbbrev] = r.toRefVal(request.Principal)
		r.vars[conditions.CELResourceAbbrev] = r.toRefVal(request.Resource)

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

		principalVal := r.toRefVal(request.Principal)
		r.output.PrintResult(name, principalVal)

		r.vars[conditions.CELRequestIdent] = r.toRefVal(request)
		r.vars[conditions.CELPrincipalAbbrev] = principalVal
		r.vars[conditions.CELResourceAbbrev] = r.toRefVal(request.Resource)

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

		resourceVal := r.toRefVal(request.Resource)
		r.output.PrintResult(name, resourceVal)

		r.vars[conditions.CELRequestIdent] = r.toRefVal(request)
		r.vars[conditions.CELPrincipalAbbrev] = r.toRefVal(request.Principal)
		r.vars[conditions.CELResourceAbbrev] = resourceVal

	case conditions.CELVariablesIdent, conditions.CELVariablesAbbrev:
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return fmt.Errorf("failed to unmarshal JSON as %q: %w", name, err)
		}

		varsVal := r.toRefVal(v)
		r.output.PrintResult(name, varsVal)

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

	r.output.PrintResult(name, val)
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
			r.output.Print(colored.REPLError(ce.ToDisplayString(src)))
		}
		r.output.Println()

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

// variables is a type that provides the interpreter.Activation interface.
type variables map[string]ref.Val

func (v variables) ResolveName(name string) (interface{}, bool) {
	val, ok := v[name]
	return val, ok
}

func (v variables) Parent() interpreter.Activation {
	return nil
}

type Output interface {
	Print(string, ...interface{})
	Println(...interface{})
	PrintResult(string, ref.Val)
	PrintJSON(interface{})
	PrintErr(string, error)
}

type PrinterOutput struct {
	*printer.Printer
}

func NewPrinterOutput(stdout, stderr io.Writer) *PrinterOutput {
	return &PrinterOutput{
		Printer: printer.New(stdout, stderr),
	}
}

func (po *PrinterOutput) Print(format string, args ...interface{}) {
	po.Printf(format, args...)
	po.Println()
}

func (po *PrinterOutput) PrintResult(name string, value ref.Val) {
	po.Printf("%s = ", colored.REPLVar(name))

	if types.IsPrimitiveType(value) {
		po.PrintJSON(value.Value())
		return
	}

	switch value.Type() {
	case types.MapType:
		if v, err := value.ConvertToNative(mapType); err == nil {
			po.PrintJSON(v)
			return
		}
	case types.ListType:
		if v, err := value.ConvertToNative(listType); err == nil {
			po.PrintJSON(v)
			return
		}
	}

	//nolint: ifshort
	goVal := value.Value()
	if v, ok := goVal.(proto.Message); ok {
		if err := po.PrintProtoJSON(v, false); err != nil {
			po.Println("<...>")
		}
		po.Println()
	} else {
		po.PrintJSON(goVal)
	}
}

func (po *PrinterOutput) PrintJSON(obj interface{}) {
	if err := po.Printer.PrintJSON(obj, false); err != nil {
		po.Println("<...>")
	}
	po.Println()
}

func (po *PrinterOutput) PrintErr(msg string, err error) {
	po.Println(colored.REPLError(fmt.Sprintf("Error: %s", msg)))
	if err != nil {
		po.Printf(" %v\n", err)
	}
	po.Println()
}
