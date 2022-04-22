// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/peterh/liner"
	"github.com/pterm/pterm"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

var (
	//go:embed banner.txt
	banner string
	//go:embed help.txt
	helpText string

	errExit        = errors.New("exit")
	errInvalidExpr = errors.New("invalid expr")

	listType = reflect.TypeOf([]any{})
	mapType  = reflect.TypeOf(map[string]any{})

	oppositeChars = map[rune]rune{
		')': '(',
		'}': '{',
		']': '[',
	}
)

const (
	commentPrefix   = '#'
	directivePrefix = ':'
	prompt          = "-> "
	rulePrefix      = "#"
	secondaryPrompt = "> "
	yamlIndent      = 2
)

type policyHolder struct {
	key       string
	variables map[string]string
	rules     []proto.Message
}

type REPL struct {
	output   Output
	vars     variables
	decls    map[string]*exprpb.Decl
	reader   *liner.State
	parser   *participle.Parser
	toRefVal func(any) ref.Val
	policy   *policyHolder
	varV     map[string]any
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

	stack := runeStack{}
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

		isStr := false
		for idx, r := range line {
			switch r {
			case '"':
				if idx-1 >= 0 && line[idx-1] == '\\' {
					continue
				}

				if p, ok := stack.Peek(); ok {
					if p == '"' {
						stack.Pop()
					}
				} else {
					stack.Push(r)
				}

				isStr = !isStr
			case '(', '{', '[':
				if isStr {
					continue
				}
				stack.Push(r)
			case ')', '}', ']':
				if isStr {
					continue
				}
				if p, ok := stack.Peek(); ok {
					if oppositeChars[r] == p {
						stack.Pop()
					}
				}
			}
		}

		if !stack.IsEmpty() {
			input.WriteString(line)
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
	case directive.Rules:
		return r.showRules()
	case directive.Let != nil:
		prefix, _, _ := strings.Cut(directive.Let.Name, ".")
		if _, ok := specialVars[prefix]; ok {
			return r.setSpecialVar(directive.Let.Name, directive.Let.Expr)
		}
		return r.processExpr(directive.Let.Name, directive.Let.Expr)
	case directive.Load != nil:
		return r.loadRulesFromPolicy(directive.Load.Path)
	case directive.Exec != nil:
		return r.execRule(directive.Exec.RuleID)
	default:
		return fmt.Errorf("unknown directive %q", line)
	}
}

func (r *REPL) reset() error {
	r.vars, r.decls = resetVarsAndDecls()
	r.policy = nil
	r.varV = nil
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

func (r *REPL) showRules() error {
	if r.policy == nil {
		r.output.Println()
		return nil
	}

	r.output.Print(fmt.Sprintf("Conditional rules in '%s'\n", colored.REPLPolicyName(r.policy.key)))
	for idx, rule := range r.policy.rules {
		if err := r.output.PrintRule(idx, rule); err != nil {
			return err
		}
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

		r.evalPolicyVariables()

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

		r.evalPolicyVariables()

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

		r.evalPolicyVariables()

	case conditions.CELVariablesIdent, conditions.CELVariablesAbbrev:
		var v map[string]any
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return fmt.Errorf("failed to unmarshal JSON as %q: %w", name, err)
		}

		r.addToVarV(v)
		r.evalPolicyVariables()
		r.output.PrintResult(name, r.vars[conditions.CELVariablesIdent])

	default:
		return fmt.Errorf("setting %q is unsupported", name)
	}

	return nil
}

func (r *REPL) addToVarV(v map[string]any) {
	if r.varV == nil {
		r.varV = make(map[string]any, len(v))
	}

	for name, val := range v {
		r.varV[name] = val
	}

	varsVal := r.toRefVal(r.varV)
	r.vars[conditions.CELVariablesIdent] = varsVal
	r.vars[conditions.CELVariablesAbbrev] = varsVal
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

func (r *REPL) loadRulesFromPolicy(path string) error {
	f, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return fmt.Errorf("failed to open policy file at %s: %w", path, err)
	}
	defer f.Close()

	p, err := policy.ReadPolicy(f)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	ph := &policyHolder{key: namer.PolicyKey(p), variables: p.Variables}
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition != nil && rule.Condition.Condition != nil {
				ph.rules = append(ph.rules, rule)
			}
		}
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition != nil {
				ph.rules = append(ph.rules, def)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition != nil {
					pr := &policyv1.PrincipalRule{
						Resource: rule.Resource,
						Actions: []*policyv1.PrincipalRule_Action{
							action,
						},
					}
					ph.rules = append(ph.rules, pr)
				}
			}
		}
	}

	r.policy = ph
	r.evalPolicyVariables()

	r.output.Println(fmt.Sprintf("Loaded %s", colored.REPLPolicyName(ph.key)))
	r.output.Println()

	if len(ph.variables) > 0 {
		r.output.Println("Policy variables:")
		r.output.PrintJSON(ph.variables)
	}

	return r.showRules()
}

func (r *REPL) evalPolicyVariables() {
	if r.policy == nil || len(r.policy.variables) == 0 {
		return
	}

	result := make(map[string]any, len(r.policy.variables))
	for name, expr := range r.policy.variables {
		v, _, err := r.evalExpr(expr)
		if err != nil {
			result[name] = types.NewErr("failed to evaluate '%s = %s': %v", name, expr, err)
		} else {
			result[name] = v
		}
	}

	r.addToVarV(result)
}

func (r *REPL) execRule(id int) error {
	if r.policy == nil || id >= len(r.policy.rules) {
		return fmt.Errorf("failed to find rule %d", id)
	}

	return r.evalCondition(id)
}

func (r *REPL) evalCondition(id int) error {
	var cond *policyv1.Condition
	switch rt := r.policy.rules[id].(type) {
	case *policyv1.ResourceRule:
		cond = rt.Condition
	case *policyv1.RoleDef:
		cond = rt.Condition
	case *policyv1.PrincipalRule:
		cond = rt.Actions[0].Condition
	}

	condition, err := compile.Condition(cond)
	if err != nil {
		return fmt.Errorf("failed to compile condition: %w", err)
	}

	e := r.doEvalCondition(condition)
	eo := buildEvalOutput(e)

	return pterm.DefaultTree.WithRoot(pterm.NewTreeFromLeveledList(eo.tree)).Render()
}

func (r *REPL) doEvalCondition(condition *runtimev1.Condition) *eval {
	switch c := condition.Op.(type) {
	case *runtimev1.Condition_Expr:
		val, tpe, err := r.evalExpr(c.Expr.Original)
		if err != nil {
			return &eval{err: err, success: false, evalType: evalTypeExpr, evals: nil, expr: c.Expr.Original}
		}

		r.vars[lastResultVar] = val
		r.decls[lastResultVar] = decls.NewVar(lastResultVar, tpe)

		if success, ok := val.Value().(bool); ok {
			return &eval{err: nil, success: success, evalType: evalTypeExpr, evals: nil, expr: c.Expr.Original}
		}

		return &eval{err: err, success: false, evalType: evalTypeExpr, evals: nil, expr: c.Expr.Original}
	case *runtimev1.Condition_All:
		eval := &eval{err: nil, success: true, evalType: evalTypeAll, evals: nil}
		for _, expr := range c.All.GetExpr() {
			e := r.doEvalCondition(expr)
			eval.append(e)
		}
		return eval
	case *runtimev1.Condition_Any:
		eval := &eval{err: nil, success: true, evalType: evalTypeAny, evals: nil}
		for _, expr := range c.Any.GetExpr() {
			e := r.doEvalCondition(expr)
			eval.append(e)
		}
		return eval
	case *runtimev1.Condition_None:
		eval := &eval{err: nil, success: true, evalType: evalTypeNone, evals: nil}
		for _, expr := range c.None.GetExpr() {
			e := r.doEvalCondition(expr)
			eval.append(e)
		}
		return eval
	}

	return nil
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

func (v variables) ResolveName(name string) (any, bool) {
	val, ok := v[name]
	return val, ok
}

func (v variables) Parent() interpreter.Activation {
	return nil
}

type Output interface {
	Print(string, ...any)
	Println(...any)
	PrintResult(string, ref.Val)
	PrintRule(int, proto.Message) error
	PrintJSON(any)
	PrintYAML(proto.Message, int)
	PrintErr(string, error)
}

type PrinterOutput struct {
	*printer.Printer
	level outputcolor.Level
}

func NewPrinterOutput(stdout, stderr io.Writer) *PrinterOutput {
	return &PrinterOutput{
		Printer: printer.New(stdout, stderr),
		level:   outputcolor.DefaultLevel(),
	}
}

func (po *PrinterOutput) Print(format string, args ...any) {
	po.Printf(format, args...)
	po.Println()
}

func (po *PrinterOutput) PrintRule(id int, rule proto.Message) error {
	po.Println(fmt.Sprintf("[%s]", colored.REPLRule(fmt.Sprintf("%s%d", rulePrefix, id))))
	po.PrintYAML(rule, yamlIndent)

	return nil
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
		if err := po.PrintProtoJSON(v, po.level); err != nil {
			po.Println("<...>")
		}
		po.Println()
	} else {
		po.PrintJSON(goVal)
	}
}

func (po *PrinterOutput) PrintJSON(obj any) {
	if err := po.Printer.PrintJSON(obj, po.level); err != nil {
		po.Println("<...>")
	}
	po.Println()
}

func (po *PrinterOutput) PrintYAML(obj proto.Message, indent int) {
	if err := po.PrintProtoYAML(obj, po.level, indent); err != nil {
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
