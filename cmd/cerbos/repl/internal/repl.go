// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/alecthomas/participle/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/peterh/liner"
	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

var (
	//go:embed banner.txt
	banner string
	//go:embed help.txt
	helpText string

	errExit   = errors.New("exit")
	errSilent = errors.New("") // returned when an error has occurred but feedback has already been provided to the user

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
	output       Output
	vars         variables
	decls        map[string]*decls.VariableDecl
	reader       *liner.State
	parser       *participle.Parser[REPLDirective]
	toRefVal     func(any) ref.Val
	policy       *policyHolder
	varC         map[string]any
	varV         map[string]any
	constExports map[string]map[string]*structpb.Value
	varExports   map[string]map[string]string
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
		toRefVal: conditions.StdEnv.CELTypeAdapter().NativeToValue,
	}

	return repl, repl.reset()
}

func (r *REPL) Loop(ctx context.Context) error {
	r.output.Println(banner)
	r.output.Println(fmt.Sprintf("Type %s to get help", colored.REPLCmd(":help")))
	r.output.Println()

	for {
		input, err := r.readInput()
		if err != nil {
			if errors.Is(err, errExit) {
				return nil
			}

			r.output.PrintErr("Failed to read input", err)
			continue
		}

		if input == "" {
			continue
		}

		r.reader.AppendHistory(input)
		if err := r.handleInput(ctx, input); err != nil {
			if errors.Is(err, errExit) {
				return nil
			}

			if !errors.Is(err, errSilent) {
				r.output.PrintErr("Failed to process input", err)
			}
		}
	}
}

func (r *REPL) readInput() (string, error) {
	var input strings.Builder
	currPrompt := prompt

	stack := &runeStack{}
	for {
		line, err := r.reader.Prompt(currPrompt)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if stack.IsEmpty() {
					return "", errExit
				}

				r.output.Println()
				return "", nil
			}

			if errors.Is(err, liner.ErrPromptAborted) {
				return "", nil
			}

			return "", err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return input.String(), nil
		}

		l, terminated := isTerminated(line, stack)
		if !terminated {
			input.WriteString(l)
			input.WriteString(" ")
			currPrompt = secondaryPrompt
		} else {
			input.WriteString(l)
			return input.String(), nil
		}
	}
}

func (r *REPL) handleInput(ctx context.Context, input string) error {
	switch input[0] {
	case directivePrefix:
		return r.processDirective(ctx, input[1:])
	case commentPrefix:
		return nil
	default:
		return r.processExpr(ctx, lastResultVar, input)
	}
}

func (r *REPL) processDirective(ctx context.Context, line string) error {
	directive, err := r.parser.ParseString("", line)
	if err != nil {
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
			return r.setSpecialVar(ctx, directive.Let.Name, directive.Let.Expr)
		}
		return r.processExpr(ctx, directive.Let.Name, directive.Let.Expr)
	case directive.Load != nil:
		return r.loadPolicy(ctx, directive.Load.Path)
	case directive.Exec != nil:
		return r.execRule(ctx, directive.Exec.RuleID)
	default:
		return fmt.Errorf("unknown directive %q", line)
	}
}

func (r *REPL) reset() error {
	r.vars, r.decls = resetVarsAndDecls()
	r.policy = nil
	r.varV = nil
	r.constExports = make(map[string]map[string]*structpb.Value)
	r.varExports = make(map[string]map[string]string)
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

func (r *REPL) setSpecialVar(ctx context.Context, name, value string) error {
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

		r.evalPolicyVariables(ctx)

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

		r.evalPolicyVariables(ctx)

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

		r.evalPolicyVariables(ctx)

	case conditions.CELConstantsIdent, conditions.CELConstantsAbbrev:
		var c map[string]any
		if err := json.Unmarshal([]byte(value), &c); err != nil {
			return fmt.Errorf("failed to unmarshal JSON as %q: %w", name, err)
		}

		r.addToVarC(c)
		r.evalPolicyVariables(ctx)
		r.output.PrintResult(name, r.vars[conditions.CELConstantsIdent])

	case conditions.CELVariablesIdent, conditions.CELVariablesAbbrev:
		var v map[string]any
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return fmt.Errorf("failed to unmarshal JSON as %q: %w", name, err)
		}

		r.addToVarV(v)
		r.evalPolicyVariables(ctx)
		r.output.PrintResult(name, r.vars[conditions.CELVariablesIdent])

	case conditions.CELGlobalsIdent, conditions.CELGlobalsAbbrev:
		var globals map[string]any
		if err := json.Unmarshal([]byte(value), &globals); err != nil {
			return fmt.Errorf("failed to unmarshal JSON as %q: %w", name, err)
		}

		globalsVal := r.toRefVal(globals)
		r.vars[conditions.CELGlobalsIdent] = globalsVal
		r.vars[conditions.CELGlobalsAbbrev] = globalsVal
		r.evalPolicyVariables(ctx)
		r.output.PrintResult(name, r.vars[conditions.CELGlobalsIdent])

	default:
		return fmt.Errorf("setting %q is unsupported", name)
	}

	return nil
}

func (r *REPL) addToVarC(c map[string]any) {
	if r.varC == nil {
		r.varC = make(map[string]any, len(c))
	}

	for name, val := range c {
		r.varC[name] = val
	}

	varsVal := r.toRefVal(r.varC)
	r.vars[conditions.CELConstantsIdent] = varsVal
	r.vars[conditions.CELConstantsAbbrev] = varsVal
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

func (r *REPL) processExpr(ctx context.Context, name, expr string) error {
	val, tpe, err := r.evalExpr(ctx, expr)
	if err != nil {
		return err
	}

	r.output.PrintResult(name, val)
	r.vars[name] = val
	r.decls[name] = decls.NewVariable(name, tpe)

	return nil
}

func (r *REPL) evalExpr(ctx context.Context, expr string) (ref.Val, *types.Type, error) {
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

		return nil, nil, errSilent
	}

	val, _, err := conditions.ContextEval(ctx, env, ast, r.vars, conditions.Now())
	if err != nil {
		return nil, nil, err
	}

	tpe := types.DynType
	if t, ok := env.CELTypeProvider().FindStructType(val.Type().TypeName()); ok {
		tpe = t
	}

	return val, tpe, nil
}

func (r *REPL) loadPolicy(ctx context.Context, path string) error {
	f, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return fmt.Errorf("failed to open policy file at %s: %w", path, err)
	}
	defer f.Close()

	p, _, err := policy.ReadPolicyWithSourceContextFromReader(f)
	if err != nil {
		r.printLoadError(err)
		return fmt.Errorf("failed to read policy file %s", path)
	}

	ph := &policyHolder{key: namer.PolicyKey(p)}
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ExportConstants:
		r.constExports[pt.ExportConstants.Name] = pt.ExportConstants.Definitions
	case *policyv1.Policy_ExportVariables:
		r.varExports[pt.ExportVariables.Name] = pt.ExportVariables.Definitions
	case *policyv1.Policy_ResourcePolicy:
		err := r.mergeConstantDefinitions(ph.key, pt.ResourcePolicy.Constants)
		if err != nil {
			return err
		}

		ph.variables, err = r.mergeVariableDefinitions(ph.key, pt.ResourcePolicy.Variables, p.Variables) //nolint:staticcheck
		if err != nil {
			return err
		}

		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition != nil && rule.Condition.Condition != nil {
				ph.rules = append(ph.rules, rule)
			}
		}
	case *policyv1.Policy_DerivedRoles:
		err := r.mergeConstantDefinitions(ph.key, pt.DerivedRoles.Constants)
		if err != nil {
			return err
		}

		ph.variables, err = r.mergeVariableDefinitions(ph.key, pt.DerivedRoles.Variables, p.Variables) //nolint:staticcheck
		if err != nil {
			return err
		}

		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition != nil {
				ph.rules = append(ph.rules, def)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		err := r.mergeConstantDefinitions(ph.key, pt.PrincipalPolicy.Constants)
		if err != nil {
			return err
		}

		ph.variables, err = r.mergeVariableDefinitions(ph.key, pt.PrincipalPolicy.Variables, p.Variables) //nolint:staticcheck
		if err != nil {
			return err
		}

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
	r.evalPolicyVariables(ctx)

	r.output.Println(fmt.Sprintf("Loaded %s", colored.REPLPolicyName(ph.key)))
	r.output.Println()

	if len(ph.variables) > 0 {
		r.output.Println("Policy variables:")
		r.output.PrintJSON(ph.variables)
	}

	if len(ph.rules) > 0 {
		return r.showRules()
	}

	return nil
}

func (r *REPL) printLoadError(err error) {
	u, ok := err.(interface{ Unwrap() []error }) //nolint:errorlint
	if ok {
		unwrapped := u.Unwrap()
		for _, ue := range unwrapped {
			r.printLoadError(ue)
		}

		return
	}

	var unmarshalErr parser.UnmarshalError
	if errors.As(err, &unmarshalErr) {
		r.output.Println(colored.REPLError(fmt.Sprintf("%+v", unmarshalErr)))
	} else {
		r.output.PrintErr("Error:", err)
	}
}

func (r *REPL) mergeConstantDefinitions(policyKey string, policyConstants *policyv1.Constants) error {
	merged := make(map[string]any)
	sources := make(map[string][]string)
	missingImports := make([]string, 0, len(policyConstants.GetImport()))

	for _, name := range policyConstants.GetImport() {
		imported, ok := r.constExports[name]
		if !ok {
			missingImports = append(missingImports, name)
			continue
		}

		mergeConstantDefinitions(merged, sources, imported, fmt.Sprintf("import %q", name))
	}

	if len(missingImports) > 0 {
		var plural string
		if len(missingImports) > 1 {
			plural = "s"
		}

		r.output.PrintErr(fmt.Sprintf("Missing constants import%s", plural), nil)
		r.output.Print("%s imports the following constant definitions:", policyKey)

		for _, name := range missingImports {
			r.output.Print("  - %s", colored.REPLPolicyName(name))
		}

		r.output.Println()
		r.output.Print("Load the file%s containing the constant definitions, then try again", plural)
		r.output.Println()

		return errSilent
	}

	mergeConstantDefinitions(merged, sources, policyConstants.GetLocal(), "policy local constants")

	for name, definedIn := range sources {
		if len(definedIn) == 1 {
			delete(sources, name)
		}
	}

	if len(sources) > 0 {
		var plural string
		if len(sources) > 1 {
			plural = "s"
		}

		r.output.PrintErr(fmt.Sprintf("Duplicate constant definition%s", plural), nil)
		for name, definedIn := range sources {
			r.output.Print("- %s is defined in %s", colored.REPLVar(name), strings.Join(definedIn, " and "))
		}
	}

	r.addToVarC(merged)

	return nil
}

func mergeConstantDefinitions(merged map[string]any, sources map[string][]string, values map[string]*structpb.Value, source string) {
	for name, value := range values {
		merged[name] = value.AsInterface()
		sources[name] = append(sources[name], source)
	}
}

func (r *REPL) mergeVariableDefinitions(policyKey string, policyVariables *policyv1.Variables, deprecatedTopLevel map[string]string) (map[string]string, error) {
	merged := make(map[string]string)
	sources := make(map[string][]string)
	missingImports := make([]string, 0, len(policyVariables.GetImport()))

	for _, name := range policyVariables.GetImport() {
		imported, ok := r.varExports[name]
		if !ok {
			missingImports = append(missingImports, name)
			continue
		}

		mergeVariableDefinitions(merged, sources, imported, fmt.Sprintf("import %q", name))
	}

	if len(missingImports) > 0 {
		var plural string
		if len(missingImports) > 1 {
			plural = "s"
		}

		r.output.PrintErr(fmt.Sprintf("Missing variables import%s", plural), nil)
		r.output.Print("%s imports the following variable definitions:", policyKey)

		for _, name := range missingImports {
			r.output.Print("  - %s", colored.REPLPolicyName(name))
		}

		r.output.Println()
		r.output.Print("Load the file%s containing the variable definitions, then try again", plural)
		r.output.Println()

		return nil, errSilent
	}

	mergeVariableDefinitions(merged, sources, policyVariables.GetLocal(), "policy local variables")
	mergeVariableDefinitions(merged, sources, deprecatedTopLevel, "top-level policy variables (deprecated)")

	for name, definedIn := range sources {
		if len(definedIn) == 1 {
			delete(sources, name)
		}
	}

	if len(sources) > 0 {
		var plural string
		if len(sources) > 1 {
			plural = "s"
		}

		r.output.PrintErr(fmt.Sprintf("Duplicate variable definition%s", plural), nil)
		for name, definedIn := range sources {
			r.output.Print("- %s is defined in %s", colored.REPLVar(name), strings.Join(definedIn, " and "))
		}
	}

	return merged, nil
}

func mergeVariableDefinitions(merged map[string]string, sources map[string][]string, values map[string]string, source string) {
	for name, expr := range values {
		merged[name] = expr
		sources[name] = append(sources[name], source)
	}
}

func (r *REPL) evalPolicyVariables(ctx context.Context) {
	if r.policy == nil || len(r.policy.variables) == 0 {
		return
	}

	result := make(map[string]any, len(r.policy.variables))
	for name, expr := range r.policy.variables {
		v, _, err := r.evalExpr(ctx, expr)
		if err != nil {
			result[name] = types.NewErr("failed to evaluate '%s = %s': %v", name, expr, err)
		} else {
			result[name] = v
		}
	}

	r.addToVarV(result)
}

func (r *REPL) execRule(ctx context.Context, id int) error {
	if r.policy == nil || id >= len(r.policy.rules) {
		return fmt.Errorf("failed to find rule %d", id)
	}

	return r.evalCondition(ctx, id)
}

func (r *REPL) evalCondition(ctx context.Context, id int) error {
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

	e := r.doEvalCondition(ctx, condition)
	eo := buildEvalOutput(e)

	return pterm.DefaultTree.WithRoot(putils.TreeFromLeveledList(eo.tree)).Render()
}

func (r *REPL) doEvalCondition(ctx context.Context, condition *runtimev1.Condition) *eval {
	switch c := condition.Op.(type) {
	case *runtimev1.Condition_Expr:
		val, tpe, err := r.evalExpr(ctx, c.Expr.Original)
		if err != nil {
			return &eval{err: err, success: false, evalType: evalTypeExpr, evals: nil, expr: c.Expr.Original}
		}

		r.vars[lastResultVar] = val
		r.decls[lastResultVar] = decls.NewVariable(lastResultVar, tpe)

		if success, ok := val.Value().(bool); ok {
			return &eval{err: nil, success: success, evalType: evalTypeExpr, evals: nil, expr: c.Expr.Original}
		}

		return &eval{err: err, success: false, evalType: evalTypeExpr, evals: nil, expr: c.Expr.Original}
	case *runtimev1.Condition_All:
		eval := &eval{err: nil, success: true, evalType: evalTypeAll, evals: nil}
		for _, expr := range c.All.GetExpr() {
			e := r.doEvalCondition(ctx, expr)
			eval.append(e)
		}
		return eval
	case *runtimev1.Condition_Any:
		eval := &eval{err: nil, success: true, evalType: evalTypeAny, evals: nil}
		for _, expr := range c.Any.GetExpr() {
			e := r.doEvalCondition(ctx, expr)
			eval.append(e)
		}
		return eval
	case *runtimev1.Condition_None:
		eval := &eval{err: nil, success: true, evalType: evalTypeNone, evals: nil}
		for _, expr := range c.None.GetExpr() {
			e := r.doEvalCondition(ctx, expr)
			eval.append(e)
		}
		return eval
	}

	return nil
}

func (r *REPL) mkEnv() (*cel.Env, error) {
	decls := make([]*decls.VariableDecl, len(r.decls))
	i := 0
	for _, d := range r.decls {
		decls[i] = d
		i++
	}

	return conditions.StdEnv.Extend(cel.VariableDecls(decls...))
}

func (r *REPL) Complete(line string) []string {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		parts = []string{""}
	}

	chars := []rune(line)

	if len(chars) != 0 && unicode.IsSpace(chars[len(chars)-1]) {
		parts = append(parts, "")
	}

	lastTokIndx := len(parts) - 1
	lastTok := parts[lastTokIndx]

	if lastTokIndx == 0 {
		return r.completeCmd(lastTok)
	}

	var compls []string
	// This isn't ideal, but the directives are baked into tags
	// making this trickier to implement neatly
	switch parts[0] {
	case ":load":
		compls = r.completeFile(lastTok)
	case ":let":
		compls = r.completeVar(lastTok)
	case ":exec":
		compls = r.completeRule(lastTok)
	}

	res := make([]string, len(compls))
	for i, c := range compls {
		parts[lastTokIndx] = c
		res[i] = strings.Join(parts, " ")
	}

	return res
}

var directives = []string{
	":help",
	":let",
	":load",
	":vars",
	":rules",
	":exec",
	":reset",
	":quit",
}

func (r *REPL) completeCmd(prefix string) (c []string) {
	var matches []string

	for _, d := range directives {
		if strings.HasPrefix(d, prefix) {
			matches = append(matches, d)
		}
	}

	return matches
}

var (
	skippableDirs  = regexp.MustCompile(`^(_schemas|testdata|derived_roles)$`)
	skippableFiles = regexp.MustCompile(`(^\.)|(_test\.(yaml|yml|json)$)`)
	matchingFiles  = regexp.MustCompile(`\.(yaml|yml|json)$`)
)

func (r *REPL) completeFile(prefix string) (c []string) {
	path := filepath.Dir(prefix)
	if path == "" {
		path = "."
	}

	// This is subtle, but the first path may be a complete directory the user explicitly
	// passed, so should not be skipped. This is also needed for the tests to pass (since
	// we skip testdata
	top := true

	var matches []string

	// TODO(tcm): this should probably limit the depth of the search
	_ = filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if top {
			defer func() { top = false }()
		}

		if err != nil {
			return err
		}
		dn := d.Name()
		if !top && d.IsDir() && skippableDirs.MatchString(dn) {
			return fs.SkipDir
		}
		if d.IsDir() {
			return nil
		}

		if strings.HasPrefix(path, prefix) && !skippableFiles.MatchString(dn) && matchingFiles.MatchString(dn) {
			matches = append(matches, path)
		}
		return nil
	})
	return matches
}

func (r *REPL) completeVar(prefix string) (c []string) {
	var matches []string

	for k := range r.vars {
		if strings.HasPrefix(k, prefix) {
			matches = append(matches, k)
		}
	}
	sort.Strings(matches)

	return matches
}

func (r *REPL) completeRule(prefix string) (c []string) {
	var matches []string

	if len(prefix) == 0 {
		prefix = "#"
	}

	if r.policy == nil || !strings.HasPrefix(prefix, "#") {
		return matches
	}

	numStr := prefix[1:]

	if _, err := strconv.Atoi(numStr); numStr != "" && err != nil {
		return matches
	}

	for idx := range r.policy.rules {
		idxStr := strconv.Itoa(idx)
		if strings.HasPrefix(idxStr, numStr) {
			matches = append(matches, "#"+idxStr)
		}
	}

	return matches
}

func isTerminated(line string, stack *runeStack) (string, bool) {
	if line[len(line)-1] == '\\' {
		return line[:len(line)-1], false
	}

	inQuote := false
	for idx, r := range line {
		switch r {
		case '"', '\'':
			if idx-1 >= 0 && line[idx-1] == '\\' {
				continue
			}

			if p, ok := stack.Peek(); ok {
				if p == r {
					stack.Pop()
				}
			} else {
				stack.Push(r)
			}

			inQuote = !inQuote
		case '(', '{', '[':
			if inQuote {
				continue
			}
			stack.Push(r)
		case ')', '}', ']':
			if inQuote {
				continue
			}
			if p, ok := stack.Peek(); ok {
				if oppositeChars[r] == p {
					stack.Pop()
				}
			}
		}
	}

	return line, stack.IsEmpty()
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
