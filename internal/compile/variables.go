// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/cel-go/common/ast"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/simple"
	"gonum.org/v1/gonum/graph/topo"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func compilePolicyVariables(modCtx *moduleCtx, variables *policyv1.Variables) {
	if modCtx.variables != nil {
		return
	}

	modCtx.variables = newVariableDefinitions(modCtx)

	for i, imp := range variables.GetImport() {
		evModID := namer.ExportVariablesModuleID(imp)

		evModCtx := modCtx.moduleCtx(evModID)
		if evModCtx == nil {
			path := policy.VariablesImportProtoPath(modCtx.def, i)
			modCtx.addErrForProtoPath(path, errImportNotFound, "Variables import '%s' cannot be found", imp)
			continue
		}

		compileExportVariables(evModCtx)
		modCtx.variables.Import(evModCtx, fmt.Sprintf("import '%s'", imp))
	}

	modCtx.variables.Compile(variables.GetLocal(), policy.VariablesLocalProtoPath(modCtx.def), "policy local variables")
	modCtx.variables.Compile(modCtx.def.Variables, "variables", "deprecated top-level policy variables") //nolint:staticcheck

	modCtx.variables.Resolve()
}

func compileExportVariables(modCtx *moduleCtx) {
	if modCtx.variables != nil {
		return
	}

	modCtx.variables = newVariableDefinitions(modCtx)

	ev := modCtx.def.GetExportVariables()
	if ev == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not an export variables definition")
		return
	}

	modCtx.variables.Compile(ev.Definitions, policy.ExportVariablesVariableProtoPath(), "definitions")
}

func sortCompiledVariables(fqn string, variables map[string]*runtimev1.Expr) ([]*runtimev1.Variable, error) {
	modCtx := &moduleCtx{
		unitCtx: &unitCtx{errors: new(ErrorSet)},
		fqn:     fqn,
	}

	modCtx.variables = newVariableDefinitions(modCtx)
	for name, expr := range variables {
		modCtx.variables.Add(&runtimev1.Variable{Name: name, Expr: expr}, modCtx.variableCtx("", fmt.Sprintf("variables.%s", name)))
	}
	modCtx.variables.Resolve()

	ordered, _ := modCtx.variables.All()
	return ordered, modCtx.error()
}

type variableNode struct {
	*runtimev1.Variable
	varCtx *variableCtx
	id     int64
}

func (v *variableNode) ID() int64 {
	return v.id
}

type variableDefinitions struct {
	modCtx  *moduleCtx
	graph   *simple.DirectedGraph
	ids     map[string]int64
	sources map[string][]*variableCtx
	used    map[string]struct{}
	nextID  int64
}

func newVariableDefinitions(modCtx *moduleCtx) *variableDefinitions {
	return &variableDefinitions{
		modCtx:  modCtx,
		graph:   simple.NewDirectedGraph(),
		ids:     make(map[string]int64),
		sources: make(map[string][]*variableCtx),
	}
}

func (vd *variableDefinitions) Compile(definitions map[string]string, path, source string) {
	for name, expr := range definitions {
		varPath := fmt.Sprintf("%s[%q]", path, name)
		variable := &runtimev1.Variable{
			Name: name,
			Expr: &runtimev1.Expr{
				Original: expr,
				Checked:  compileCELExpr(vd.modCtx, varPath, expr, false),
			},
		}

		vd.Add(variable, vd.modCtx.variableCtx(source, varPath))
	}
}

func (vd *variableDefinitions) Import(from *moduleCtx, source string) {
	nodes := from.variables.graph.Nodes()
	for nodes.Next() {
		variable := nodes.Node().(*variableNode) //nolint:forcetypeassert
		vd.Add(variable.Variable, variable.varCtx.withSource(source))
	}
}

func (vd *variableDefinitions) Add(variable *runtimev1.Variable, varCtx *variableCtx) {
	vd.sources[variable.Name] = append(vd.sources[variable.Name], varCtx)
	vd.ids[variable.Name] = vd.nextID
	vd.graph.AddNode(&variableNode{id: vd.nextID, Variable: variable, varCtx: varCtx})
	vd.nextID++
}

func (vd *variableDefinitions) Resolve() {
	vd.reportRedefinedVariables()
	vd.resolveReferences()
	vd.ResetUsage()
}

func (vd *variableDefinitions) reportRedefinedVariables() {
	for name, definedIn := range vd.sources {
		var definedInMsg string
		switch len(definedIn) {
		case 1:
			continue

		case 2: //nolint:mnd
			definedInMsg = strings.Join(variableDefinitionPlaces(definedIn), " and ")

		default:
			dil := variableDefinitionPlaces(definedIn)
			definedInMsg = fmt.Sprintf("%s, and %s", strings.Join(dil[:len(dil)-1], ", "), dil[len(dil)-1])
		}

		vd.modCtx.addErrWithDesc(errVariableRedefined, "Variable '%s' has multiple definitions in %s", name, definedInMsg)
	}
}

func variableDefinitionPlaces(contexts []*variableCtx) []string {
	out := make([]string, len(contexts))
	for i, vc := range contexts {
		pos := vc.srcCtx.PositionForProtoPath(vc.path)
		if pos != nil {
			out[i] = fmt.Sprintf("%s (%s:%d:%d)", vc.source, vc.sourceFile, pos.GetLine(), pos.GetColumn())
		} else {
			out[i] = fmt.Sprintf("%s (%s)", vc.source, vc.sourceFile)
		}
	}

	return out
}

func (vd *variableDefinitions) resolveReferences() {
	for referrerName, referrerID := range vd.ids {
		referrer := vd.graph.Node(referrerID).(*variableNode) //nolint:forcetypeassert
		for referencedName := range vd.references(fmt.Sprintf("variable '%s'", referrerName), referrer.Expr.Checked) {
			if referencedName == referrerName {
				referrer.varCtx.addErrForProtoPath(referrer.varCtx.path, errCyclicalVariables, "Variable '%s' references itself", referencedName)
				continue
			}

			referencedID, ok := vd.ids[referencedName]
			if !ok {
				referrer.varCtx.addErrForProtoPath(referrer.varCtx.path, errUndefinedVariable, "Undefined variable '%s' referenced in variable '%s'", referencedName, referrerName)
				continue
			}

			referenced := vd.graph.Node(referencedID)
			vd.graph.SetEdge(vd.graph.NewEdge(referenced, referrer))
		}
	}
}

func (vd *variableDefinitions) references(path string, expr *expr.CheckedExpr) map[string]struct{} {
	exprAST, err := ast.ToAST(expr)
	if err != nil {
		vd.modCtx.addErrForProtoPath(path, err, "Failed to convert expression to AST")
		return nil
	}

	references := make(map[string]struct{})
	action := func(varName string) {
		references[varName] = struct{}{}
	}

	ast.PreOrderVisit(exprAST.Expr(), VariableVisitor(action))
	return references
}

func VariableVisitor(action func(string)) ast.Visitor {
	return ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}

		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		if operandNode.Kind() == ast.IdentKind {
			ident := operandNode.AsIdent()
			if ident == conditions.CELVariablesIdent || ident == conditions.CELVariablesAbbrev {
				action(selectNode.FieldName())
			}
		}
	})
}

func (vd *variableDefinitions) ResetUsage() {
	vd.used = make(map[string]struct{}, len(vd.ids))
}

func (vd *variableDefinitions) Use(path string, expr *expr.CheckedExpr) {
	for name := range vd.references(path, expr) {
		id, defined := vd.ids[name]
		if defined {
			vd.use(id, name)
		} else {
			vd.modCtx.addErrForProtoPath(path, errUndefinedVariable, "Undefined variable '%s'", name)
		}
	}
}

func (vd *variableDefinitions) use(id int64, name string) {
	_, alreadyUsed := vd.used[name]
	if alreadyUsed {
		return
	}

	vd.used[name] = struct{}{}

	references := vd.graph.To(id)
	for references.Next() {
		referenced := references.Node().(*variableNode) //nolint:forcetypeassert
		vd.use(referenced.id, referenced.Variable.Name)
	}
}

func (vd *variableDefinitions) Used() ([]*runtimev1.Variable, map[string]*runtimev1.Expr) {
	return vd.list(false)
}

func (vd *variableDefinitions) All() ([]*runtimev1.Variable, map[string]*runtimev1.Expr) {
	return vd.list(true)
}

func (vd *variableDefinitions) list(includeUnused bool) ([]*runtimev1.Variable, map[string]*runtimev1.Expr) {
	nodes, err := topo.SortStabilized(vd.graph, sortVariablesByName)
	if err != nil {
		var cycles topo.Unorderable
		if errors.As(err, &cycles) {
			vd.reportCyclicalVariables(cycles)
		} else {
			vd.modCtx.addErrWithDesc(err, "Unexpected error sorting variable definitions")
		}
		return nil, nil
	}

	ordered := make([]*runtimev1.Variable, 0, len(nodes))
	unordered := make(map[string]*runtimev1.Expr, len(nodes))
	for _, node := range nodes {
		variable := node.(*variableNode).Variable //nolint:forcetypeassert
		_, used := vd.used[variable.Name]
		if used || includeUnused {
			ordered = append(ordered, variable)
			unordered[variable.Name] = variable.Expr
		}
	}

	return ordered, unordered
}

func (vd *variableDefinitions) reportCyclicalVariables(cycles [][]graph.Node) {
	for _, cycle := range cycles {
		sortVariablesByName(cycle)

		var desc strings.Builder
		desc.WriteString("Variables ")

		for i, node := range cycle {
			switch i {
			case 0:

			case len(cycle) - 1:
				if len(cycle) > 2 { //nolint:mnd
					desc.WriteString(",")
				}
				desc.WriteString(" and ")

			default:
				desc.WriteString(", ")
			}

			variable := node.(*variableNode) //nolint:forcetypeassert
			pos := variable.varCtx.srcCtx.PositionForProtoPath(variable.varCtx.path)
			if pos != nil {
				fmt.Fprintf(&desc, "'%s' (%s:%d:%d)", variable.Name, variable.varCtx.sourceFile, pos.GetLine(), pos.GetColumn())
			} else {
				fmt.Fprintf(&desc, "'%s'", variable.Name)
			}
		}

		desc.WriteString(" form a cycle")
		if len(cycle) > 0 {
			firstItem := cycle[0].(*variableNode)                                                           //nolint:forcetypeassert
			firstItem.varCtx.addErrForProtoPath(firstItem.varCtx.path, errCyclicalVariables, desc.String()) //nolint:govet
		} else {
			vd.modCtx.addErrWithDesc(errCyclicalVariables, desc.String()) //nolint:govet
		}
	}
}

func sortVariablesByName(nodes []graph.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].(*variableNode).Name < nodes[j].(*variableNode).Name //nolint:forcetypeassert
	})
}
