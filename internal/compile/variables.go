// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/google/cel-go/common/ast"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/simple"
	"gonum.org/v1/gonum/graph/topo"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func compilePolicyVariables(modCtx *moduleCtx, variables *policyv1.Variables) {
	if modCtx.variables != nil {
		return
	}

	modCtx.variables = newVariableDefinitions(modCtx)

	for _, imp := range variables.GetImport() {
		evModID := namer.ExportVariablesModuleID(imp)

		evModCtx := modCtx.moduleCtx(evModID)
		if evModCtx == nil {
			modCtx.addErrWithDesc(errImportNotFound, "Variables import '%s' cannot be found", imp)
			continue
		}

		compileExportVariables(evModCtx)
		modCtx.variables.Import(evModCtx, fmt.Sprintf("import '%s'", imp))
	}

	modCtx.variables.Compile(variables.GetLocal(), "policy local variables")
	modCtx.variables.Compile(modCtx.def.Variables, "top-level policy variables (deprecated)") //nolint:staticcheck

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

	modCtx.variables.Compile(ev.Definitions, "definitions")
}

func sortCompiledVariables(fqn string, variables map[string]*runtimev1.Expr) ([]*runtimev1.Variable, error) {
	modCtx := &moduleCtx{
		unitCtx: &unitCtx{errors: new(ErrorList)},
		fqn:     fqn,
	}

	modCtx.variables = newVariableDefinitions(modCtx)
	for name, expr := range variables {
		modCtx.variables.Add(&runtimev1.Variable{Name: name, Expr: expr}, "")
	}
	modCtx.variables.Resolve()

	ordered, _ := modCtx.variables.All()
	return ordered, modCtx.error()
}

type variableNode struct {
	*runtimev1.Variable
	id int64
}

func (v *variableNode) ID() int64 {
	return v.id
}

type variableDefinitions struct {
	modCtx  *moduleCtx
	graph   *simple.DirectedGraph
	ids     map[string]int64
	sources map[string][]string
	used    map[string]struct{}
	nextID  int64
}

func newVariableDefinitions(modCtx *moduleCtx) *variableDefinitions {
	return &variableDefinitions{
		modCtx:  modCtx,
		graph:   simple.NewDirectedGraph(),
		ids:     make(map[string]int64),
		sources: make(map[string][]string),
	}
}

func (vd *variableDefinitions) Compile(definitions map[string]string, source string) {
	for name, expr := range definitions {
		vd.Add(&runtimev1.Variable{
			Name: name,
			Expr: &runtimev1.Expr{
				Original: expr,
				Checked:  compileCELExpr(vd.modCtx, fmt.Sprintf("variable '%s'", name), expr, false),
			},
		}, source)
	}
}

func (vd *variableDefinitions) Import(from *moduleCtx, source string) {
	nodes := from.variables.graph.Nodes()
	for nodes.Next() {
		vd.Add(nodes.Node().(*variableNode).Variable, source) //nolint:forcetypeassert
	}
}

func (vd *variableDefinitions) Add(variable *runtimev1.Variable, source string) {
	vd.sources[variable.Name] = append(vd.sources[variable.Name], source)
	vd.ids[variable.Name] = vd.nextID
	vd.graph.AddNode(&variableNode{id: vd.nextID, Variable: variable})
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

		case 2: //nolint:gomnd
			definedInMsg = strings.Join(definedIn, " and ")

		default:
			definedInMsg = fmt.Sprintf("%s, and %s", strings.Join(definedIn[:len(definedIn)-1], ", "), definedIn[len(definedIn)-1])
		}

		vd.modCtx.addErrWithDesc(errVariableRedefined, "Variable '%s' has multiple definitions in %s", name, definedInMsg)
	}
}

func (vd *variableDefinitions) resolveReferences() {
	for referrerName, referrerID := range vd.ids {
		referrer := vd.graph.Node(referrerID).(*variableNode) //nolint:forcetypeassert
		for referencedName := range vd.references(fmt.Sprintf("variable '%s'", referrerName), referrer.Expr.Checked) {
			if referencedName == referrerName {
				vd.modCtx.addErrWithDesc(errCyclicalVariables, "Variable '%s' references itself", referrerName)
				continue
			}

			referencedID, ok := vd.ids[referencedName]
			if !ok {
				vd.modCtx.addErrWithDesc(errUndefinedVariable, "Undefined variable '%s' referenced in variable '%s'", referencedName, referrerName)
				continue
			}

			referenced := vd.graph.Node(referencedID)
			vd.graph.SetEdge(vd.graph.NewEdge(referenced, referrer))
		}
	}
}

func (vd *variableDefinitions) references(parent string, expr *expr.CheckedExpr) map[string]struct{} {
	exprAST, err := ast.ToAST(expr)
	if err != nil {
		vd.modCtx.addErrWithDesc(err, "Failed to convert expression to AST in %s", parent)
		return nil
	}

	references := make(map[string]struct{})
	visitor := ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}

		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		if operandNode.Kind() == ast.IdentKind {
			ident := operandNode.AsIdent()
			if ident == conditions.CELVariablesIdent || ident == conditions.CELVariablesAbbrev {
				references[selectNode.FieldName()] = struct{}{}
			}
		}
	})
	ast.PreOrderVisit(exprAST.Expr(), visitor)

	return references
}

func (vd *variableDefinitions) ResetUsage() {
	vd.used = make(map[string]struct{}, len(vd.ids))
}

func (vd *variableDefinitions) Use(parent string, expr *expr.CheckedExpr) {
	for name := range vd.references(parent, expr) {
		id, defined := vd.ids[name]
		if defined {
			vd.use(id, name)
		} else {
			vd.modCtx.addErrWithDesc(errUndefinedVariable, "Undefined variable '%s' referenced in %s", name, parent)
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
				if len(cycle) > 2 { //nolint:gomnd
					desc.WriteString(",")
				}
				desc.WriteString(" and ")

			default:
				desc.WriteString(", ")
			}

			fmt.Fprintf(&desc, "'%s'", node.(*variableNode).Name) //nolint:forcetypeassert
		}

		desc.WriteString(" form a cycle")
		vd.modCtx.addErrWithDesc(errCyclicalVariables, desc.String())
	}
}

func sortVariablesByName(nodes []graph.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].(*variableNode).Name < nodes[j].(*variableNode).Name //nolint:forcetypeassert
	})
}
