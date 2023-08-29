// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/simple"
	"gonum.org/v1/gonum/graph/topo"
)

func compileVariables(modCtx *moduleCtx, variables *policyv1.Variables) ([]*runtimev1.Variable, map[string]*runtimev1.Expr) {
	definitions := newVariableDefinitions()

	for _, imp := range variables.GetImport() {
		evModID := namer.ExportVariablesModuleID(imp)

		evModCtx := modCtx.moduleCtx(evModID)
		if evModCtx == nil {
			modCtx.addErrWithDesc(errImportNotFound, "Variables import '%s' cannot be found", imp)
			continue
		}

		ev := evModCtx.def.GetExportVariables()
		if ev == nil {
			evModCtx.addErrWithDesc(errUnexpectedErr, "Not an export variables definition")
			continue
		}

		definitions.Compile(evModCtx, ev.Definitions, fmt.Sprintf("import '%s'", imp))
	}

	definitions.Compile(modCtx, variables.GetLocal(), "policy local variables")
	definitions.Compile(modCtx, modCtx.def.Variables, "top-level policy variables (deprecated)") //nolint:staticcheck

	return definitions.Resolve(modCtx)
}

func sortCompiledVariables(fqn string, variables map[string]*runtimev1.Expr) ([]*runtimev1.Variable, error) {
	modCtx := &moduleCtx{
		unitCtx: &unitCtx{errors: new(ErrorList)},
		fqn:     fqn,
	}

	definitions := newVariableDefinitions()
	for name, expr := range variables {
		definitions.Add(&runtimev1.Variable{Name: name, Expr: expr})
	}

	ordered, _ := definitions.Resolve(modCtx)

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
	graph   *simple.DirectedGraph
	ids     map[string]int64
	sources map[string][]string
	nextID  int64
}

func newVariableDefinitions() *variableDefinitions {
	return &variableDefinitions{
		graph:   simple.NewDirectedGraph(),
		ids:     make(map[string]int64),
		sources: make(map[string][]string),
	}
}

func (vd *variableDefinitions) Compile(modCtx *moduleCtx, definitions map[string]string, source string) {
	for name, expr := range definitions {
		vd.sources[name] = append(vd.sources[name], source)
		vd.Add(&runtimev1.Variable{
			Name: name,
			Expr: &runtimev1.Expr{
				Original: expr,
				Checked:  compileCELExpr(modCtx, fmt.Sprintf("variable '%s'", name), expr),
			},
		})
	}
}

func (vd *variableDefinitions) Add(variable *runtimev1.Variable) {
	vd.ids[variable.Name] = vd.nextID
	vd.graph.AddNode(&variableNode{id: vd.nextID, Variable: variable})
	vd.nextID++
}

func (vd *variableDefinitions) Resolve(modCtx *moduleCtx) ([]*runtimev1.Variable, map[string]*runtimev1.Expr) {
	vd.reportRedefinedVariables(modCtx)
	vd.resolveReferences(modCtx)

	nodes, err := topo.SortStabilized(vd.graph, sortVariablesByName)
	if err != nil {
		var cycles topo.Unorderable
		if errors.As(err, &cycles) {
			vd.reportCyclicalVariables(modCtx, cycles)
		} else {
			modCtx.addErrWithDesc(err, "Unexpected error sorting variable definitions")
		}
		return nil, nil
	}

	ordered := make([]*runtimev1.Variable, len(nodes))
	unordered := make(map[string]*runtimev1.Expr)
	for i, node := range nodes {
		variable := node.(*variableNode).Variable //nolint:forcetypeassert
		ordered[i] = variable
		unordered[variable.Name] = variable.Expr
	}

	return ordered, unordered
}

func (vd *variableDefinitions) reportRedefinedVariables(modCtx *moduleCtx) {
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

		modCtx.addErrWithDesc(errVariableRedefined, "Variable '%s' has multiple definitions in %s", name, definedInMsg)
	}
}

func (vd *variableDefinitions) resolveReferences(modCtx *moduleCtx) {
	for referrerName, referrerID := range vd.ids {
		referrer := vd.graph.Node(referrerID).(*variableNode) //nolint:forcetypeassert
		for referencedName := range variableReferences(modCtx, fmt.Sprintf("variable '%s'", referrerName), referrer.Expr) {
			if referencedName == referrerName {
				modCtx.addErrWithDesc(errCyclicalVariables, "Variable '%s' references itself", referrerName)
				continue
			}

			referencedID, ok := vd.ids[referencedName]
			if !ok {
				modCtx.addErrWithDesc(errUndefinedVariable, "Undefined variable '%s' referenced in variable '%s'", referencedName, referrerName)
				continue
			}

			referenced := vd.graph.Node(referencedID)
			vd.graph.SetEdge(vd.graph.NewEdge(referenced, referrer))
		}
	}
}

func (vd *variableDefinitions) reportCyclicalVariables(modCtx *moduleCtx, cycles [][]graph.Node) {
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
		modCtx.addErrWithDesc(errCyclicalVariables, desc.String())
	}
}

func sortVariablesByName(nodes []graph.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].(*variableNode).Name < nodes[j].(*variableNode).Name //nolint:forcetypeassert
	})
}
