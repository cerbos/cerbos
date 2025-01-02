// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/common/ast"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func compilePolicyConstants(modCtx *moduleCtx, constants *policyv1.Constants) {
	if modCtx.constants != nil {
		return
	}

	modCtx.constants = newConstantDefinitions(modCtx)

	for i, imp := range constants.GetImport() {
		ecModID := namer.ExportConstantsModuleID(imp)

		ecModCtx := modCtx.moduleCtx(ecModID)
		if ecModCtx == nil {
			path := policy.ConstantsImportProtoPath(modCtx.def, i)
			modCtx.addErrForProtoPath(path, errImportNotFound, "Constants import '%s' cannot be found", imp)
			continue
		}

		compileExportConstants(ecModCtx)
		modCtx.constants.Import(ecModCtx, fmt.Sprintf("import '%s'", imp))
	}

	modCtx.constants.Compile(constants.GetLocal(), policy.ConstantsLocalProtoPath(modCtx.def), "policy local constants")

	modCtx.constants.Resolve()
}

func compileExportConstants(modCtx *moduleCtx) {
	if modCtx.constants != nil {
		return
	}

	modCtx.constants = newConstantDefinitions(modCtx)

	ec := modCtx.def.GetExportConstants()
	if ec == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not an export constants definition")
		return
	}

	modCtx.constants.Compile(ec.Definitions, policy.ExportConstantsConstantProtoPath(), "definitions")
}

type constantDefinitions struct {
	modCtx  *moduleCtx
	values  map[string]*structpb.Value
	sources map[string][]*constantCtx
	used    map[string]struct{}
}

func newConstantDefinitions(modCtx *moduleCtx) *constantDefinitions {
	return &constantDefinitions{
		modCtx:  modCtx,
		values:  make(map[string]*structpb.Value),
		sources: make(map[string][]*constantCtx),
	}
}

func (cd *constantDefinitions) Compile(definitions map[string]*structpb.Value, path, source string) {
	for name, value := range definitions {
		cd.Add(name, value, cd.modCtx.constantCtx(source, fmt.Sprintf("%s[%q]", path, name)))
	}
}

func (cd *constantDefinitions) Import(from *moduleCtx, source string) {
	for name, value := range from.constants.values {
		cd.Add(name, value, from.constants.sources[name][0].withSource(source))
	}
}

func (cd *constantDefinitions) Add(name string, value *structpb.Value, constCtx *constantCtx) {
	cd.values[name] = value
	cd.sources[name] = append(cd.sources[name], constCtx)
}

func (cd *constantDefinitions) Resolve() {
	cd.reportRedefinedConstants()
	cd.ResetUsage()
}

func (cd *constantDefinitions) IsDefined(name string) bool {
	_, ok := cd.values[name]
	return ok
}

func (cd *constantDefinitions) reportRedefinedConstants() {
	for name, definedIn := range cd.sources {
		var definedInMsg string
		switch len(definedIn) {
		case 1:
			continue

		case 2: //nolint:mnd
			definedInMsg = strings.Join(constantDefinitionPlaces(definedIn), " and ")

		default:
			dil := constantDefinitionPlaces(definedIn)
			definedInMsg = fmt.Sprintf("%s, and %s", strings.Join(dil[:len(dil)-1], ", "), dil[len(dil)-1])
		}

		cd.modCtx.addErrWithDesc(errConstantRedefined, "Constant '%s' has multiple definitions in %s", name, definedInMsg)
	}
}

func constantDefinitionPlaces(contexts []*constantCtx) []string {
	out := make([]string, len(contexts))
	for i, cc := range contexts {
		pos := cc.srcCtx.PositionForProtoPath(cc.path)
		if pos != nil {
			out[i] = fmt.Sprintf("%s (%s:%d:%d)", cc.source, cc.sourceFile, pos.GetLine(), pos.GetColumn())
		} else {
			out[i] = fmt.Sprintf("%s (%s)", cc.source, cc.sourceFile)
		}
	}

	return out
}

func (cd *constantDefinitions) references(path string, expr *expr.CheckedExpr) map[string]struct{} {
	exprAST, err := ast.ToAST(expr)
	if err != nil {
		cd.modCtx.addErrForProtoPath(path, err, "Failed to convert expression to AST")
		return nil
	}

	references := make(map[string]struct{})
	ast.PreOrderVisit(exprAST.Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}

		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		if operandNode.Kind() == ast.IdentKind {
			ident := operandNode.AsIdent()
			switch ident {
			case conditions.CELConstantsIdent, conditions.CELConstantsAbbrev:
				references[selectNode.FieldName()] = struct{}{}
			}
		}
	}))

	return references
}

func (cd *constantDefinitions) ResetUsage() {
	cd.used = make(map[string]struct{}, len(cd.values))
}

func (cd *constantDefinitions) Use(path string, expr *expr.CheckedExpr) {
	for name := range cd.references(path, expr) {
		_, defined := cd.values[name]
		if defined {
			cd.used[name] = struct{}{}
		} else {
			cd.modCtx.addErrForProtoPath(path, errUndefinedConstant, "Undefined constant '%s'", name)
		}
	}
}

func (cd *constantDefinitions) Used() map[string]*structpb.Value {
	used := make(map[string]*structpb.Value, len(cd.used))
	for name := range cd.used {
		used[name] = cd.values[name]
	}
	return used
}
