// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/ast"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

const (
	storeFetchTimeout = 2 * time.Second
	updateQueueSize   = 32
)

func BatchCompile(queue <-chan *policy.CompilationUnit) error {
	var errs ErrorList

	for unit := range queue {
		if _, err := Compile(unit); err != nil {
			errList := new(ErrorList)
			if errors.As(err, errList) {
				errs = append(errs, (*errList)...)
			} else {
				errs = append(errs, newError(unit.MainSourceFile(), err, "Compiler error"))
			}
		}
	}

	return errs.ErrOrNil()
}

func Compile(unit *policy.CompilationUnit) (Evaluator, error) {
	if err := checkForAmbiguousOrUnknownDerivedRoles(unit); err != nil {
		return nil, err
	}

	modules, conditionIdx, err := hydrate(unit)
	if err != nil {
		return nil, newError(unit.MainSourceFile(), err, "Failed to generate code")
	}

	regoCompiler := codegen.NewRegoCompiler()
	if regoCompiler.Compile(modules); regoCompiler.Failed() {
		return nil, newCodeGenErrors(unit.MainSourceFile(), regoCompiler.Errors)
	}

	eval, err := newEvaluator(unit, regoCompiler, conditionIdx)
	if err != nil {
		return nil, newError(unit.MainSourceFile(), err, "Failed to prepare evaluator")
	}

	return eval, nil
}

func checkForAmbiguousOrUnknownDerivedRoles(p *policy.CompilationUnit) ErrorList {
	root := p.Definitions[p.ModID]
	rp, ok := root.PolicyType.(*policyv1.Policy_ResourcePolicy)
	if !ok {
		return nil
	}

	var errors ErrorList
	srcFile := policy.GetSourceFile(root)

	// build a set of derived roles defined in the imports.
	roleDefs := make(map[string][]string)

	for _, imp := range rp.ResourcePolicy.ImportDerivedRoles {
		impID := namer.GenModuleIDFromName(namer.DerivedRolesModuleName(imp))

		def, ok := p.Definitions[impID]
		if !ok {
			errors = append(errors,
				newError(srcFile, ErrImportNotFound, fmt.Sprintf("Import '%s' cannot be found", imp)))
			continue
		}

		dr, ok := def.PolicyType.(*policyv1.Policy_DerivedRoles)
		if !ok {
			errors = append(errors,
				newError(srcFile, ErrInvalidImport, fmt.Sprintf("Import '%s' is not a derived roles definition", imp)))
			continue
		}

		for _, rd := range dr.DerivedRoles.Definitions {
			roleDefs[rd.Name] = append(roleDefs[rd.Name], imp)
		}
	}

	if len(errors) > 0 {
		return errors
	}

	// check for derived role references that don't exist in the imports.
	for _, rule := range rp.ResourcePolicy.Rules {
		for _, r := range rule.DerivedRoles {
			rd, ok := roleDefs[r]
			if !ok {
				errors = append(errors,
					newError(srcFile, ErrUnknownDerivedRole, fmt.Sprintf("Derived role '%s' is not defined in any imports", r)))
			}

			if len(rd) > 1 {
				rdList := strings.Join(rd, ",")
				errors = append(errors,
					newError(srcFile, ErrAmbiguousDerivedRole, fmt.Sprintf("Derived role '%s' is defined in more than one import: [%s]", r, rdList)))
			}
		}
	}

	return errors
}

func hydrate(unit *policy.CompilationUnit) (map[string]*ast.Module, ConditionIndex, error) {
	var conditionIdx ConditionIndex
	modules := make(map[string]*ast.Module, len(unit.Definitions))

	for modID, def := range unit.Definitions {
		srcFile := policy.GetSourceFile(def)
		var mod *ast.Module
		var cm ConditionMap
		var err error

		// use generated code if it exists -- which should be faster.
		if gp, ok := unit.Generated[modID]; ok {
			mod, cm, err = hydrateGeneratedPolicy(srcFile, gp, def.Globals)
			if err != nil {
				// try to generate the code from source
				mod, cm, err = generateCode(srcFile, def)
			}
		} else {
			mod, cm, err = generateCode(srcFile, def)
		}

		if err != nil {
			return nil, nil, err
		}

		modules[srcFile] = mod
		if cm != nil {
			if conditionIdx == nil {
				conditionIdx = NewConditionIndex()
			}

			conditionIdx[modID] = cm
		}
	}

	return modules, conditionIdx, nil
}

func hydrateGeneratedPolicy(srcFile string, gp *policyv1.GeneratedPolicy, globals map[string]string) (*ast.Module, ConditionMap, error) {
	m, err := ast.ParseModule(srcFile, string(gp.Code))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated code: %w", err)
	}

	cm, err := NewConditionMapFromRepr(gp.CelConditions, globals)
	if err != nil {
		return nil, nil, err
	}

	return m, cm, nil
}

func generateCode(srcFile string, p *policyv1.Policy) (*ast.Module, ConditionMap, error) {
	res, err := codegen.GenerateCode(p)
	if err != nil {
		return nil, nil, newCodeGenErrors(srcFile, err)
	}

	var cm ConditionMap

	if len(res.Conditions) > 0 {
		cm, err = NewConditionMap(res.Conditions, p.Globals)
		if err != nil {
			return nil, nil, err
		}
	}

	return res.Module, cm, nil
}
