package compile

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"

	policyv1 "github.com/cerbos/cerbos/pkg/generated/policy/v1"
	"github.com/cerbos/cerbos/pkg/internal"
	"github.com/cerbos/cerbos/pkg/namer"
	"github.com/cerbos/cerbos/pkg/observability/metrics"
)

type Unit struct {
	ModID       namer.ModuleID
	Definitions map[string]*policyv1.Policy
	ModToFile   map[namer.ModuleID]string
	Err         error
}

type Incremental struct {
	AddOrUpdate map[namer.ModuleID]*Unit
	Remove      map[namer.ModuleID]struct{}
}

type Compiler struct {
	mu         sync.RWMutex
	evaluators map[namer.ModuleID]*evaluator
}

func Compile(pchan <-chan *Unit) (*Compiler, error) {
	c := &Compiler{evaluators: make(map[namer.ModuleID]*evaluator)}

	var errors ErrorList

	for p := range pchan {
		if p.Err != nil {
			errors = append(errors, newError("NA", p.Err, "Invalid policy set"))
			continue
		}

		eval, err := measureCompileDuration(p)
		if err.ErrOrNil() != nil {
			errors = append(errors, err...)
			continue
		}

		c.evaluators[p.ModID] = eval
	}

	return c, errors.ErrOrNil()
}

func measureCompileDuration(p *Unit) (*evaluator, ErrorList) {
	startTime := time.Now()
	eval, err := compilePolicy(p)
	durationMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := "success"
	if err != nil {
		status = "failure"
	}

	_ = stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{tag.Upsert(metrics.KeyCompileStatus, status)},
		metrics.CompileDuration.M(durationMs),
	)

	return eval, err
}

func compilePolicy(p *Unit) (*evaluator, ErrorList) {
	if errs := checkForAmbiguousOrUnknownDerivedRoles(p); errs.ErrOrNil() != nil {
		return nil, errs
	}

	var errors ErrorList
	var conditionIdx ConditionIndex

	modules := make(map[string]*ast.Module, len(p.Definitions))

	for file, pol := range p.Definitions {
		result, err := internal.GenerateCode(pol)
		if err != nil {
			errors = append(errors, newCodeGenErrors(file, err)...)
			continue
		}

		modules[file] = result.Module

		if len(result.Conditions) > 0 {
			if conditionIdx == nil {
				conditionIdx = make(ConditionIndex)
			}

			conditionIdx[result.ModID] = NewConditionMap(result.Conditions)
		}
	}

	if errors.ErrOrNil() != nil {
		return nil, errors
	}

	regoCompiler := internal.NewRegoCompiler()
	if regoCompiler.Compile(modules); regoCompiler.Failed() {
		errors = append(errors, newCodeGenErrors(p.ModToFile[p.ModID], regoCompiler.Errors)...)

		return nil, errors
	}

	eval := newEvaluator(regoCompiler, conditionIdx)

	return eval, errors
}

func checkForAmbiguousOrUnknownDerivedRoles(p *Unit) ErrorList {
	polFile := p.ModToFile[p.ModID]
	root := p.Definitions[polFile]
	rp, ok := root.PolicyType.(*policyv1.Policy_ResourcePolicy)
	if !ok {
		return nil
	}

	var errors ErrorList

	// build a set of derived roles defined in the imports.
	roleDefs := make(map[string][]string)

	for _, imp := range rp.ResourcePolicy.ImportDerivedRoles {
		impID := namer.GenModuleIDFromName(namer.DerivedRolesModuleName(imp))
		impFile, ok := p.ModToFile[impID]
		if !ok {
			errors = append(errors, newError(polFile, ErrImportNotFound, fmt.Sprintf("Import '%s' cannot be found", imp)))
			continue
		}

		def, ok := p.Definitions[impFile]
		if !ok {
			errors = append(errors, newError(polFile, ErrImportNotFound, fmt.Sprintf("Import '%s' cannot be found", imp)))
			continue
		}

		dr, ok := def.PolicyType.(*policyv1.Policy_DerivedRoles)
		if !ok {
			errors = append(errors, newError(polFile, ErrInvalidImport, fmt.Sprintf("Import '%s' is not a derived roles definition", imp)))
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
				errors = append(errors, newError(polFile, ErrUnknownDerivedRole, fmt.Sprintf("Derived role '%s' is not defined in any imports", r)))
			}

			if len(rd) > 1 {
				errors = append(errors, newError(polFile, ErrAmbiguousDerivedRole, fmt.Sprintf("Derived role '%s' is defined in more than one import: [%s]", r, strings.Join(rd, ","))))
			}
		}
	}

	return errors
}

func (c *Compiler) Update(inc *Incremental) error {
	var errors ErrorList

	evaluators := make(map[namer.ModuleID]*evaluator)
	for _, p := range inc.AddOrUpdate {
		eval, errs := measureCompileDuration(p)
		if len(errs) > 0 {
			errors = append(errors, errs...)
			continue
		}

		evaluators[p.ModID] = eval
	}

	if err := errors.ErrOrNil(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for modID, eval := range evaluators {
		c.evaluators[modID] = eval
	}

	for modID := range inc.Remove {
		delete(c.evaluators, modID)
	}

	return nil
}

func (c *Compiler) GetEvaluator(modID namer.ModuleID) Evaluator {
	c.mu.RLock()
	defer c.mu.RUnlock()

	eval, ok := c.evaluators[modID]
	if !ok {
		return nil
	}

	return eval
}
