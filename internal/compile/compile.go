// Copyright 2021 Zenauth Ltd.

package compile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/codegen"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
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
		return nil, err
	}

	regoCompiler := codegen.NewRegoCompiler()
	if regoCompiler.Compile(modules); regoCompiler.Failed() {
		return nil, newCodeGenErrors(unit.MainSourceFile(), regoCompiler.Errors)
	}

	return newEvaluator(regoCompiler, conditionIdx), nil
}

func hydrate(unit *policy.CompilationUnit) (map[string]*ast.Module, ConditionIndex, error) {
	var conditionIdx ConditionIndex
	modules := make(map[string]*ast.Module, len(unit.Definitions))

	for modID, def := range unit.Definitions {
		srcFile := policy.GetSourceFile(def)
		var cgResult *codegen.Result

		genCode, ok := unit.Generated[modID]
		if !ok {
			res, err := codegen.GenerateCode(def)
			if err != nil {
				return nil, nil, newCodeGenErrors(srcFile, err)
			}
			cgResult = res
		} else {
			res, err := codegen.CodeGenResultFromRepr(genCode)
			if err != nil {
				return nil, nil, newCodeGenErrors(srcFile, err)
			}
			cgResult = res
		}

		modules[srcFile] = cgResult.Module

		if len(cgResult.Conditions) > 0 {
			if conditionIdx == nil {
				conditionIdx = NewConditionIndex()
			}

			cm, err := NewConditionMap(cgResult.Conditions)
			if err != nil {
				return nil, nil, err
			}

			conditionIdx.Add(cgResult.ModName, cm)
		}
	}

	return modules, conditionIdx, nil
}

type Compiler struct {
	log         *zap.SugaredLogger
	store       storage.Store
	updateQueue chan storage.Event
	mu          sync.RWMutex
	evaluators  map[namer.ModuleID]Evaluator
}

func NewCompiler(ctx context.Context, store storage.Store) *Compiler {
	c := &Compiler{
		log:         zap.S().Named("compiler"),
		store:       store,
		updateQueue: make(chan storage.Event, updateQueueSize),
		evaluators:  make(map[namer.ModuleID]Evaluator),
	}

	go c.processUpdateQueue(ctx)
	store.Subscribe(c)

	return c
}

func (c *Compiler) SubscriberID() string {
	return "compiler"
}

func (c *Compiler) OnStorageEvent(events ...storage.Event) {
	for _, evt := range events {
		c.log.Debugw("Received storage event", "event", evt)
		c.updateQueue <- evt
	}
}

func (c *Compiler) processUpdateQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-c.updateQueue:
			c.log.Debugw("Processing storage event", "event", evt)
			if err := c.recompile(evt); err != nil {
				c.log.Warnw("Error while processing storage event", "event", evt, "error", err)
			}
		}
	}
}

func (c *Compiler) recompile(evt storage.Event) error {
	// if this is a delete event, remove the module from the cache
	if evt.Kind == storage.EventDeletePolicy {
		c.Evict(evt.PolicyID)
	}

	// find the modules that will be affected by this policy getting updated or deleted.
	var toRecompile []namer.ModuleID
	if evt.Kind == storage.EventAddOrUpdatePolicy {
		toRecompile = append(toRecompile, evt.PolicyID)
	}

	dependents, err := c.getDependents(evt.PolicyID)
	if err != nil {
		return err
	}

	// only recompile the ones that are already cached.
	c.mu.RLock()
	for _, d := range dependents {
		if _, ok := c.evaluators[d]; ok {
			toRecompile = append(toRecompile, d)
		}
	}
	c.mu.RUnlock()

	ctx, cancelFunc := context.WithTimeout(context.Background(), storeFetchTimeout)
	defer cancelFunc()

	compileUnits, err := c.store.GetCompilationUnits(ctx, toRecompile...)
	if err != nil {
		return fmt.Errorf("failed to get compilation units: %w", err)
	}

	for modID, cu := range compileUnits {
		if err := c.Compile(cu); err != nil {
			// log and remove the module that failed to compile.
			c.log.Errorw("Failed to recompile", "id", modID, "error", err)
			c.Evict(modID)
		}
	}

	return nil
}

func (c *Compiler) getDependents(modID namer.ModuleID) ([]namer.ModuleID, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), storeFetchTimeout)
	defer cancelFunc()

	dependents, err := c.store.GetDependents(ctx, modID)
	if err != nil {
		return nil, fmt.Errorf("failed to find dependents: %w", err)
	}

	if len(dependents) > 0 {
		return dependents[modID], nil
	}

	return nil, nil
}

func (c *Compiler) Compile(unit *policy.CompilationUnit) error {
	startTime := time.Now()
	err := c.doCompile(unit)
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

	return err
}

func (c *Compiler) Evict(modID namer.ModuleID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.evaluators, modID)
}

func (c *Compiler) doCompile(unit *policy.CompilationUnit) error {
	eval, err := Compile(unit)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.evaluators[unit.ModID] = eval
	c.mu.Unlock()

	return nil
}

func (c *Compiler) GetEvaluator(ctx context.Context, modID namer.ModuleID) (Evaluator, error) {
	c.mu.RLock()
	eval, ok := c.evaluators[modID]
	c.mu.RUnlock()

	if ok {
		return eval, nil
	}

	compileUnits, err := c.store.GetCompilationUnits(ctx, modID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	// TODO (cell): Negative cache for missing policies
	if len(compileUnits) == 0 {
		return nil, nil
	}

	for _, cu := range compileUnits {
		if err := c.Compile(cu); err != nil {
			return nil, fmt.Errorf("failed to compile module %w", err)
		}
	}

	c.mu.RLock()
	eval = c.evaluators[modID]
	c.mu.RUnlock()

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
			errors = append(errors, newError(srcFile, ErrImportNotFound, fmt.Sprintf("Import '%s' cannot be found", imp)))
			continue
		}

		dr, ok := def.PolicyType.(*policyv1.Policy_DerivedRoles)
		if !ok {
			errors = append(errors, newError(srcFile, ErrInvalidImport, fmt.Sprintf("Import '%s' is not a derived roles definition", imp)))
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
				errors = append(errors, newError(srcFile, ErrUnknownDerivedRole, fmt.Sprintf("Derived role '%s' is not defined in any imports", r)))
			}

			if len(rd) > 1 {
				errors = append(errors, newError(srcFile, ErrAmbiguousDerivedRole, fmt.Sprintf("Derived role '%s' is defined in more than one import: [%s]", r, strings.Join(rd, ","))))
			}
		}
	}

	return errors
}
