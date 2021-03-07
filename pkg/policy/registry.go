package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/internal"
	"github.com/charithe/menshen/pkg/namer"
)

var (
	ErrEmptyTransaction    = errors.New("transaction is empty")
	ErrInactiveTransaction = errors.New("transaction is not active")
	ErrStaleTransaction    = errors.New("transaction is stale")
)

// RegistryWatcher is an interface for watchers who want to be notified of registry updates.
type RegistryWatcher interface {
	RegistryUpdated(uint64)
}

// Transaction represents a set of actions to perform on the registry.
type Transaction interface {
	Add(*policyv1.Policy) error
	Remove(*policyv1.Policy) error
}

// Transaction is the builder for registry transactions.
// Not thread-safe: must only be used inside a single goroutine.
type transaction struct {
	modulesAdded   map[string]*ast.Module
	modulesRemoved map[string]struct{}
	conditionIdx   ConditionIndex
	opCount        uint64
	active         bool
}

// Add adds a policy to the transaction.
func (tx *transaction) Add(p *policyv1.Policy) error {
	if !tx.active {
		return ErrInactiveTransaction
	}

	result, err := internal.GenerateCode(p)
	if err != nil {
		return fmt.Errorf("failed to generate code for policy: %w", err)
	}

	if tx.modulesAdded == nil {
		tx.modulesAdded = make(map[string]*ast.Module)
	}

	if tx.conditionIdx == nil {
		tx.conditionIdx = make(ConditionIndex)
	}

	tx.modulesAdded[result.ModName] = result.Module
	tx.conditionIdx[result.ModName] = NewConditionMap(result.Conditions)
	tx.opCount++

	return nil
}

// Remove removes a policy from the transaction.
func (tx *transaction) Remove(p *policyv1.Policy) error {
	if !tx.active {
		return ErrInactiveTransaction
	}

	modName := namer.ModuleName(p)
	if tx.modulesRemoved == nil {
		tx.modulesRemoved = make(map[string]struct{})
	}

	tx.modulesRemoved[modName] = struct{}{}
	tx.opCount++

	return nil
}

func (tx *transaction) prepareToCommit(ctx context.Context) error {
	if tx == nil || tx.opCount == 0 {
		return ErrEmptyTransaction
	}

	if !tx.active {
		return ErrInactiveTransaction
	}

	// mark the tx as inactive to prevent it from being reused.
	tx.active = false

	return ctx.Err()
}

type state struct {
	revision     uint64
	modules      map[string]*ast.Module
	conditionIdx ConditionIndex
}

// Registry maintains the current set of policies.
type Registry interface {
	NewTransaction() Transaction
	Replace(context.Context, Transaction) error
	Update(context.Context, Transaction) error
	GetChecker() *Checker
	GetConditionEvaluator(string, string) (ConditionEvaluator, error)
	AddWatcher(string, RegistryWatcher)
	RemoveWatcher(string)
}

// NewRegistry creates a new instance of the registry.
func NewRegistry() Registry {
	return &registry{
		log:          zap.S().Named("policy.registry"),
		modules:      make(map[string]*ast.Module),
		conditionIdx: make(ConditionIndex),
	}
}

type registry struct {
	log          *zap.SugaredLogger
	mu           sync.RWMutex
	revision     uint64
	modules      map[string]*ast.Module
	conditionIdx ConditionIndex
	checker      *Checker
	watcherMu    sync.RWMutex
	watchers     map[string]RegistryWatcher
}

// NewTransaction creates a new transaction.
func (reg *registry) NewTransaction() Transaction {
	return &transaction{active: true}
}

// Replace commits a transaction that completely replaces the registry entries.
func (reg *registry) Replace(ctx context.Context, txn Transaction) error {
	tx, ok := txn.(*transaction)
	if !ok {
		return fmt.Errorf("unknown transaction type %T", tx)
	}

	if err := tx.prepareToCommit(ctx); err != nil {
		return err
	}

	// compile the set of modules
	compiler, err := compileModules(tx.modulesAdded)
	if err != nil {
		return err
	}

	// if the context is cancelled, return
	if err := ctx.Err(); err != nil {
		return err
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()

	reg.modules = tx.modulesAdded
	reg.conditionIdx = tx.conditionIdx
	reg.checker = &Checker{
		compiler: compiler,
		log:      zap.S().Named("policy.checker").With("revision", reg.revision),
	}

	go reg.notifyUpdate(reg.revision)
	reg.revision++

	return nil
}

// Update commits an incremental transaction to the registry.
func (reg *registry) Update(ctx context.Context, txn Transaction) error {
	tx, ok := txn.(*transaction)
	if !ok {
		return fmt.Errorf("unknown transaction type %T", tx)
	}

	if err := tx.prepareToCommit(ctx); err != nil {
		return err
	}

	// make a copy of current state
	currState := reg.cloneState()

	// delete removed modules and conditions from the copy
	for modName := range tx.modulesRemoved {
		delete(currState.modules, modName)
		delete(currState.conditionIdx, modName)
	}

	// add the new modules to the copy
	for modName, mod := range tx.modulesAdded {
		currState.modules[modName] = mod
	}

	// add the new conditions to the copy
	for modName, condMap := range tx.conditionIdx {
		currState.conditionIdx[modName] = condMap
	}

	// compile the set of modules
	compiler, err := compileModules(currState.modules)
	if err != nil {
		return err
	}

	// if the context is cancelled, return
	if err := ctx.Err(); err != nil {
		return err
	}

	// now try swapping in the new state
	reg.mu.Lock()
	defer reg.mu.Unlock()

	// if the revision is not the same, the transaction is stale
	if reg.revision != currState.revision {
		return ErrStaleTransaction
	}

	reg.modules = currState.modules
	reg.conditionIdx = currState.conditionIdx
	reg.checker = &Checker{
		compiler: compiler,
		log:      zap.S().Named("policy.checker").With("revision", currState.revision),
	}

	go reg.notifyUpdate(currState.revision)
	reg.revision++

	return nil
}

func compileModules(m map[string]*ast.Module) (*ast.Compiler, error) {
	compiler := ast.NewCompiler()
	if compiler.Compile(m); compiler.Failed() {
		errList := make([]error, len(compiler.Errors))
		for i, err := range compiler.Errors {
			errList[i] = err
		}

		return nil, fmt.Errorf("compilation failed: %w", multierr.Combine(errList...))
	}

	return compiler, nil
}

func (reg *registry) cloneState() state {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	s := state{
		revision:     reg.revision,
		modules:      make(map[string]*ast.Module, len(reg.modules)),
		conditionIdx: make(ConditionIndex, len(reg.conditionIdx)),
	}

	for k, m := range reg.modules {
		s.modules[k] = m
	}

	for k, c := range reg.conditionIdx {
		s.conditionIdx[k] = c
	}

	return s
}

func (reg *registry) notifyUpdate(revision uint64) {
	reg.log.Info("Registry updated")

	reg.watcherMu.RLock()
	defer reg.watcherMu.RUnlock()

	for name, w := range reg.watchers {
		reg.log.Debugw("Notifying watcher", "watcher", name, "revision", revision)
		w.RegistryUpdated(revision)
	}
}

// GetChecker returns the current checker.
func (reg *registry) GetChecker() *Checker {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	return reg.checker
}

// GetConditionEvaluator returns a condition evaluator matching the given keys.
func (reg *registry) GetConditionEvaluator(modName, key string) (ConditionEvaluator, error) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	return reg.conditionIdx.GetConditionEvaluator(modName, key)
}

// AddWatcher adds a new watcher to the registry.
func (reg *registry) AddWatcher(name string, w RegistryWatcher) {
	reg.log.Debugw("Adding watcher", "key", name)

	reg.watcherMu.Lock()
	defer reg.watcherMu.Unlock()

	if reg.watchers == nil {
		reg.watchers = make(map[string]RegistryWatcher)
	}

	reg.watchers[name] = w
}

// RemoveWatcher removes a watcher from the registry.
func (reg *registry) RemoveWatcher(name string) {
	reg.log.Debugw("Removing watcher", "key", name)

	reg.watcherMu.Lock()
	defer reg.watcherMu.Unlock()

	if reg.watchers != nil {
		delete(reg.watchers, name)
	}
}

// ModuleCount returns the number of modules currently in the registry.
func (reg *registry) ModuleCount() int {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	return len(reg.modules)
}
