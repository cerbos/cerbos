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

const eventBufferSize = 16

var ErrStaleTransaction = errors.New("stale transaction")

// IndexWatcher is an interface for watchers who want to be notified of index changes.
type IndexWatcher interface {
	IndexUpdated(uint64)
}

// IndexTxn is an index transaction.
type IndexTxn struct {
	revision uint64
	modules  map[string]*ast.Module
	updates  uint64
}

// Add adds a policy to the transaction.
func (tx *IndexTxn) Add(p *policyv1.Policy) error {
	modName := namer.ModuleName(p)

	mod, err := internal.GenerateRegoModule(modName, p)
	if err != nil {
		return fmt.Errorf("failed to generate module %s: %w", modName, err)
	}

	tx.modules[modName] = mod
	tx.updates++

	return nil
}

// Remove removes a policy from the transaction.
func (tx *IndexTxn) Remove(p *policyv1.Policy) error {
	modName := namer.ModuleName(p)
	delete(tx.modules, modName)
	tx.updates++

	return nil
}

// Contains returns true if the transaction contains the given policy.
func (tx *IndexTxn) Contains(p *policyv1.Policy) bool {
	modName := namer.ModuleName(p)
	_, exists := tx.modules[modName]

	return exists
}

// Index maintains an index of the policies in effect.
type Index struct {
	log        *zap.SugaredLogger
	mu         sync.RWMutex
	revision   uint64
	modules    map[string]*ast.Module
	checker    *Checker
	updateChan chan uint64
	watcherMu  sync.RWMutex
	watchers   map[string]IndexWatcher
}

// NewIndex creates a new index.
// It automatically starts a goroutine to update any watchers. Cancel the context to stop the goroutine.
func NewIndex(ctx context.Context) *Index {
	idx := &Index{
		log:        zap.S().Named("policy.index"),
		updateChan: make(chan uint64, eventBufferSize),
		watchers:   make(map[string]IndexWatcher),
	}

	go idx.startEventConsumer(ctx)

	return idx
}

func (idx *Index) startEventConsumer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case rev := <-idx.updateChan:
			idx.notifyWatchers(rev)
		}
	}
}

func (idx *Index) notifyWatchers(revision uint64) {
	idx.log.Debugw("Notifying watchers", "revision", revision)

	idx.watcherMu.RLock()
	defer idx.watcherMu.RUnlock()

	for _, w := range idx.watchers {
		w.IndexUpdated(revision)
	}
}

// AddWatcher adds a new watcher to the index.
func (idx *Index) AddWatcher(name string, w IndexWatcher) {
	idx.log.Debugw("Adding watcher", "key", name)

	idx.watcherMu.Lock()
	defer idx.watcherMu.Unlock()

	idx.watchers[name] = w
}

// RemoveWatcher removes a watcher from the index.
func (idx *Index) RemoveWatcher(name string) {
	idx.log.Debugw("Removing watcher", "key", name)

	idx.watcherMu.Lock()
	defer idx.watcherMu.Unlock()

	delete(idx.watchers, name)
}

func (idx *Index) notifyUpdate(revision uint64) {
	select {
	case idx.updateChan <- revision:
	default:
		idx.log.Warnw("Failed to send update event", "revision", revision)
	}
}

// NewTxn create a new transaction.
func (idx *Index) NewTxn() *IndexTxn {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	tx := &IndexTxn{
		revision: idx.revision,
		modules:  make(map[string]*ast.Module, len(idx.modules)),
	}

	for name, mod := range idx.modules {
		// We don't Copy the module because it doesn't get modified during the transaction.
		// It will either be replaced or removed. Not copying saves us some memory.
		tx.modules[name] = mod
	}

	return tx
}

// Commit commits a transaction.
func (idx *Index) Commit(ctx context.Context, tx *IndexTxn) error {
	// nothing to do if nothing changed
	if tx.updates == 0 {
		return nil
	}

	// if this is a stale txn, don't do extra work
	idx.mu.RLock()
	stale := idx.revision != tx.revision
	idx.mu.RUnlock()

	if stale {
		return ErrStaleTransaction
	}

	// compile the new set of modules
	compiler := ast.NewCompiler()
	if compiler.Compile(tx.modules); compiler.Failed() {
		errList := make([]error, len(compiler.Errors))
		for i, err := range compiler.Errors {
			errList[i] = err
		}

		return fmt.Errorf("compilation failed: %w", multierr.Combine(errList...))
	}

	checker := &Checker{compiler: compiler, log: zap.S().Named("policy.checker")}

	if err := ctx.Err(); err != nil {
		return err
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.revision != tx.revision {
		return ErrStaleTransaction
	}

	idx.revision++
	idx.modules = tx.modules
	idx.checker = checker

	idx.notifyUpdate(idx.revision)

	return nil
}

// GetChecker returns the current checker.
func (idx *Index) GetChecker() *Checker {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	return idx.checker
}

// Contains returns true if the given module name already exists in the index.
func (idx *Index) Contains(p *policyv1.Policy) bool {
	modName := namer.ModuleName(p)

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	_, exists := idx.modules[modName]

	return exists
}
