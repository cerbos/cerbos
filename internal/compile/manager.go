// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package compile

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

type Manager struct {
	store storage.SourceStore
	log   *zap.SugaredLogger
}

func NewManager(ctx context.Context, store storage.SourceStore) (*Manager, error) {
	if err := config.GetSection(&Conf{}); err != nil {
		return nil, err
	}

	c := &Manager{
		log:   zap.S().Named("compiler"),
		store: store,
	}

	return c, nil
}

func (c *Manager) compile(unit *policy.CompilationUnit) (*runtimev1.RunnablePolicySet, error) {
	return metrics.RecordDuration2(metrics.CompileDuration(), func() (*runtimev1.RunnablePolicySet, error) {
		return Compile(unit, nil)
	})
}

func (c *Manager) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	if len(candidates) == 0 {
		return nil, errors.New("candidates list must contain at least one candidate")
	}

	cu, err := c.store.GetFirstMatch(ctx, candidates)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	if cu == nil {
		return nil, nil
	}

	rps, err := c.compile(cu)
	if err != nil {
		return nil, PolicyCompilationErr{underlying: err}
	}

	return rps, nil
}

func (c *Manager) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	cus, err := c.store.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	rpsSet := make([]*runtimev1.RunnablePolicySet, 0, len(cus))
	for _, cu := range cus {
		rps, err := c.compile(cu)
		if err != nil {
			return nil, PolicyCompilationErr{underlying: err}
		}

		if rps == nil {
			continue
		}

		rpsSet = append(rpsSet, rps)
	}

	return rpsSet, nil
}

func (c *Manager) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	res := []*runtimev1.RunnablePolicySet{}

	if len(modIDs) == 0 {
		return res, nil
	}

	cus, err := c.store.GetAllMatching(ctx, modIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	rpsSet := make([]*runtimev1.RunnablePolicySet, len(cus))
	for i, cu := range cus {
		rps, err := c.compile(cu)
		if err != nil {
			return nil, PolicyCompilationErr{underlying: err}
		}

		rpsSet[i] = rps
	}

	return rpsSet, nil
}

func (c *Manager) GetPolicySet(ctx context.Context, modID namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	compileUnits, err := c.store.GetCompilationUnits(ctx, modID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	if len(compileUnits) == 0 {
		return nil, nil
	}

	if cu, ok := compileUnits[modID]; ok {
		rps, err := c.compile(cu)
		if err != nil {
			return nil, PolicyCompilationErr{underlying: err}
		}

		return rps, nil
	}

	return nil, nil
}

func (c *Manager) Source() *auditv1.PolicySource {
	return c.store.Source()
}

type PolicyCompilationErr struct {
	underlying error
}

func (pce PolicyCompilationErr) Error() string {
	return fmt.Sprintf("policy compilation error: %v", pce.underlying)
}

func (pce PolicyCompilationErr) Unwrap() error {
	return pce.underlying
}

func (pce PolicyCompilationErr) Is(target error) bool {
	return errors.As(target, &PolicyCompilationErr{})
}
