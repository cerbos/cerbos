// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"strings"
	"unique"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
)

type UniqueHandles map[unique.Handle[string]]struct{}

type StringDeduper struct {
	Handles UniqueHandles
}

func NewStringDeduper() *StringDeduper {
	return &StringDeduper{Handles: make(map[unique.Handle[string]]struct{})}
}

// Intern replaces *p with the canonical copy held by the unique package, so
// equal strings share one backing array.
func (s *StringDeduper) Intern(p *string) {
	if *p == "" {
		return
	}
	h := unique.Make(*p)
	s.Handles[h] = struct{}{}
	*p = h.Value()
}

func (s *StringDeduper) DedupCondition(c *runtimev1.Condition) {
	if c == nil {
		return
	}
	switch op := c.Op.(type) {
	case *runtimev1.Condition_All:
		if op.All != nil {
			for _, e := range op.All.Expr {
				s.DedupCondition(e)
			}
		}
	case *runtimev1.Condition_Any:
		if op.Any != nil {
			for _, e := range op.Any.Expr {
				s.DedupCondition(e)
			}
		}
	case *runtimev1.Condition_None:
		if op.None != nil {
			for _, e := range op.None.Expr {
				s.DedupCondition(e)
			}
		}
	case *runtimev1.Condition_Expr:
		s.dedupExpr(op.Expr)
	}
}

func (s *StringDeduper) dedupExpr(e *runtimev1.Expr) {
	if e == nil {
		return
	}
	s.Intern(&e.Original)
}

func (s *StringDeduper) dedupOutput(o *runtimev1.Output) {
	if o == nil || o.When == nil {
		return
	}
	s.dedupExpr(o.When.RuleActivated)
	s.dedupExpr(o.When.ConditionNotMet)
}

// RelocateConstants rebuilds a constant map with interned keys and relocated,
// deep-copied values.
func (s *StringDeduper) RelocateConstants(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		s.Intern(&k)
		out[k] = s.relocateAny(v)
	}
	return out
}

func (s *StringDeduper) relocateAny(v any) any {
	switch x := v.(type) {
	case string:
		return strings.Clone(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			s.Intern(&k)
			out[k] = s.relocateAny(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.relocateAny(e)
		}
		return out
	default:
		return v
	}
}

func (s *StringDeduper) dedupCore(c *FunctionalCore) {
	s.DedupCondition(c.Condition)
	s.DedupCondition(c.DerivedRoleCondition)
	s.dedupOutput(c.EmitOutput)
	s.dedupParams(c.Params)
	s.dedupParams(c.DerivedRoleParams)
	if len(c.origins) > 0 {
		out := make(map[string]struct{}, len(c.origins))
		for k := range c.origins {
			s.Intern(&k)
			out[k] = struct{}{}
		}
		c.origins = out
	}
}

func (s *StringDeduper) dedupParams(p *RowParams) {
	if p == nil {
		return
	}
	p.Constants = s.RelocateConstants(p.Constants)
	for _, v := range p.Variables {
		s.Intern(&v.Name)
		s.dedupExpr(v.Expr)
	}
}

func (idx *bitmapIndex) dedupStringsWith(s *StringDeduper) {
	visitedCores := make(map[*FunctionalCore]struct{}, len(idx.coresBySum))
	for _, b := range idx.bindings {
		if b == nil {
			continue
		}
		if b.Core != nil {
			if _, done := visitedCores[b.Core]; !done {
				visitedCores[b.Core] = struct{}{}
				s.dedupCore(b.Core)
			}
		}
	}
}

func (m *Index) DedupStrings(s *StringDeduper) {
	m.bi.dedupStringsWith(s)
	m.handles = s.Handles
}
