// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"

	"github.com/pterm/pterm"

	"github.com/cerbos/cerbos/internal/printer/colored"
)

var errEvalErrorPresent = errors.New("failed expression(s) present")

type evalOutput struct {
	tree  pterm.LeveledList
	level int
}

func (eo *evalOutput) append(text string) {
	eo.tree = append(eo.tree, pterm.LeveledListItem{Level: eo.level, Text: text})
}

func (eo *evalOutput) appendAndLevelUp(text string) {
	eo.append(text)
	eo.level++
}

func buildEvalOutput(e *eval) *evalOutput {
	eo := &evalOutput{level: 0}
	doBuildEvalOutput(eo, e)

	return eo
}

func successText(success bool) string {
	if success {
		return colored.REPLSuccess("true")
	}

	return colored.REPLError("false")
}

func doBuildEvalOutput(eo *evalOutput, e *eval) {
	switch e.evalType {
	case evalTypeExpr:
		eo.append(fmt.Sprintf("%s [%v]", colored.REPLExpr(e.expr), successText(e.success)))
	case evalTypeAny, evalTypeAll, evalTypeNone:
		eo.appendAndLevelUp(fmt.Sprintf("%s [%v]", e.evalType, successText(e.success)))
		for _, ev := range e.evals {
			doBuildEvalOutput(eo, ev)
		}
	}
}

type evalType string

const (
	evalTypeAll  evalType = "all"
	evalTypeAny  evalType = "any"
	evalTypeExpr evalType = "expr"
	evalTypeNone evalType = "none"
)

type eval struct {
	err      error
	evalType evalType
	expr     string
	evals    []*eval
	success  bool
}

func (e *eval) append(eval *eval) {
	e.evals = append(e.evals, eval)

	if eval.err != nil {
		e.err = errEvalErrorPresent
		e.success = false
	}

	if e.err == nil {
		switch e.evalType {
		case evalTypeAll:
			e.success = e.success && eval.success
		case evalTypeAny:
			e.success = e.success || eval.success
		case evalTypeNone:
			e.success = e.success && !eval.success
		default:
			panic(fmt.Errorf("unexpected append to eval of type %q", e.evalType))
		}
	}
}
