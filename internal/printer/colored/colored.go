// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package colored

import (
	"fmt"

	"github.com/fatih/color"

	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
)

var (
	Action                  = color.New(color.FgYellow).SprintFunc()
	ErrorMsg                = color.New(color.FgRed).SprintFunc()
	ErroredTest             = color.New(color.FgRed).SprintFunc()
	FailedTest              = color.New(color.FgRed).SprintFunc()
	FileName                = color.New(color.FgBlue).SprintFunc()
	Header                  = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	LineAndCol              = color.New(color.FgGreen).SprintFunc()
	PassedTest              = color.New(color.FgGreen).SprintFunc()
	PolicyKey               = color.New(color.FgCyan).SprintFunc()
	Principal               = color.New(color.FgCyan).SprintFunc()
	REPLCmd                 = color.New(color.FgYellow).SprintFunc()
	REPLError               = color.New(color.FgRed).SprintFunc()
	REPLExpr                = color.New(color.FgCyan).SprintFunc()
	REPLPolicyName          = color.New(color.FgCyan).SprintFunc()
	REPLRule                = color.New(color.FgCyan, color.Bold).SprintFunc()
	REPLSuccess             = color.New(color.FgGreen).SprintFunc()
	REPLVar                 = color.New(color.FgCyan).SprintFunc()
	Resource                = color.New(color.FgBlue).SprintFunc()
	SkippedTest             = color.New(color.FgHiWhite).SprintFunc()
	Suite                   = color.New(color.FgBlue, color.Bold).SprintFunc()
	TestCase                = color.New(color.FgBlue).SprintFunc()
	TestOutputSrc           = color.New(color.FgBlue).SprintFunc()
	TestOutputVal           = color.New(color.FgBlue).SprintFunc()
	Trace                   = color.New(color.FgHiWhite).SprintFunc()
	TraceComponentKey       = color.New(color.FgBlue).SprintFunc()
	TraceComponentSeparator = color.New(color.FgHiBlack).SprintFunc()
	TraceEventActivated     = color.New(color.FgGreen).SprintFunc()
	TraceEventEffectAllow   = color.New(color.FgGreen).SprintFunc()
	TraceEventEffectDeny    = color.New(color.FgRed).SprintFunc()
	TraceEventSkipped       = color.New(color.FgHiWhite).SprintFunc()
)

func Position(file string, position *sourcev1.Position) string {
	if position == nil {
		return FileName(file)
	}

	return fmt.Sprintf("%s:%s:%s", FileName(file), LineAndCol(position.GetLine()), LineAndCol(position.GetColumn()))
}
