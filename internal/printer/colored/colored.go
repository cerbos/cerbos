// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package colored

import "github.com/fatih/color"

var (
	Action                  = color.New(color.FgYellow).SprintFunc()
	ErrorMsg                = color.New(color.FgRed).SprintFunc()
	ErroredTest             = color.New(color.FgRed).SprintFunc()
	FailedTest              = color.New(color.FgRed).SprintFunc()
	FileName                = color.New(color.FgCyan).SprintFunc()
	Header                  = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	PassedTest              = color.New(color.FgGreen).SprintFunc()
	TestCase                = color.New(color.FgBlue).SprintFunc()
	TestOutputSrc           = color.New(color.FgBlue).SprintFunc()
	TestOutputVal           = color.New(color.FgBlue).SprintFunc()
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
	Trace                   = color.New(color.FgHiWhite).SprintFunc()
	TraceComponentKey       = color.New(color.FgBlue).SprintFunc()
	TraceComponentSeparator = color.New(color.FgHiBlack).SprintFunc()
	TraceEventActivated     = color.New(color.FgGreen).SprintFunc()
	TraceEventEffectAllow   = color.New(color.FgGreen).SprintFunc()
	TraceEventEffectDeny    = color.New(color.FgRed).SprintFunc()
	TraceEventSkipped       = color.New(color.FgHiWhite).SprintFunc()
)
