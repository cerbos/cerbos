// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package colored

import "github.com/fatih/color"

var (
	Header                  = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	FileName                = color.New(color.FgCyan).SprintFunc()
	ErrorMsg                = color.New(color.FgRed).SprintFunc()
	SkippedTest             = color.New(color.FgHiWhite).SprintFunc()
	FailedTest              = color.New(color.FgRed).SprintFunc()
	SuccessfulTest          = color.New(color.FgGreen).SprintFunc()
	Suite                   = color.New(color.FgBlue, color.Bold).SprintFunc()
	Principal               = color.New(color.FgCyan).SprintFunc()
	Resource                = color.New(color.FgBlue).SprintFunc()
	Action                  = color.New(color.FgYellow).SprintFunc()
	Trace                   = color.New(color.FgHiWhite).SprintFunc()
	TraceComponentKey       = color.New(color.FgBlue).SprintFunc()
	TraceComponentSeparator = color.New(color.FgHiBlack).SprintFunc()
	TraceEventActivated     = color.New(color.FgGreen).SprintFunc()
	TraceEventSkipped       = color.New(color.FgHiWhite).SprintFunc()
	TraceEventEffectAllow   = color.New(color.FgGreen).SprintFunc()
	TraceEventEffectDeny    = color.New(color.FgRed).SprintFunc()
)
