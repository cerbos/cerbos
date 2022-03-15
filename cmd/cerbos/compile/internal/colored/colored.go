// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package colored

import "github.com/fatih/color"

var (
	Header         = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	FileName       = color.New(color.FgHiCyan).SprintFunc()
	ErrorMsg       = color.New(color.FgHiRed).SprintFunc()
	SkippedTest    = color.New(color.FgHiWhite).SprintFunc()
	FailedTest     = color.New(color.FgHiRed).SprintFunc()
	SuccessfulTest = color.New(color.FgHiGreen).SprintFunc()
	Suite          = color.New(color.FgHiBlue, color.Bold).SprintFunc()
	Principal      = color.New(color.FgHiCyan).SprintFunc()
	Resource       = color.New(color.FgHiBlue).SprintFunc()
	Action         = color.New(color.FgYellow).SprintFunc()
	Trace          = color.New(color.FgHiWhite).SprintFunc()
)
