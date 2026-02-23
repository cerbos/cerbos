// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build printsummary

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bojand/ghz/printer"
	"github.com/bojand/ghz/runner"
)

func main() {
	var report runner.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode report: %v\n", err)
		os.Exit(1)
	}
	p := printer.ReportPrinter{Out: os.Stdout, Report: &report}
	if err := p.Print("summary"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to print summary: %v\n", err)
		os.Exit(1)
	}
}
