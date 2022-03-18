// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	internalcompile "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/compilation"
	internalerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/lint"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/printer"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/verification"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
)

const help = `
Examples:

# Compile and run tests found in /path/to/policy/repo

cerbos compile /path/to/policy/repo

# Compile and run tests that contain "Delete" in their name

cerbos compile --run=Delete /path/to/policy/repo

# Compile but skip tests

cerbos compile --skip-tests /path/to/policy/repo
`

type Cmd struct {
	Dir           string               `help:"Policy directory" arg:"" required:"" type:"existingdir"`
	Output        flagset.OutputFormat `help:"Output format (${enum})" default:"tree" enum:"tree,list,json" short:"o"`
	Tests         string               `help:"Path to the directory containing tests. Defaults to policy directory." type:"existingdir"`
	RunRegex      string               `help:"Run only tests that match this regex" name:"run"`
	SkipTests     bool                 `help:"Skip tests"`
	IgnoreSchemas bool                 `help:"Ignore schemas during compilation"`
	Verbose       bool                 `help:"Verbose output on test failure"`
	NoColor       bool                 `help:"Disable colored output"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	color.NoColor = c.NoColor
	p := printer.New(k.Stdout, k.Stderr)

	idx, err := index.Build(ctx, os.DirFS(c.Dir))
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return lint.Display(p, idxErr, c.Output, c.NoColor)
		}

		return fmt.Errorf("failed to open directory %s: %w", c.Dir, err)
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})

	enforcement := schema.EnforcementReject
	if c.IgnoreSchemas {
		enforcement = schema.EnforcementNone
	}
	schemaMgr := schema.NewWithConf(ctx, store, schema.NewConf(enforcement))

	if err := compile.BatchCompile(idx.GetAllCompilationUnits(ctx), schemaMgr); err != nil {
		compErr := new(compile.ErrorList)
		if errors.As(err, compErr) {
			return internalcompile.Display(p, *compErr, c.Output, c.NoColor)
		}

		return fmt.Errorf("failed to create engine: %w", err)
	}

	if !c.SkipTests {
		verifyConf := verify.Config{
			TestsDir: c.Tests,
			Run:      c.RunRegex,
			Trace:    c.Verbose,
		}

		if verifyConf.TestsDir == "" {
			verifyConf.TestsDir = c.Dir
		}

		compiler := compile.NewManagerWithDefaultConf(ctx, store, schemaMgr)
		eng, err := engine.NewEphemeral(ctx, compiler, schemaMgr)
		if err != nil {
			return fmt.Errorf("failed to create engine: %w", err)
		}

		results, err := verify.Verify(ctx, eng, verifyConf)
		if err != nil {
			return fmt.Errorf("failed to run tests: %w", err)
		}

		err = verification.Display(p, results, c.Output, c.Verbose, c.NoColor)
		if err != nil {
			return fmt.Errorf("failed to display test results: %w", err)
		}

		switch results.Result {
		case policyv1.TestResults_RESULT_FAILED, policyv1.TestResults_RESULT_ERRORED:
			return internalerrors.ErrTestsFailed
		}
	}

	return nil
}

func (c *Cmd) Help() string {
	return help
}
