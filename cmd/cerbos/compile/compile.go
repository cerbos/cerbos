// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/pterm/pterm"
	"go.uber.org/zap"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	internalcompile "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/compilation"
	internalerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/lint"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/verification"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
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

type Cmd struct { //nolint:govet // Kong prints fields in order, so we don't want to reorder fields to save bytes.
	Dir           string               `help:"Policy directory" arg:"" required:"" type:"existingdir"`
	IgnoreSchemas bool                 `help:"Ignore schemas during compilation"`
	Tests         string               `help:"Path to the directory containing tests. Defaults to policy directory." type:"existingdir"`
	RunRegex      string               `help:"Run only tests that match this regex" name:"run"`
	SkipTests     bool                 `help:"Skip tests"`
	Output        flagset.OutputFormat `help:"Output format (${enum})" default:"tree" enum:"tree,list,json" short:"o"`
	Color         *outputcolor.Level   `help:"Output color level (auto,never,always,256,16m). Defaults to auto." xor:"color"`
	NoColor       bool                 `help:"Disable colored output" xor:"color"`
	Verbose       bool                 `help:"Verbose output on test failure"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	colorLevel := c.Color.Resolve(c.NoColor)

	color.NoColor = !colorLevel.Enabled()

	if colorLevel.Enabled() {
		pterm.EnableColor()
	} else {
		pterm.DisableColor()
	}

	p := printer.New(k.Stdout, k.Stderr)

	fsys, err := util.OpenDirectoryFS(c.Dir)
	if err != nil {
		return err
	}

	idx, err := index.Build(ctx, fsys, index.WithBuildFailureLogLevel(zap.DebugLevel))
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return lint.Display(p, idxErr, c.Output, colorLevel)
		}

		return fmt.Errorf("failed to open directory %s: %w", c.Dir, err)
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})

	enforcement := schema.EnforcementReject
	if c.IgnoreSchemas {
		enforcement = schema.EnforcementNone
	}
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(enforcement))

	if err := compile.BatchCompile(idx.GetAllCompilationUnits(ctx), schemaMgr); err != nil {
		compErr := new(compile.ErrorList)
		if errors.As(err, &compErr) {
			return internalcompile.Display(p, *compErr, c.Output, colorLevel)
		}

		return fmt.Errorf("failed to create engine: %w", err)
	}

	if !c.SkipTests {
		verifyConf := verify.Config{
			Run:   c.RunRegex,
			Trace: c.Verbose,
		}

		compiler := compile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
		eng, err := engine.NewEphemeral(compiler, schemaMgr)
		if err != nil {
			return fmt.Errorf("failed to create engine: %w", err)
		}

		testFsys, err := c.testsDir()
		if err != nil {
			return err
		}
		results, err := verify.Verify(ctx, testFsys, eng, verifyConf)
		if err != nil {
			return fmt.Errorf("failed to run tests: %w", err)
		}

		err = verification.Display(p, results, c.Output, c.Verbose, colorLevel)
		if err != nil {
			return fmt.Errorf("failed to display test results: %w", err)
		}

		switch results.Summary.OverallResult {
		case policyv1.TestResults_RESULT_FAILED, policyv1.TestResults_RESULT_ERRORED:
			return internalerrors.ErrTestsFailed
		default:
		}
	}

	return nil
}

func (c *Cmd) testsDir() (fs.FS, error) {
	if c.Tests == "" {
		return util.OpenDirectoryFS(c.Dir)
	}

	return util.OpenDirectoryFS(c.Tests)
}

func (c *Cmd) Help() string {
	return help
}
