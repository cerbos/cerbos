// Copyright 2021-2025 Zenauth Ltd.
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
	compileerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/errors"
	internalcompile "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/compilation"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/lint"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/verification"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/ruletable"
	internalschema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/verify"
)

const (
	help = `
Examples:

# Compile and run tests found in /path/to/policy/repo

cerbos compile /path/to/policy/repo

# Compile and run tests that contain "Delete" in their name

cerbos compile --run=Delete /path/to/policy/repo

# Compile but skip tests

cerbos compile --skip-tests /path/to/policy/repo
`
)

type Cmd struct { //nolint:govet // Kong prints fields in order, so we don't want to reorder fields to save bytes.
	Dir           string                            `help:"Policy directory" arg:"" required:"" type:"path"`
	IgnoreSchemas bool                              `help:"Ignore schemas during compilation"`
	Tests         string                            `help:"[Deprecated] Path to the directory containing tests. Defaults to policy directory." type:"path"`
	RunRegexp     string                            `help:"Run only tests that match this regex" name:"run"`
	SkipTests     bool                              `help:"Skip tests"`
	Output        flagset.OutputFormat              `help:"Output format (${enum})" default:"tree" enum:"tree,list,json" short:"o"`
	TestOutput    *flagset.VerificationOutputFormat `help:"Test output format. If unspecified matches the value of the output flag. (tree,list,json,junit)"`
	Color         *outputcolor.Level                `help:"Output color level (auto,never,always,256,16m). Defaults to auto." xor:"color"`
	NoColor       bool                              `help:"Disable colored output" xor:"color"`
	Verbose       bool                              `help:"Verbose output on test failure"`
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
		return fmt.Errorf("failed to open policy repository at %q: %w", c.Dir, err)
	}

	idx, err := index.Build(ctx, fsys, index.WithBuildFailureLogLevel(zap.DebugLevel))
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return lint.Display(p, idxErr, c.Output, colorLevel)
		}

		return fmt.Errorf("failed to load policy repository at %q: %w", c.Dir, err)
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	defer store.Close()

	enforcement := internalschema.EnforcementReject
	if c.IgnoreSchemas {
		enforcement = internalschema.EnforcementNone
	}
	schemaMgr := internalschema.NewFromConf(ctx, store, internalschema.NewConf(enforcement))

	if err := compile.BatchCompile(idx.GetAllCompilationUnits(ctx), schemaMgr); err != nil {
		compErr := new(compile.ErrorSet)
		if errors.As(err, &compErr) {
			return internalcompile.Display(p, *compErr, c.Output, colorLevel)
		}

		return fmt.Errorf("failed to compile policies: %w", err)
	}

	if c.TestOutput == nil {
		var value flagset.VerificationOutputFormat
		switch c.Output {
		case flagset.OutputFormatTree:
			value = flagset.VerificationOutputFormatTree
		case flagset.OutputFormatList:
			value = flagset.VerificationOutputFormatList
		case flagset.OutputFormatJSON:
			value = flagset.VerificationOutputFormatJSON
		}
		c.TestOutput = &value
	}

	if !c.SkipTests {
		verifyConf := verify.Config{
			IncludedTestNamesRegexp: c.RunRegexp,
			Trace:                   c.Verbose,
		}

		rt := ruletable.NewRuletable()

		rtMgr, err := ruletable.NewRuleTableManager(rt, nil, schemaMgr)
		if err != nil {
			return fmt.Errorf("failed to create ruletable manager: %w", err)
		}

		eng := engine.NewEphemeral(nil, rtMgr, schemaMgr)

		testFsys, testDir, err := c.testsDir()
		if err != nil {
			return err
		}

		results, err := verify.Verify(ctx, testFsys, eng, verifyConf)
		if err != nil {
			return fmt.Errorf("failed to run tests from %q: %w", testDir, err)
		}

		if err = verification.Display(p, results, *c.TestOutput, c.Verbose, colorLevel); err != nil {
			return fmt.Errorf("failed to display test results: %w", err)
		}

		switch results.Summary.OverallResult {
		case policyv1.TestResults_RESULT_FAILED, policyv1.TestResults_RESULT_ERRORED:
			return compileerrors.ErrTestsFailed
		default:
		}
	}

	return nil
}

func (c *Cmd) testsDir() (fs.FS, string, error) {
	dir := c.Dir
	if c.Tests != "" {
		dir = c.Tests
	}

	fsys, err := util.OpenDirectoryFS(dir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open tests directory at %q: %w", dir, err)
	}
	return fsys, dir, nil
}

func (c *Cmd) Help() string {
	return help
}
