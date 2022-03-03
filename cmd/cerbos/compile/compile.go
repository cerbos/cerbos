// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
)

var (
	// ErrFailed is the error returned when compilation fails.
	ErrFailed = errors.New("failed to compile")
	// ErrTestsFailed is the error returned when tests fail.
	ErrTestsFailed = errors.New("tests failed")

	header         = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	fileName       = color.New(color.FgHiCyan).SprintFunc()
	errorMsg       = color.New(color.FgHiRed).SprintFunc()
	testName       = color.New(color.FgHiBlue, color.Bold).SprintFunc()
	skippedTest    = color.New(color.FgHiWhite).SprintFunc()
	failedTest     = color.New(color.FgHiRed).SprintFunc()
	successfulTest = color.New(color.FgHiGreen).SprintFunc()
)

const (
	formatJSON  = "json"
	formatPlain = "plain"
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
	Dir           string `help:"Policy directory" arg:"" required:"" type:"existingdir"`
	Format        string `help:"Output format (${enum})" default:"pretty" enum:"pretty,plain,json" short:"f"`
	Tests         string `help:"Path to the directory containing tests. Defaults to policy directory." type:"existingdir"`
	RunRegex      string `help:"Run only tests that match this regex" name:"run"`
	SkipTests     bool   `help:"Skip tests"`
	IgnoreSchemas bool   `help:"Ignore schemas during compilation"`
	Verbose       bool   `help:"Verbose output on test failure"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	p := &printer{format: c.Format, verbose: c.Verbose, stdout: k.Stdout, stderr: k.Stderr}

	idx, err := index.Build(ctx, os.DirFS(c.Dir))
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return displayLintErrors(p, idxErr)
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
			return displayCompileErrors(p, *compErr)
		}

		return fmt.Errorf("failed to create engine: %w", err)
	}

	if !c.SkipTests {
		verifyConf := verify.Config{
			TestsDir: c.Tests,
			Run:      c.RunRegex,
		}

		if verifyConf.TestsDir == "" {
			verifyConf.TestsDir = c.Dir
		}

		compiler := compile.NewManagerWithDefaultConf(ctx, store, schemaMgr)
		eng, err := engine.NewEphemeral(ctx, compiler, schemaMgr)
		if err != nil {
			return fmt.Errorf("failed to create engine: %w", err)
		}

		result, err := verify.Verify(ctx, eng, verifyConf)
		if err != nil {
			return fmt.Errorf("failed to run tests: %w", err)
		}

		return displayVerificationResult(p, result)
	}

	return nil
}

func (c *Cmd) Help() string {
	return help
}

type printer struct {
	stdout  io.Writer
	stderr  io.Writer
	format  string
	verbose bool
}

func (p *printer) Println(args ...interface{}) {
	fmt.Fprintln(p.stdout, args...)
}

func (p *printer) Printf(format string, args ...interface{}) {
	fmt.Fprintf(p.stdout, format, args...)
}

func (p *printer) OutOrStdout() io.Writer {
	return p.stdout
}

func displayLintErrors(p *printer, errs *index.BuildError) error {
	switch p.format {
	case formatJSON:
		if err := outputJSON(p, map[string]*index.BuildError{"lintErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case formatPlain:
		color.NoColor = true
	}

	if len(errs.DuplicateDefs) > 0 {
		p.Println(header("Duplicate definitions"))
		for _, dd := range errs.DuplicateDefs {
			p.Printf("%s is a duplicate of %s\n", fileName(dd.File), fileName(dd.OtherFile))
		}
		p.Println()
	}

	if len(errs.MissingImports) > 0 {
		p.Println(header("Missing Imports"))
		for _, mi := range errs.MissingImports {
			p.Printf("%s: %s\n", fileName(mi.ImportingFile), errorMsg(mi.Desc))
		}
		p.Println()
	}

	if len(errs.LoadFailures) > 0 {
		p.Println(header("Load failures"))
		for _, lf := range errs.LoadFailures {
			p.Printf("%s: %s\n", fileName(lf.File), errorMsg(lf.Err.Error()))
		}
		p.Println()
	}

	if len(errs.MissingScopes) > 0 {
		p.Println(header("Missing Scopes"))
		for _, mi := range errs.MissingScopes {
			p.Println(errorMsg(mi))
		}
		p.Println()
	}

	if len(errs.Disabled) > 0 {
		p.Println(header("Disabled policies"))
		for _, d := range errs.Disabled {
			p.Println(fileName(d))
		}
		p.Println()
	}

	return ErrFailed
}

func displayCompileErrors(p *printer, errs compile.ErrorList) error {
	switch p.format {
	case formatJSON:
		if err := outputJSON(p, map[string]compile.ErrorList{"compileErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case formatPlain:
		color.NoColor = true
	}

	p.Println(header("Compilation errors"))
	for _, err := range errs {
		p.Printf("%s: %s (%s)\n", fileName(err.File), errorMsg(err.Description), err.Err.Error())
	}

	return ErrFailed
}

func displayVerificationResult(p *printer, result *verify.Result) error {
	switch p.format {
	case formatJSON:
		if err := outputJSON(p, result); err != nil {
			return err
		}

		if result.Failed {
			return ErrFailed
		}

		return nil
	case formatPlain:
		color.NoColor = true
	}

	p.Println(header("Test results"))
	for _, sr := range result.Results {
		p.Printf("= %s %s ", testName(sr.Suite), fileName("(", sr.File, ")"))
		if sr.Failed {
			p.Println(failedTest("[FAILED]"))
			continue
		}

		if sr.Skipped {
			p.Println(skippedTest("[SKIPPED]"))
			continue
		}

		p.Println()
		for _, tr := range sr.Tests {
			p.Printf("== %s ", testName(tr.Name.String()))
			if tr.Skipped {
				p.Println(skippedTest("[SKIPPED]"))
				continue
			}

			if tr.Failed {
				p.Println(failedTest("[FAILED]"))
				p.Printf("\tError: %s\n", tr.Error)
				if p.verbose {
					p.Printf("\tTrace: \n%s\n", tr.EngineTrace)
				}
				continue
			}

			p.Println(successfulTest("[OK]"))
		}
		if sr.Failed {
			p.Println(errorMsg("Invalid test suite"))
		}
	}

	if result.Failed {
		return ErrTestsFailed
	}

	return nil
}

func outputJSON(p *printer, val interface{}) error {
	enc := json.NewEncoder(p.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(val)
}
