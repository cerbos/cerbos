// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
	"github.com/cerbos/cerbos/internal/verify"
)

var (
	// ErrFailed is the error returned when compilation fails.
	ErrFailed = errors.New("failed to compile")

	header         = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	fileName       = color.New(color.FgHiCyan).SprintFunc()
	errorMsg       = color.New(color.FgHiRed).SprintFunc()
	testName       = color.New(color.FgHiBlue, color.Bold).SprintFunc()
	skippedTest    = color.New(color.FgHiWhite).SprintFunc()
	failedTest     = color.New(color.FgHiRed).SprintFunc()
	successfulTest = color.New(color.FgHiGreen).SprintFunc()

	format     string
	verifyConf = verify.Config{}
)

const (
	formatJSON  = "json"
	formatPlain = "plain"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "compile DIR",
		Short:         "Compile the policy files found in the directory",
		RunE:          doRun,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "", "Output format (valid values: json,plain)")
	cmd.Flags().StringVar(&verifyConf.TestsDir, "tests", "", "Path to the directory containing tests")
	cmd.Flags().StringVar(&verifyConf.Run, "run", "", "Run only tests that match this regex")

	return cmd
}

func doRun(cmd *cobra.Command, args []string) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	idx, err := index.Build(ctx, os.DirFS(args[0]), index.WithMemoryCache())
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return displayLintErrors(cmd, idxErr)
		}

		return fmt.Errorf("failed to open directory %s: %w", args[0], err)
	}

	if err := compile.BatchCompile(idx.GetAllCompilationUnits(ctx)); err != nil {
		compErr := new(compile.ErrorList)
		if errors.As(err, compErr) {
			return displayCompileErrors(cmd, *compErr)
		}

		return fmt.Errorf("failed to create engine: %w", err)
	}

	if verifyConf.TestsDir != "" {
		compiler := compile.NewManager(ctx, disk.NewFromIndex(idx))
		eng, err := engine.NewEphemeral(ctx, compiler)
		if err != nil {
			return fmt.Errorf("failed to create engine: %w", err)
		}

		result, err := verify.Verify(ctx, eng, verifyConf)
		if err != nil {
			return fmt.Errorf("failed to run tests: %w", err)
		}

		return displayVerificationResult(cmd, result)
	}

	return nil
}

func displayLintErrors(cmd *cobra.Command, errs *index.BuildError) error {
	switch strings.ToLower(format) {
	case formatJSON:
		if err := outputJSON(cmd, map[string]*index.BuildError{"lintErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case formatPlain:
		color.NoColor = true
	}

	if len(errs.DuplicateDefs) > 0 {
		cmd.Println(header("Duplicate definitions"))
		for _, dd := range errs.DuplicateDefs {
			cmd.Printf("%s is a duplicate of %s\n", fileName(dd.File), fileName(dd.OtherFile))
		}
		cmd.Println()
	}

	if len(errs.MissingImports) > 0 {
		cmd.Println(header("Missing Imports"))
		for _, mi := range errs.MissingImports {
			cmd.Printf("%s: %s\n", fileName(mi.ImportingFile), errorMsg(mi.Desc))
		}
		cmd.Println()
	}

	if len(errs.LoadFailures) > 0 {
		cmd.Println(header("Load failures"))
		for _, lf := range errs.LoadFailures {
			cmd.Printf("%s: %s\n", fileName(lf.File), errorMsg(lf.Err.Error()))
		}
		cmd.Println()
	}

	if len(errs.CodegenFailures) > 0 {
		cmd.Println(header("Code generation failures"))
		for _, cf := range errs.CodegenFailures {
			cmd.Printf("%s: %s\n", fileName(cf.File), errorMsg(cf.Err.Error()))
		}
		cmd.Println()
	}

	if len(errs.Disabled) > 0 {
		cmd.Println(header("Disabled policies"))
		for _, d := range errs.Disabled {
			cmd.Println(fileName(d))
		}
		cmd.Println()
	}

	return ErrFailed
}

func displayCompileErrors(cmd *cobra.Command, errs compile.ErrorList) error {
	switch strings.ToLower(format) {
	case formatJSON:
		if err := outputJSON(cmd, map[string]compile.ErrorList{"compileErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case formatPlain:
		color.NoColor = true
	}

	cmd.Println(header("Compilation errors"))
	for _, err := range errs {
		cmd.Printf("%s: %s (%s)\n", fileName(err.File), errorMsg(err.Description), err.Err.Error())
	}

	return ErrFailed
}

func displayVerificationResult(cmd *cobra.Command, result *verify.Result) error {
	switch strings.ToLower(format) {
	case formatJSON:
		if err := outputJSON(cmd, result); err != nil {
			return err
		}

		if result.Failed {
			return ErrFailed
		}

		return nil
	case formatPlain:
		color.NoColor = true
	}

	cmd.Println(header("Test results"))
	for _, sr := range result.Results {
		cmd.Printf("= %s %s ", testName(sr.Suite), fileName("(", sr.File, ")"))
		if sr.Skipped {
			cmd.Println(skippedTest("[SKIPPED]"))
			continue
		}

		cmd.Println()
		for _, tr := range sr.Tests {
			cmd.Printf("== %s ", testName(tr.Name.String()))
			if tr.Skipped {
				cmd.Println(skippedTest("[SKIPPED]"))
				continue
			}

			if tr.Failed {
				cmd.Println(failedTest("[FAILED]"))
				cmd.Printf("\tError: %s\n", tr.Error)
				continue
			}

			cmd.Println(successfulTest("[OK]"))
		}
	}

	if result.Failed {
		return ErrFailed
	}

	return nil
}

func outputJSON(cmd *cobra.Command, val interface{}) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(val)
}
