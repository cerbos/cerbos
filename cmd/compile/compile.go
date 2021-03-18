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

	"github.com/charithe/menshen/pkg/compile"
	"github.com/charithe/menshen/pkg/engine"
	"github.com/charithe/menshen/pkg/storage/disk"
)

var (
	ErrFailed = errors.New("failed to compile")

	header   = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	fileName = color.New(color.FgHiCyan).SprintFunc()
	errorMsg = color.New(color.FgHiRed).SprintFunc()

	format string
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

	return cmd
}

func doRun(cmd *cobra.Command, args []string) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	store, err := disk.NewReadOnlyStore(ctx, args[0])
	if err != nil {
		idxErr := new(disk.IndexBuildError)
		if errors.As(err, &idxErr) {
			return displayLintErrors(cmd, idxErr)
		}

		return fmt.Errorf("failed to open directory %s: %w", args[0], err)
	}

	_, err = engine.New(ctx, store)
	if err != nil {
		compErr := new(compile.ErrorList)
		if errors.As(err, compErr) {
			return displayCompileErrors(cmd, *compErr)
		}

		return fmt.Errorf("failed to create engine: %w", err)
	}

	return nil
}

func displayLintErrors(cmd *cobra.Command, errs *disk.IndexBuildError) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]*disk.IndexBuildError{"lintErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case "plain":
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
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]compile.ErrorList{"compileErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case "plain":
		color.NoColor = true
	}

	cmd.Println(header("Compilation errors"))
	for _, err := range errs {
		cmd.Printf("%s: %s (%s)\n", fileName(err.File), errorMsg(err.Description), err.Err.Error())
	}

	return ErrFailed
}
