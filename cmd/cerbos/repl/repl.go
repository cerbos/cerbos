// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package repl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/alecthomas/kong"
	"github.com/peterh/liner"

	"github.com/cerbos/cerbos/cmd/cerbos/repl/internal"
)

type Cmd struct {
	History string `help:"Path to history file" type:"path"`
}

func (c *Cmd) clear(stdout io.Writer) {
	fmt.Fprintf(stdout, "\033[H\033[2J")
}

func (c *Cmd) Run(k *kong.Kong) error {
	c.clear(k.Stdout)

	histFile := getHistoryFile(c.History)

	reader := liner.NewLiner()
	reader.SetCtrlCAborts(true)
	reader.SetMultiLineMode(true)

	defer func() {
		if err := writeHistory(reader, histFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to persist history: %v", err)
		}

		_ = reader.Close()
	}()

	if err := loadHistory(reader, histFile); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read history: %v", err)
	}

	r, err := internal.NewREPL(reader, internal.NewPrinterOutput(k.Stdout, k.Stderr))
	if err != nil {
		return fmt.Errorf("failed to initialize the REPL: %w", err)
	}

	return r.Loop()
}

func getHistoryFile(path string) string {
	if path == "" {
		dir := filepath.Join(xdg.DataHome, "cerbos")
		//nolint:mnd
		if err := os.MkdirAll(dir, 0o744); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create directory %q (%v): history is disabled", dir, err)
			return ""
		}

		return filepath.Join(dir, ".cerbos_repl_history")
	}

	finfo, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "Failed to stat history file %q (%v): history is disabled", path, err)
		return ""
	}

	if finfo != nil && finfo.IsDir() {
		return filepath.Join(path, ".cerbos_repl_history")
	}

	return path
}

func loadHistory(reader *liner.State, histFile string) error {
	if histFile == "" {
		return nil
	}

	f, err := os.Open(histFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}
	defer f.Close()

	_, err = reader.ReadHistory(f)
	return err
}

func writeHistory(reader *liner.State, histFile string) error {
	if histFile == "" {
		return nil
	}

	f, err := os.Create(histFile)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = reader.WriteHistory(f)
	return err
}
