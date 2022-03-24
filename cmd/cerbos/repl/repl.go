// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package repl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos/cmd/cerbos/repl/internal"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/peterh/liner"
)

type Cmd struct {
	History string `help:"Path to history file" type:"path"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	histFile := getHistoryFile(c.History)

	reader := liner.NewLiner()
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

	r, err := internal.NewREPL(reader, printer.New(k.Stdout, k.Stderr))
	if err != nil {
		return fmt.Errorf("failed to initialize the REPL: %w", err)
	}

	return r.Loop()
}

func getHistoryFile(path string) string {
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return ""
		}

		return filepath.Join(homeDir, ".cerbos_history")
	}

	finfo, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ""
	}

	if finfo != nil && finfo.IsDir() {
		return filepath.Join(path, ".cerbos_history")
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
