// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package repl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/peterh/liner"
)

var errExit = errors.New("exit")

type Cmd struct {
	History string `help:"Path to history file" type:"path"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	histFile := getHistoryFile(c.History)

	reader := liner.NewLiner()
	defer func() {
		if err := writeHistory(reader, histFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to persist history: %v", err)
		}

		_ = reader.Close()
	}()

	if err := loadHistory(reader, histFile); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read history: %v", err)
	}

	return repl(reader)
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

func repl(reader *liner.State) error {
	for {
		line, err := reader.Prompt("> ")
		if err != nil && !errors.Is(err, io.EOF) {
			printErr("Error reading input", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch line[0] {
		case ':':
			if err := processCmd(line); err != nil {
				if errors.Is(err, errExit) {
					return nil
				}

				printErr("Failed to parse command", err)
			}
		case '#':
			continue
		default:
			processExpr(line)
		}
	}
}

func printErr(msg string, err error) {
	fmt.Printf("ERROR: %s\n", msg)
	if err != nil {
		fmt.Printf("  cause: %v", err)
	}
}

func processCmd(line string) error {
	cmd := strings.TrimPrefix(line, ":")
	switch cmd {
	case "q", "quit", "exit":
		return errExit
	default:
		return nil

	}
}

func processExpr(line string) error {
	return nil
}
