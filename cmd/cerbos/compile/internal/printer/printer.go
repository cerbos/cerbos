// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/jwalton/gchalk"
)

func New(stdout, stderr io.Writer) *Printer {
	return &Printer{stdout: stdout, stderr: stderr}
}

type Printer struct {
	stdout io.Writer
	stderr io.Writer
}

func (p *Printer) Println(args ...interface{}) {
	fmt.Fprintln(p.stdout, args...)
}

func (p *Printer) Printf(format string, args ...interface{}) {
	fmt.Fprintf(p.stdout, format, args...)
}

func (p *Printer) PrintJSON(val interface{}) error {
	lexer := chroma.Coalesce(lexers.Get("json"))
	if lexer == nil {
		lexer = lexers.Fallback
	}

	var formatter chroma.Formatter
	switch gchalk.GetLevel() {
	case gchalk.LevelAnsi256:
		formatter = formatters.TTY256
	case gchalk.LevelAnsi16m:
		formatter = formatters.TTY16m
	default:
		formatter = formatters.TTY
	}

	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetIndent("", "  ")
	if err := enc.Encode(val); err != nil {
		return fmt.Errorf("failed to encode json: %w", err)
	}

	iterator, err := lexer.Tokenise(nil, data.String())
	if err != nil {
		return fmt.Errorf("failed to tokenise json: %w", err)
	}

	return formatter.Format(p.stdout, styles.SolarizedDark256, iterator)
}
