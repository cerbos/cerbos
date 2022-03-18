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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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

func (p *Printer) coloredJSON(data string) error {
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

	iterator, err := lexer.Tokenise(nil, data)
	if err != nil {
		return fmt.Errorf("failed to tokenise json: %w", err)
	}

	return formatter.Format(p.stdout, styles.SolarizedDark256, iterator)
}

func (p *Printer) PrintJSON(val interface{}, noColor bool) error {
	var data bytes.Buffer
	var enc *json.Encoder
	if noColor {
		enc = json.NewEncoder(p.stdout)
	} else {
		enc = json.NewEncoder(&data)
	}

	enc.SetIndent("", "  ")
	if err := enc.Encode(val); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	if !noColor {
		return p.coloredJSON(data.String())
	}

	return nil
}

func (p *Printer) PrintProtoJSON(message proto.Message, noColor bool) error {
	data, err := protojson.MarshalOptions{Multiline: true}.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	output := fmt.Sprintf("%s\n", data)

	if !noColor {
		return p.coloredJSON(output)
	}

	fmt.Fprint(p.stdout, output)
	return nil
}
