// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package printer

import (
	"encoding/json"
	"fmt"
	"io"
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
	enc := json.NewEncoder(p.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(val)
}
