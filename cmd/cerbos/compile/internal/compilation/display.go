// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilation

import (
	compileerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

func Display(p *printer.Printer, errs compile.ErrorList, output flagset.OutputFormat, colorLevel outputcolor.Level) error {
	switch output {
	case flagset.OutputFormatJSON:
		return displayJSON(p, errs, colorLevel)
	case flagset.OutputFormatList, flagset.OutputFormatTree:
		return displayList(p, errs)
	}

	return compileerrors.ErrFailed
}

func displayJSON(p *printer.Printer, errs compile.ErrorList, colorLevel outputcolor.Level) error {
	if err := p.PrintJSON(map[string]compile.ErrorList{"compileErrors": errs}, colorLevel); err != nil {
		return err
	}

	return compileerrors.ErrFailed
}

func displayList(p *printer.Printer, errs compile.ErrorList) error {
	p.Println(colored.Header("Compilation errors"))
	for _, err := range errs.Errors {
		p.Printf("%s %s <%s>\n", colored.Position(err.GetFile(), err.GetPosition()), colored.ErrorMsg(err.GetDescription()), err.GetError())
		if ctx := err.GetContext(); ctx != "" {
			p.Println(ctx)
		}
		p.Println()
	}

	return compileerrors.ErrFailed
}
