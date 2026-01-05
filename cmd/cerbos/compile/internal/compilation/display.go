// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilation

import (
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	compileerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

func Display(p *printer.Printer, errs compile.ErrorSet, output flagset.OutputFormat, colorLevel outputcolor.Level) error {
	switch output {
	case flagset.OutputFormatJSON:
		return displayJSON(p, errs, colorLevel)
	case flagset.OutputFormatList, flagset.OutputFormatTree:
		return displayList(p, errs)
	}

	return compileerrors.ErrFailed
}

func displayJSON(p *printer.Printer, errs compile.ErrorSet, colorLevel outputcolor.Level) error {
	if err := p.PrintJSON(map[string]*runtimev1.CompileErrors{"compileErrors": errs.Errors()}, colorLevel); err != nil {
		return err
	}

	return compileerrors.ErrFailed
}

func displayList(p *printer.Printer, errs compile.ErrorSet) error {
	p.Println(colored.Header("Compilation errors"))
	errList := errs.Errors().GetErrors()
	for _, err := range errList {
		p.Printf("%s %s <%s>\n", colored.Position(err.GetFile(), err.GetPosition()), colored.ErrorMsg(err.GetDescription()), err.GetError())
		if ctx := err.GetContext(); ctx != "" {
			p.Println(ctx)
		}
		p.Println()
	}

	return compileerrors.ErrFailed
}
