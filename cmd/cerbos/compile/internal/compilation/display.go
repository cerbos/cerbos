// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilation

import (
	"fmt"

	internalerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
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
	case flagset.OutputFormatJUnit:
		return fmt.Errorf("invalid option %s", flagset.OutputFormatJUnit)
	}

	return internalerrors.ErrFailed
}

func displayJSON(p *printer.Printer, errs compile.ErrorList, colorLevel outputcolor.Level) error {
	if err := p.PrintJSON(map[string]compile.ErrorList{"compileErrors": errs}, colorLevel); err != nil {
		return err
	}

	return internalerrors.ErrFailed
}

func displayList(p *printer.Printer, errs compile.ErrorList) error {
	p.Println(colored.Header("Compilation errors"))
	for _, err := range errs.Errors {
		p.Printf("%s: %s (%s)\n", colored.FileName(err.File), colored.ErrorMsg(err.Description), err.Error)
	}

	return internalerrors.ErrFailed
}
