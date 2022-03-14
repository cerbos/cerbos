// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilation

import (
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/colored"
	internalerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/printer"
	"github.com/cerbos/cerbos/internal/compile"
)

func Display(p *printer.Printer, errs compile.ErrorList, output flagset.OutputFormat) error {
	switch output {
	case flagset.OutputFormatJSON:
		return displayJSON(p, errs)
	case flagset.OutputFormatList, flagset.OutputFormatTree:
		return displayPretty(p, errs)
	}

	return internalerrors.ErrFailed
}

func displayJSON(p *printer.Printer, errs compile.ErrorList) error {
	if err := p.PrintJSON(map[string]compile.ErrorList{"compileErrors": errs}); err != nil {
		return err
	}

	return internalerrors.ErrFailed
}

func displayPretty(p *printer.Printer, errs compile.ErrorList) error {
	p.Println(colored.Header("Compilation errors"))
	for _, err := range errs {
		p.Printf("%s: %s (%s)\n", colored.FileName(err.File), colored.ErrorMsg(err.Description), err.Err.Error())
	}

	return internalerrors.ErrFailed
}
