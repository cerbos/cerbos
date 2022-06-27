// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package lint

import (
	internalerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
	"github.com/cerbos/cerbos/internal/storage/index"
)

func Display(p *printer.Printer, errs *index.BuildError, output flagset.OutputFormat, colorLevel outputcolor.Level) error {
	switch output {
	case flagset.OutputFormatJSON:
		return displayJSON(p, errs, colorLevel)
	case flagset.OutputFormatList, flagset.OutputFormatTree:
		return displayList(p, errs)
	}

	return internalerrors.ErrFailed
}

func displayJSON(p *printer.Printer, errs *index.BuildError, colorLevel outputcolor.Level) error {
	if err := p.PrintJSON(map[string]*index.BuildError{"lintErrors": errs}, colorLevel); err != nil {
		return err
	}

	return internalerrors.ErrFailed
}

func displayList(p *printer.Printer, errs *index.BuildError) error {
	if len(errs.DuplicateDefs) > 0 {
		p.Println(colored.Header("Duplicate definitions"))
		for _, dd := range errs.DuplicateDefs {
			p.Printf("%s is a duplicate of %s\n", colored.FileName(dd.File), colored.FileName(dd.OtherFile))
		}
		p.Println()
	}

	if len(errs.MissingImports) > 0 {
		p.Println(colored.Header("Missing Imports"))
		for _, mi := range errs.MissingImports {
			p.Printf("%s: %s\n", colored.FileName(mi.ImportingFile), colored.ErrorMsg(mi.Desc))
		}
		p.Println()
	}

	if len(errs.LoadFailures) > 0 {
		p.Println(colored.Header("Load failures"))
		for _, lf := range errs.LoadFailures {
			p.Printf("%s: %s\n", colored.FileName(lf.File), colored.ErrorMsg(lf.Error))
		}
		p.Println()
	}

	if len(errs.MissingScopes) > 0 {
		p.Println(colored.Header("Missing Scopes"))
		for _, mi := range errs.MissingScopes {
			p.Println(colored.ErrorMsg(mi))
		}
		p.Println()
	}

	if len(errs.Disabled) > 0 {
		p.Println(colored.Header("Disabled policies"))
		for _, d := range errs.Disabled {
			p.Println(colored.FileName(d))
		}
		p.Println()
	}

	return internalerrors.ErrFailed
}
