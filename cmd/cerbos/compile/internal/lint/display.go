// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package lint

import (
	"strings"

	compileerrors "github.com/cerbos/cerbos/cmd/cerbos/compile/errors"
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

	return compileerrors.ErrFailed
}

func displayJSON(p *printer.Printer, errs *index.BuildError, colorLevel outputcolor.Level) error {
	if err := p.PrintJSON(map[string]*index.BuildError{"lintErrors": errs}, colorLevel); err != nil {
		return err
	}

	return compileerrors.ErrFailed
}

func displayList(p *printer.Printer, errs *index.BuildError) error {
	if len(errs.DisabledDefs) > 0 {
		p.Println(colored.Header("Disabled policies"))
		for _, d := range errs.DisabledDefs {
			p.Printf("%s %s\n", colored.Position(d.GetFile(), d.GetPosition()), colored.PolicyKey(d.GetPolicy()))
		}
		p.Println()
	}

	if len(errs.MissingScopeDetails) > 0 {
		p.Println(colored.Header("Missing scopes"))
		for _, missingScopes := range errs.MissingScopeDetails {
			p.Printf(
				"scoped policy %s is not found but is required by descendant policies %s\n",
				colored.ErrorMsg(missingScopes.MissingPolicy),
				colored.PolicyKey(strings.Join(missingScopes.Descendants, ", ")),
			)
		}
		p.Println()
	}

	if len(errs.DuplicateDefs) > 0 {
		p.Println(colored.Header("Duplicate definitions"))
		for _, dd := range errs.DuplicateDefs {
			p.Printf("%s duplicate definition of %s (previous definition in %s)\n", colored.Position(dd.GetFile(), dd.GetPosition()), colored.PolicyKey(dd.GetPolicy()), colored.FileName(dd.OtherFile))
		}
		p.Println()
	}

	if len(errs.MissingImports) > 0 {
		p.Println(colored.Header("Missing imports"))
		for _, mi := range errs.MissingImports {
			p.Printf("%s cannot find %s %q imported by %s\n", colored.Position(mi.GetImportingFile(), mi.GetPosition()), mi.ImportKind, mi.ImportName, colored.PolicyKey(mi.ImportingPolicy))
			if c := mi.GetContext(); c != "" {
				p.Println(c)
				p.Println()
			}
		}
		p.Println()
	}

	if len(errs.LoadFailures) > 0 {
		p.Println(colored.Header("Load failures"))
		for _, lf := range errs.LoadFailures {
			if d := lf.GetErrorDetails(); d != nil {
				p.Printf("%s %s\n", colored.Position(lf.GetFile(), d.GetPosition()), colored.ErrorMsg(d.GetMessage()))
				if d.GetContext() != "" {
					p.Println(d.GetContext())
					p.Println()
				}
			} else {
				p.Printf("%s %s\n", colored.FileName(lf.GetFile()), colored.ErrorMsg(d.GetMessage()))
			}
		}
		p.Println()
	}

	if len(errs.ScopePermissionsConflicts) > 0 {
		p.Println(colored.Header("Scope permission conflicts"))
		for _, spc := range errs.ScopePermissionsConflicts {
			p.Printf("policies sharing scope %s have conflicting scopePermissions\n", spc.Scope)
		}
		p.Println()
	}

	return compileerrors.ErrFailed
}
