// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilestore

import (
	"github.com/cerbos/cerbos/cmd/cerbos/internal/flagset"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

func display(p *printer.Printer, format flagset.Format, colorLevel outputcolor.Level, policyKeys map[string][]errWithDesc) error {
	switch format.Output {
	case flagset.OutputFormatJSON:
		return displayJSON(p, colorLevel, policyKeys)
	case flagset.OutputFormatList, flagset.OutputFormatTree:
		return displayList(p, policyKeys)
	default:
		return nil
	}
}

func displayJSON(p *printer.Printer, colorLevel outputcolor.Level, policyKeys map[string][]errWithDesc) error {
	if err := p.PrintJSON(map[string]map[string][]errWithDesc{
		"disabledInvalidPolicies": policyKeys,
	}, colorLevel); err != nil {
		return err
	}

	return nil
}

func displayList(p *printer.Printer, policyKeys map[string][]errWithDesc) error {
	p.Println(colored.Header("Disabled invalid policies"))
	for policyKey, errs := range policyKeys {
		for _, err := range errs {
			if err.Description != "" {
				p.Printf("%s %s <%s>\n", colored.PolicyKey(policyKey), colored.ErrorMsg(err.Description), err.Err)
				continue
			}

			p.Printf("%s <%s>\n", colored.PolicyKey(policyKey), err.Err)
		}
	}

	return nil
}
