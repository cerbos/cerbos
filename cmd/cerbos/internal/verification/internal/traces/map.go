// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

type Map map[string]*enginev1.TraceBatch

func (m *Map) Add(suiteName, principalName, resourceName, actionName string, batch *enginev1.TraceBatch) {
	if batch == nil || len(batch.Entries) == 0 {
		return
	}

	key := fmt.Sprintf("%s - %s.%s.%s", colored.Suite(suiteName), colored.Principal(principalName), colored.Resource(resourceName), colored.Action(actionName))
	(*m)[key] = batch
}

func (m *Map) Print(p *printer.Printer) {
	if len(*m) == 0 {
		return
	}

	p.Println()
	p.Println(colored.Trace("TRACES"))
	for key, batch := range *m {
		p.Println(key)
		for i, traceEntry := range batch.Entries {
			if i > 0 {
				p.Println()
			}
			p.PrintTraceEntry(batch.Definitions, traceEntry)
		}
		p.Println()
	}
}
