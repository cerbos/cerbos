// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

type Map map[string]*enginev1.TraceBatch

func (m *Map) Add(suiteName, principalName, resourceName, actionName string, traceBatch *enginev1.TraceBatch) {
	if traceBatch == nil {
		return
	}

	key := fmt.Sprintf("%s - %s.%s.%s", colored.Suite(suiteName), colored.Principal(principalName), colored.Resource(resourceName), colored.Action(actionName))
	(*m)[key] = traceBatch
}

func (m *Map) Print(p *printer.Printer) {
	if len(*m) == 0 {
		return
	}

	p.Println()
	p.Println(colored.Trace("TRACES"))
	for key, traceBatch := range *m {
		definitions := tracer.TraceComponentDefinitionsToMap(traceBatch.Definitions)

		p.Println(key)
		for i, entry := range traceBatch.Entries {
			if i > 0 {
				p.Println()
			}
			p.PrintTrace(definitions, entry)
		}
		p.Println()
	}
}
