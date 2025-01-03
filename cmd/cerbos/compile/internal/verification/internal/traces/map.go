// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

type Map map[string][]*enginev1.Trace

func (m *Map) Add(suiteName, principalName, resourceName, actionName string, traces []*enginev1.Trace) {
	if len(traces) == 0 {
		return
	}

	key := fmt.Sprintf("%s - %s.%s.%s", colored.Suite(suiteName), colored.Principal(principalName), colored.Resource(resourceName), colored.Action(actionName))
	(*m)[key] = traces
}

func (m *Map) Print(p *printer.Printer) {
	if len(*m) == 0 {
		return
	}

	p.Println()
	p.Println(colored.Trace("TRACES"))
	for key, traces := range *m {
		p.Println(key)
		for i, trace := range traces {
			if i > 0 {
				p.Println()
			}
			p.PrintTrace(trace)
		}
		p.Println()
	}
}
