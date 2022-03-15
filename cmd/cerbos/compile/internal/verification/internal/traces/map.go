// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"fmt"

	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/colored"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/printer"
)

type Map map[string]string

func (m *Map) Add(suiteName, principalName, resourceName, actionName, trace string) {
	key := fmt.Sprintf("%s - %s.%s.%s", colored.Suite(suiteName), colored.Principal(principalName), colored.Resource(resourceName), colored.Action(actionName))
	ptr := *m
	ptr[key] = trace
}

func (m *Map) Print(p *printer.Printer) {
	if len(*m) == 0 {
		return
	}
	p.Println()
	p.Println(colored.Trace("TRACES"))
	for key, trace := range *m {
		p.Println(key)
		p.Println(trace)
	}
}
