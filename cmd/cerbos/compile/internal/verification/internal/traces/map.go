// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"fmt"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/colored"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/printer"
	"google.golang.org/protobuf/encoding/protojson"
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

			printTraceComponents(p, trace.Components)
			printTraceEvent(p, trace.Event)
		}
		p.Println()
	}
}

func printTraceComponents(p *printer.Printer, components []*enginev1.Trace_Component) {
	p.Printf("  ")
	for i, component := range components {
		if i > 0 {
			p.Printf(colored.TraceComponentSeparator(" > "))
		}

		printTraceComponent(p, component)
	}
	p.Println()
}

func printTraceComponent(p *printer.Printer, component *enginev1.Trace_Component) {
	switch component.Kind {
	case enginev1.Trace_Component_KIND_ACTION:
		p.Printf("%s%s", colored.TraceComponentKey("action="), component.GetAction())

	case enginev1.Trace_Component_KIND_CONDITION_ALL:
		p.Printf(colored.TraceComponentKey("conditionAll"))

	case enginev1.Trace_Component_KIND_CONDITION_ANY:
		p.Printf(colored.TraceComponentKey("conditionAny"))

	case enginev1.Trace_Component_KIND_CONDITION_NONE:
		p.Printf(colored.TraceComponentKey("conditionNone"))

	case enginev1.Trace_Component_KIND_CONDITION:
		p.Printf(colored.TraceComponentKey("condition"))
		if details, ok := component.Details.(*enginev1.Trace_Component_Index); ok {
			p.Printf("#%d", details.Index)
		}

	case enginev1.Trace_Component_KIND_DERIVED_ROLE:
		p.Printf("%s%s", colored.TraceComponentKey("derivedRole="), component.GetDerivedRole())

	case enginev1.Trace_Component_KIND_EXPR:
		p.Printf("%s`%s`", colored.TraceComponentKey("expr="), component.GetExpr())

	case enginev1.Trace_Component_KIND_POLICY:
		p.Printf("%s%s", colored.TraceComponentKey("policy="), component.GetPolicy())

	case enginev1.Trace_Component_KIND_RESOURCE:
		p.Printf("%s%s", colored.TraceComponentKey("resource="), component.GetResource())

	case enginev1.Trace_Component_KIND_RULE:
		p.Printf("%s%s", colored.TraceComponentKey("rule="), component.GetRule())

	case enginev1.Trace_Component_KIND_SCOPE:
		scope := component.GetScope()
		if scope == "" {
			scope = `""`
		}
		p.Printf("%s%s", colored.TraceComponentKey("scope="), scope)

	case enginev1.Trace_Component_KIND_VARIABLE:
		p.Printf("%s`%s`", colored.TraceComponentKey(component.GetVariable().Name, "="), component.GetVariable().Expr)

	case enginev1.Trace_Component_KIND_VARIABLES:
		p.Printf(colored.TraceComponentKey("variables"))

	default:
		p.Printf(colored.ErrorMsg("<unexpected trace component!>"))
	}
}

func printTraceEvent(p *printer.Printer, event *enginev1.Trace_Event) {
	switch event.Status {
	case enginev1.Trace_Event_STATUS_ACTIVATED:
		p.Printf("    %s\n", colored.TraceEventActivated("activated"))

	case enginev1.Trace_Event_STATUS_SKIPPED:
		p.Printf("    %s\n", colored.TraceEventSkipped("skipped"))
	}

	switch event.Effect {
	case effectv1.Effect_EFFECT_ALLOW:
		p.Printf("    effect → %s\n", colored.TraceEventEffectAllow("allow"))

	case effectv1.Effect_EFFECT_DENY:
		p.Printf("    effect → %s\n", colored.TraceEventEffectDeny("deny"))
	}

	if event.Result != nil {
		p.Printf("    result → ")

		result, err := protojson.Marshal(event.Result)
		if err != nil {
			p.Printf("<failed to encode JSON: %s>", err)
		} else {
			p.Printf("%s", result)
		}

		p.Println()
	}

	if event.Message != "" {
		p.Printf("    %s", event.Message)

		if event.Error == "" {
			p.Println()
		} else {
			p.Printf(": ")
		}
	}

	if event.Error != "" {
		if event.Message == "" {
			p.Printf("    ")
		}

		p.Println(colored.ErrorMsg(event.Error))
	}
}
