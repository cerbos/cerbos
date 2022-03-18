// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/printer/colored"
	"github.com/jwalton/gchalk"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func New(stdout, stderr io.Writer) *Printer {
	return &Printer{stdout: stdout, stderr: stderr}
}

type Printer struct {
	stdout io.Writer
	stderr io.Writer
}

func (p *Printer) Println(args ...interface{}) {
	fmt.Fprintln(p.stdout, args...)
}

func (p *Printer) Printf(format string, args ...interface{}) {
	fmt.Fprintf(p.stdout, format, args...)
}

func (p *Printer) coloredJSON(data string) error {
	lexer := chroma.Coalesce(lexers.Get("json"))
	if lexer == nil {
		lexer = lexers.Fallback
	}

	var formatter chroma.Formatter
	switch gchalk.GetLevel() {
	case gchalk.LevelAnsi256:
		formatter = formatters.TTY256
	case gchalk.LevelAnsi16m:
		formatter = formatters.TTY16m
	default:
		formatter = formatters.TTY
	}

	iterator, err := lexer.Tokenise(nil, data)
	if err != nil {
		return fmt.Errorf("failed to tokenise JSON: %w", err)
	}

	return formatter.Format(p.stdout, styles.SolarizedDark256, iterator)
}

func (p *Printer) PrintJSON(val interface{}, noColor bool) error {
	var data bytes.Buffer
	var enc *json.Encoder
	if noColor {
		enc = json.NewEncoder(p.stdout)
	} else {
		enc = json.NewEncoder(&data)
	}

	enc.SetIndent("", "  ")
	if err := enc.Encode(val); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	if !noColor {
		return p.coloredJSON(data.String())
	}

	return nil
}

func (p *Printer) PrintProtoJSON(message proto.Message, noColor bool) error {
	data, err := protojson.MarshalOptions{Multiline: true}.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	output := fmt.Sprintf("%s\n", data)

	if !noColor {
		return p.coloredJSON(output)
	}

	fmt.Fprint(p.stdout, output)
	return nil
}

func (p *Printer) PrintTrace(trace *enginev1.Trace) {
	p.printTraceComponents(trace.Components)
	p.printTraceEvent(trace.Event)
}

func (p *Printer) printTraceComponents(components []*enginev1.Trace_Component) {
	p.Printf("  ")
	for i, component := range components {
		if i > 0 {
			p.Printf(colored.TraceComponentSeparator(" > "))
		}
		p.printTraceComponent(component)
	}
	p.Println()
}

func (p *Printer) printTraceComponent(component *enginev1.Trace_Component) {
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

func (p *Printer) printTraceEvent(event *enginev1.Trace_Event) {
	switch event.Status {
	case enginev1.Trace_Event_STATUS_ACTIVATED:
		p.Printf("    %s\n", colored.TraceEventActivated("activated"))

	case enginev1.Trace_Event_STATUS_SKIPPED:
		p.Printf("    %s\n", colored.TraceEventSkipped("skipped"))

	default:
	}

	switch event.Effect {
	case effectv1.Effect_EFFECT_ALLOW:
		p.Printf("    effect → %s\n", colored.TraceEventEffectAllow("allow"))

	case effectv1.Effect_EFFECT_DENY:
		p.Printf("    effect → %s\n", colored.TraceEventEffectDeny("deny"))

	default:
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
