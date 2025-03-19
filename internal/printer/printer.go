// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

var style = styles.Get("solarized-dark256")

func New(stdout, stderr io.Writer) *Printer {
	return &Printer{stdout: stdout, stderr: stderr}
}

type Printer struct {
	stdout io.Writer
	stderr io.Writer
}

func (p *Printer) Println(args ...any) {
	fmt.Fprintln(p.stdout, args...)
}

func (p *Printer) Printf(format string, args ...any) {
	fmt.Fprintf(p.stdout, format, args...)
}

func (p *Printer) coloredJSON(data string, colorLevel outputcolor.Level) error {
	lexer := chroma.Coalesce(lexers.Get("json"))
	if lexer == nil {
		lexer = lexers.Fallback
	}

	var formatter chroma.Formatter
	switch colorLevel {
	case outputcolor.Basic:
		formatter = formatters.TTY
	case outputcolor.Ansi256:
		formatter = formatters.TTY256
	case outputcolor.Ansi16m:
		formatter = formatters.TTY16m
	default:
		formatter = formatters.NoOp
	}

	iterator, err := lexer.Tokenise(nil, data)
	if err != nil {
		return fmt.Errorf("failed to tokenise JSON: %w", err)
	}

	return formatter.Format(p.stdout, style, iterator)
}

func (p *Printer) PrintJSON(val any, colorLevel outputcolor.Level) error {
	var data bytes.Buffer
	var enc *json.Encoder
	if colorLevel.Enabled() {
		enc = json.NewEncoder(&data)
	} else {
		enc = json.NewEncoder(p.stdout)
	}

	enc.SetIndent("", "  ")
	if err := enc.Encode(val); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	if colorLevel.Enabled() {
		return p.coloredJSON(data.String(), colorLevel)
	}

	return nil
}

func (p *Printer) coloredYAML(data string, colorLevel outputcolor.Level) ([]byte, error) {
	lexer := chroma.Coalesce(lexers.Get("yaml"))
	if lexer == nil {
		lexer = lexers.Fallback
	}

	var formatter chroma.Formatter
	switch colorLevel {
	case outputcolor.Basic:
		formatter = formatters.TTY
	case outputcolor.Ansi256:
		formatter = formatters.TTY256
	case outputcolor.Ansi16m:
		formatter = formatters.TTY16m
	default:
		formatter = formatters.NoOp
	}

	iterator, err := lexer.Tokenise(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to tokenise YAML: %w", err)
	}

	var yml bytes.Buffer
	err = formatter.Format(&yml, style, iterator)
	if err != nil {
		return nil, fmt.Errorf("failed to format yaml: %w", err)
	}

	return yml.Bytes(), nil
}

func (p *Printer) PrintProtoYAML(message proto.Message, colorLevel outputcolor.Level, indent int) error {
	data, err := protojson.MarshalOptions{Multiline: true}.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	yamlBytes, err := yaml.JSONToYAML(data)
	if err != nil {
		return fmt.Errorf("failed to convert data to YAML: %w", err)
	}

	if colorLevel.Enabled() {
		yamlBytes, err = p.coloredYAML(string(yamlBytes), colorLevel)
		if err != nil {
			return err
		}
	}

	for line := range strings.SplitSeq(strings.TrimSuffix(string(yamlBytes), "\n"), "\n") {
		fmt.Fprintf(p.stdout, "%s%s\n", strings.Repeat("  ", indent), line)
	}

	return nil
}

func (p *Printer) PrintProtoJSON(message proto.Message, colorLevel outputcolor.Level) error {
	data, err := protojson.MarshalOptions{Multiline: true}.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	output := fmt.Sprintf("%s\n", data)

	if colorLevel.Enabled() {
		return p.coloredJSON(output, colorLevel)
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
			p.Printf("%s", colored.TraceComponentSeparator(" > ")) //nolint:govet
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
		p.Printf("%s", colored.TraceComponentKey("conditionAll")) //nolint:govet

	case enginev1.Trace_Component_KIND_CONDITION_ANY:
		p.Printf("%s", colored.TraceComponentKey("conditionAny")) //nolint:govet

	case enginev1.Trace_Component_KIND_CONDITION_NONE:
		p.Printf("%s", colored.TraceComponentKey("conditionNone")) //nolint:govet

	case enginev1.Trace_Component_KIND_CONDITION:
		p.Printf("%s", colored.TraceComponentKey("condition")) //nolint:govet
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

	case enginev1.Trace_Component_KIND_ROLE:
		p.Printf("%s%s", colored.TraceComponentKey("role="), component.GetRole())

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
		p.Printf("%s", colored.TraceComponentKey("variables")) //nolint:govet

	case enginev1.Trace_Component_KIND_OUTPUT:
		p.Printf("%s=%s", colored.TraceComponentKey("output"), component.GetOutput())

	default:
		p.Printf("%s", colored.ErrorMsg("<unexpected trace component!>")) //nolint:govet
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
