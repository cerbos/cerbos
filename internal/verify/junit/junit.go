// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

const (
	skipTestCaseMessage  = "This test was skipped"
	skipTestSuiteMessage = "This test suite was skipped"
)

func Build(results *policyv1.TestResults, verbose bool) (*TestSuites, error) {
	suites := make([]testSuite, len(results.Suites))
	errorCount := 0
	skippedCount := 0
	for idx, s := range results.Suites {
		suite := testSuite{
			Tests:       int(s.Summary.TestsCount),
			Name:        s.Name,
			File:        s.File,
			Description: s.Description,
		}

		switch s.Summary.OverallResult {
		case policyv1.TestResults_RESULT_ERRORED:
			suite.Error = &testError{
				Value: s.Error,
				Type:  s.Summary.OverallResult.String(),
			}
			suite.Errors++
			errorCount++
		case policyv1.TestResults_RESULT_SKIPPED:
			if verbose {
				suite.Skip = &skipped{Message: skipTestSuiteMessage}
			}
			suite.Skipped++
			skippedCount++
		case policyv1.TestResults_RESULT_PASSED, policyv1.TestResults_RESULT_FAILED:
			testCases, properties, summary, err := processTestCases(s, verbose)
			if err != nil {
				return nil, fmt.Errorf("failed to process test cases: %w", err)
			}
			suite.Properties = properties
			suite.Summary = summary
			suite.TestCases = testCases
		default:
			return nil, fmt.Errorf("unspecified overall result")
		}

		suites[idx] = suite
	}

	failureCount := 0
	for _, resultCount := range results.Summary.ResultCounts {
		switch resultCount.Result {
		case policyv1.TestResults_RESULT_ERRORED:
			errorCount = int(resultCount.Count) + errorCount
		case policyv1.TestResults_RESULT_FAILED:
			failureCount = int(resultCount.Count)
		case policyv1.TestResults_RESULT_SKIPPED:
			skippedCount = int(resultCount.Count) + skippedCount
		case policyv1.TestResults_RESULT_PASSED:
			continue
		default:
			return nil, fmt.Errorf("unspecified result count")
		}
	}

	return &TestSuites{
		Tests: int(results.Summary.TestsCount),
		Summary: Summary{
			Errors:   errorCount,
			Failures: failureCount,
			Skipped:  skippedCount,
		},
		Suites: suites,
	}, nil
}

func processTestCases(s *policyv1.TestResults_Suite, verbose bool) ([]testCase, []property, Summary, error) {
	var testCases []testCase
	var properties []property
	var summary Summary
	for _, tc := range s.TestCases {
		for _, p := range tc.Principals {
			for _, r := range p.Resources {
				for _, a := range r.Actions {
					testCase := testCase{
						Name:      tc.Name,
						File:      s.File,
						Classname: fmt.Sprintf("%s.%s.%s", p.Name, r.Name, a.Name),
					}

					switch a.Details.Result {
					case policyv1.TestResults_RESULT_ERRORED:
						testCase.Error = &testError{Type: a.Details.Result.String()}
						summary.Errors++
					case policyv1.TestResults_RESULT_FAILED:
						f, _ := a.Details.Outcome.(*policyv1.TestResults_Details_Failure)
						testCase.Failure = &failure{
							Type: a.Details.Result.String(),
							resultFailed: resultFailed{
								Actual:   f.Failure.Actual.String(),
								Expected: f.Failure.Expected.String(),
							},
						}
						summary.Failures++

						if verbose {
							name := fmt.Sprintf("step[%s - %s.%s.%s]", tc.Name, p.Name, r.Name, a.Name)
							properties = append(properties, property{
								Name:   name,
								Traces: processTraces(a.Details.EngineTrace),
							})
						}
					case policyv1.TestResults_RESULT_PASSED:
						if !verbose {
							continue
						}
					case policyv1.TestResults_RESULT_SKIPPED:
						summary.Skipped++
						testCase.Skipped = &skipped{
							Message: skipTestCaseMessage,
						}
					default:
						return nil, nil, Summary{}, fmt.Errorf("unspecified result")
					}

					testCases = append(testCases, testCase)
				}
			}
		}
	}

	return testCases, properties, summary, nil
}

func processTraces(engineTraces []*enginev1.Trace) []trace {
	traces := make([]trace, len(engineTraces))
	for idx, engineTrace := range engineTraces {
		traces[idx] = trace{
			ID:             idx + 1,
			traceComponent: processTraceComponents(engineTrace.Components),
			traceEvent:     processTraceEvent(engineTrace.Event),
		}
	}

	return traces
}

func processTraceComponents(components []*enginev1.Trace_Component) traceComponent {
	var c traceComponent
	for _, component := range components {
		c.Apply(component)
	}

	return c
}

func processTraceEvent(event *enginev1.Trace_Event) traceEvent {
	te := traceEvent{}
	switch event.Status {
	case enginev1.Trace_Event_STATUS_ACTIVATED:
		te.Activated = true
	case enginev1.Trace_Event_STATUS_SKIPPED:
		te.Skipped = true
	default:
	}

	if event.Result != nil {
		result, err := protojson.Marshal(event.Result)
		if err != nil {
			te.Result = fmt.Sprintf("<failed to encode JSON: %s>", err)
		} else {
			te.Result = string(result)
		}
	}

	switch event.Effect {
	case effectv1.Effect_EFFECT_ALLOW, effectv1.Effect_EFFECT_DENY:
		te.Effect = event.Effect.String()
	default:
	}

	te.Message = event.Message
	te.Error = event.Error

	return te
}

type TestSuites struct {
	XMLName xml.Name `xml:"testsuites"`
	Suites  []testSuite
	Summary
	Tests int `xml:"tests,attr"`
}

type testSuite struct {
	XMLName     xml.Name   `xml:"testsuite"`
	Description string     `xml:"description,attr,omitempty"`
	Name        string     `xml:"name,attr"`
	File        string     `xml:"file,attr"`
	Failure     *failure   `xml:"failure,omitempty"`
	Error       *testError `xml:"error,omitempty"`
	Skip        *skipped   `xml:"skipped,omitempty"`
	Properties  []property `xml:"properties>property,omitempty"`
	TestCases   []testCase `xml:"testCases,omitempty"`
	Summary
	Tests int `xml:"tests,attr"`
}

type testCase struct {
	XMLName    xml.Name   `xml:"testcase"`
	Skipped    *skipped   `xml:"skipped,omitempty"`
	Failure    *failure   `xml:"failure,omitempty"`
	Error      *testError `xml:"error,omitempty"`
	File       string     `xml:"file,attr"`
	Classname  string     `xml:"classname,attr"`
	Name       string     `xml:"name,attr"`
	Properties []property `xml:"properties>property,omitempty"`
}

type testError struct {
	XMLName xml.Name `xml:"error"`
	Type    string   `xml:"type,attr,omitempty"`
	Value   string   `xml:",chardata"` //nolint:tagliatelle
}

type failure struct {
	XMLName xml.Name `xml:"failure"`
	Type    string   `xml:"type,attr,omitempty"`
	resultFailed
}

type resultFailed struct {
	Actual   string `xml:"actual,omitempty"`
	Expected string `xml:"expected,omitempty"`
}

type skipped struct {
	XMLName xml.Name `xml:"skipped"`
	Message string   `xml:"message,attr"`
}

type property struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	Traces  []trace  `xml:"traces>trace,omitempty"`
}

type trace struct {
	XMLName xml.Name `xml:"trace"`
	traceComponent
	traceEvent
	ID int `xml:"id,attr"`
}

type traceComponent struct {
	Condition   *condition `xml:"condition,omitempty"`
	Variable    *variable  `xml:"variable,omitempty"`
	Action      string     `xml:"action,omitempty"`
	DerivedRole string     `xml:"derivedRole,omitempty"`
	Expr        string     `xml:"expr,omitempty"`
	Policy      string     `xml:"policy,omitempty"`
	Resource    string     `xml:"resource,omitempty"`
	Rule        string     `xml:"rule,omitempty"`
	Scope       string     `xml:"scope,omitempty"`
	Variables   bool       `xml:"variables,omitempty"`
}

func (tc *traceComponent) Apply(component *enginev1.Trace_Component) {
	switch component.Kind {
	case enginev1.Trace_Component_KIND_ACTION:
		tc.Action = component.GetAction()
	case enginev1.Trace_Component_KIND_CONDITION_ALL:
		tc.Condition = &condition{Value: enginev1.Trace_Component_KIND_CONDITION_ALL.String()}
	case enginev1.Trace_Component_KIND_CONDITION_ANY:
		tc.Condition = &condition{Value: enginev1.Trace_Component_KIND_CONDITION_ANY.String()}
	case enginev1.Trace_Component_KIND_CONDITION_NONE:
		tc.Condition = &condition{Value: enginev1.Trace_Component_KIND_CONDITION_NONE.String()}
	case enginev1.Trace_Component_KIND_CONDITION:
		tc.Condition = &condition{Value: enginev1.Trace_Component_KIND_CONDITION.String()}
		if details, ok := component.Details.(*enginev1.Trace_Component_Index); ok {
			tc.Condition.Index = int(details.Index)
		}
	case enginev1.Trace_Component_KIND_DERIVED_ROLE:
		tc.DerivedRole = component.GetDerivedRole()
	case enginev1.Trace_Component_KIND_EXPR:
		tc.Expr = component.GetExpr()
	case enginev1.Trace_Component_KIND_POLICY:
		tc.Policy = component.GetPolicy()
	case enginev1.Trace_Component_KIND_RESOURCE:
		tc.Resource = component.GetResource()
	case enginev1.Trace_Component_KIND_RULE:
		tc.Rule = component.GetRule()
	case enginev1.Trace_Component_KIND_SCOPE:
		tc.Scope = component.GetScope()
	case enginev1.Trace_Component_KIND_VARIABLE:
		tc.Variable = &variable{
			Name:  component.GetVariable().Name,
			Value: component.GetVariable().Expr,
		}
	case enginev1.Trace_Component_KIND_VARIABLES:
		tc.Variables = true
	default:
	}
}

type traceEvent struct {
	Effect    string `xml:"effect,omitempty"`
	Result    string `xml:"result,omitempty"`
	Message   string `xml:"message,omitempty"`
	Error     string `xml:"error,omitempty"`
	Activated bool   `xml:"activated,omitempty"`
	Skipped   bool   `xml:"skipped,omitempty"`
}

type condition struct {
	XMLName xml.Name `xml:"condition"`
	Value   string   `xml:",chardata"` //nolint:tagliatelle
	Index   int      `xml:"index,attr,omitempty"`
}

type variable struct {
	XMLName xml.Name `xml:"variable"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:",chardata"` //nolint:tagliatelle
}

type Summary struct {
	Errors   int `xml:"errors,attr"`
	Failures int `xml:"failures,attr"`
	Skipped  int `xml:"skipped,attr"`
}
