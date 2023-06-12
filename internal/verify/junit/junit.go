// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

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
			testCases, summary, err := processTestCases(s)
			if err != nil {
				return nil, fmt.Errorf("failed to process test cases: %w", err)
			}
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

func processTestCases(s *policyv1.TestResults_Suite) ([]testCase, Summary, error) {
	var testCases []testCase
	var summary Summary
	for _, tc := range s.TestCases {
		for _, p := range tc.Principals {
			for _, r := range p.Resources {
				for _, a := range r.Actions {
					testCase := testCase{
						Name:      tc.Name,
						File:      s.File,
						Classname: fmt.Sprintf("%s.%s.%s", p.Name, r.Name, a.Name),
						Properties: []property{
							{
								Name:  "principal",
								Value: p.Name,
							},
							{
								Name:  "resource",
								Value: r.Name,
							},
							{
								Name:  "action",
								Value: a.Name,
							},
						},
					}

					switch a.Details.Result {
					case policyv1.TestResults_RESULT_ERRORED:
						testCase.Error = &testError{Type: a.Details.Result.String()}
						summary.Errors++
					case policyv1.TestResults_RESULT_FAILED:
						f, _ := a.Details.Outcome.(*policyv1.TestResults_Details_Failure)
						testCase.Failure = &failure{
							Type:    a.Details.Result.String(),
							Message: "Effect expectation unsatisfied",
							resultFailed: resultFailed{
								Actual:   f.Failure.Actual.String(),
								Expected: f.Failure.Expected.String(),
							},
						}

						if len(f.Failure.Outputs) > 0 {
							outputSet := make([]output, len(f.Failure.Outputs))
							for i, o := range f.Failure.Outputs {
								switch t := o.Outcome.(type) {
								case *policyv1.TestResults_OutputFailure_Mismatched:
									outputSet[i] = output{
										Src:      o.Src,
										Actual:   outputValue{Value: protojson.Format(t.Mismatched.Actual)},
										Expected: outputValue{Value: protojson.Format(t.Mismatched.Expected)},
									}
								case *policyv1.TestResults_OutputFailure_Missing:
									outputSet[i] = output{
										Src:      o.Src,
										Expected: outputValue{Value: protojson.Format(t.Missing.Expected)},
									}
								default:
									outputSet[i] = output{
										Src: o.Src,
									}
								}
							}

							testCase.Failure.Message = "Output expectation unsatisfied"
							testCase.Failure.Outputs = &outputSet
						}

						summary.Failures++
					case policyv1.TestResults_RESULT_PASSED:
					case policyv1.TestResults_RESULT_SKIPPED:
						summary.Skipped++
						testCase.Skipped = &skipped{
							Message: skipTestCaseMessage,
						}
					default:
						return nil, Summary{}, fmt.Errorf("unspecified result")
					}

					testCases = append(testCases, testCase)
				}
			}
		}
	}

	return testCases, summary, nil
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
	resultFailed
	XMLName xml.Name `xml:"failure"`
	Type    string   `xml:"type,attr,omitempty"`
	Message string   `xml:"message,attr"`
}

type resultFailed struct {
	Outputs  *[]output `xml:"outputs>output,omitempty"`
	Actual   string    `xml:"actual,omitempty"`
	Expected string    `xml:"expected,omitempty"`
}

type output struct {
	XMLName  xml.Name    `xml:"output"`
	Src      string      `xml:"src,attr"`
	Expected outputValue `xml:"expected"`
	Actual   outputValue `xml:"actual"`
}

type outputValue struct {
	Value string `xml:",cdata"` //nolint:tagliatelle
}

type skipped struct {
	XMLName xml.Name `xml:"skipped"`
	Message string   `xml:"message,attr"`
}

type property struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:",chardata"` //nolint:tagliatelle
}

type Summary struct {
	Errors   int `xml:"errors,attr"`
	Failures int `xml:"failures,attr"`
	Skipped  int `xml:"skipped,attr"`
}
