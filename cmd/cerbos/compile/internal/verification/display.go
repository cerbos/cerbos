// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/verification/internal/traces"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
	"github.com/cerbos/cerbos/internal/verify/junit"
)

const (
	suiteLevel     = 0
	testCaseLevel  = 1
	principalLevel = 2
	resourceLevel  = 3
	actionLevel    = 4
	resultLevel    = 5

	listIndent = 2
)

var (
	labelColors = map[policyv1.TestResults_Result]func(...any) string{
		policyv1.TestResults_RESULT_PASSED:  colored.PassedTest,
		policyv1.TestResults_RESULT_SKIPPED: colored.SkippedTest,
		policyv1.TestResults_RESULT_FAILED:  colored.FailedTest,
		policyv1.TestResults_RESULT_ERRORED: colored.ErroredTest,
	}

	labels = map[policyv1.TestResults_Result]string{
		policyv1.TestResults_RESULT_PASSED:  "OK",
		policyv1.TestResults_RESULT_SKIPPED: "SKIPPED",
		policyv1.TestResults_RESULT_FAILED:  "FAILED",
		policyv1.TestResults_RESULT_ERRORED: "ERROR",
	}
)

func Display(p *printer.Printer, results *policyv1.TestResults, output flagset.VerificationOutputFormat, verbose bool, colorLevel outputcolor.Level) error {
	switch output {
	case flagset.VerificationOutputFormatJSON:
		return p.PrintProtoJSON(results, colorLevel)
	case flagset.VerificationOutputFormatTree:
		return displayTree(p, pterm.DefaultTree, results, verbose)
	case flagset.VerificationOutputFormatList:
		return displayTree(p, pterm.TreePrinter{Indent: listIndent, VerticalString: " "}, results, verbose)
	case flagset.VerificationOutputFormatJUnit:
		return displayJUnit(p, results, verbose)
	default:
		return nil
	}
}

func displayJUnit(p *printer.Printer, results *policyv1.TestResults, verbose bool) error {
	r, err := junit.Build(results, verbose)
	if err != nil {
		return fmt.Errorf("failed to build JUnit XML: %w", err)
	}

	output, err := xml.MarshalIndent(r, "", strings.Repeat(" ", listIndent))
	if err != nil {
		return fmt.Errorf("failed to marshal xml: %w", err)
	}

	p.Println(string(output))
	return nil
}

func displayTree(p *printer.Printer, tp pterm.TreePrinter, results *policyv1.TestResults, verbose bool) error {
	output := buildTestOutput(results, verbose)

	p.Println(colored.Header("Test results"))

	err := tp.WithRoot(putils.TreeFromLeveledList(output.tree)).Render()
	if err != nil {
		return err
	}

	if verbose {
		output.traces.Print(p)
	}

	p.Printf("%d tests executed", results.Summary.TestsCount)
	for _, tally := range results.Summary.ResultCounts {
		p.Printf(" %s", tallyLabel(tally))
	}
	p.Println()

	return nil
}

type testOutput struct {
	traces  traces.Map
	tree    pterm.LeveledList
	verbose bool
}

func buildTestOutput(results *policyv1.TestResults, verbose bool) *testOutput {
	output := &testOutput{
		traces:  make(traces.Map),
		verbose: verbose,
	}

	for _, suite := range results.Suites {
		output.addSuite(suite)
	}

	return output
}

func (o *testOutput) addSuite(suite *policyv1.TestResults_Suite) {
	suiteText := fmt.Sprintf("%s %s", colored.Suite(suite.Name), fmt.Sprintf("(%s)", colored.FileName(suite.File)))

	if suite.Error != "" {
		o.appendNode(suiteLevel, fmt.Sprintf("%s %s", suiteText, resultLabel(policyv1.TestResults_RESULT_ERRORED)))
		o.appendNode(suiteLevel+1, colored.ErrorMsg(suite.Error))
		return
	}

	if suite.Summary.OverallResult == policyv1.TestResults_RESULT_SKIPPED {
		o.appendNode(suiteLevel, fmt.Sprintf("%s %s", suiteText, resultLabel(policyv1.TestResults_RESULT_SKIPPED)))
		return
	}

	for _, tally := range suite.Summary.ResultCounts {
		suiteText = fmt.Sprintf("%s %s", suiteText, tallyLabel(tally))
	}

	o.appendNode(suiteLevel, suiteText)

	for _, testCase := range suite.TestCases {
		o.addTestCase(suite, testCase)
	}
}

func (o *testOutput) addTestCase(suite *policyv1.TestResults_Suite, testCase *policyv1.TestResults_TestCase) {
	if !o.shouldAddTestCase(testCase) {
		return
	}

	o.appendNode(testCaseLevel, colored.TestCase(testCase.Name))

	for _, principal := range testCase.Principals {
		o.addPrincipal(suite, principal)
	}
}

func (o *testOutput) shouldAddTestCase(testCase *policyv1.TestResults_TestCase) bool {
	if o.verbose {
		return true
	}

	for _, principal := range testCase.Principals {
		if o.shouldAddPrincipal(principal) {
			return true
		}
	}

	return false
}

func (o *testOutput) addPrincipal(suite *policyv1.TestResults_Suite, principal *policyv1.TestResults_Principal) {
	if !o.shouldAddPrincipal(principal) {
		return
	}

	o.appendNode(principalLevel, colored.Principal(principal.Name))

	for _, resource := range principal.Resources {
		o.addResource(suite, principal, resource)
	}
}

func (o *testOutput) shouldAddPrincipal(principal *policyv1.TestResults_Principal) bool {
	if o.verbose {
		return true
	}

	for _, resource := range principal.Resources {
		if o.shouldAddResource(resource) {
			return true
		}
	}

	return false
}

func (o *testOutput) addResource(suite *policyv1.TestResults_Suite, principal *policyv1.TestResults_Principal, resource *policyv1.TestResults_Resource) {
	if !o.shouldAddResource(resource) {
		return
	}

	o.appendNode(resourceLevel, colored.Resource(resource.Name))

	for _, action := range resource.Actions {
		o.addAction(suite, principal, resource, action)
	}
}

func (o *testOutput) shouldAddResource(resource *policyv1.TestResults_Resource) bool {
	if o.verbose {
		return true
	}

	for _, action := range resource.Actions {
		if o.shouldAddAction(action) {
			return true
		}
	}

	return false
}

func (o *testOutput) addAction(suite *policyv1.TestResults_Suite, principal *policyv1.TestResults_Principal, resource *policyv1.TestResults_Resource, action *policyv1.TestResults_Action) {
	if !o.shouldAddAction(action) {
		return
	}

	o.appendNode(actionLevel, fmt.Sprintf("%s %s", colored.Action(action.Name), resultLabel(action.Details.Result)))

	switch action.Details.Result {
	case policyv1.TestResults_RESULT_FAILED:
		failure := action.Details.GetFailure()
		o.traces.Add(suite.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
		o.appendNode(resultLevel, fmt.Sprintf("%s expected: %s, actual: %s", colored.ErrorMsg("OUTCOME:"), failure.Expected, colored.FailedTest(failure.Actual)))

	case policyv1.TestResults_RESULT_ERRORED:
		o.traces.Add(suite.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
		o.appendNode(resultLevel, fmt.Sprintf("%s %s", colored.ErrorMsg("ERROR:"), action.Details.GetError()))

	default:
	}
}

func (o *testOutput) shouldAddAction(action *policyv1.TestResults_Action) bool {
	return o.verbose || action.Details.Result != policyv1.TestResults_RESULT_PASSED
}

func (o *testOutput) appendNode(level int, text string) {
	o.tree = append(o.tree, pterm.LeveledListItem{Level: level, Text: text})
}

func resultLabel(result policyv1.TestResults_Result) string {
	return labelColors[result](fmt.Sprintf("[%s]", labels[result]))
}

func tallyLabel(tally *policyv1.TestResults_Tally) string {
	return labelColors[tally.Result](fmt.Sprintf("[%d %s]", tally.Count, labels[tally.Result]))
}
