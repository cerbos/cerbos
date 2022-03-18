// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"
	"strings"

	"github.com/pterm/pterm"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/verification/internal/traces"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
)

func Display(p *printer.Printer, results *policyv1.TestResults, output flagset.OutputFormat, verbose, noColor bool) error {
	switch output {
	case flagset.OutputFormatJSON:
		return p.PrintProtoJSON(results, noColor)
	case flagset.OutputFormatTree:
		return displayTree(p, results, verbose)
	case flagset.OutputFormatList:
		return displayList(p, results, verbose)
	default:
		return nil
	}
}

func displayList(p *printer.Printer, results *policyv1.TestResults, verbose bool) error {
	traceMap := make(traces.Map)

	p.Println(colored.Header("Test results"))

	for _, suite := range results.Suites {
		p.Printf("%s %s ", colored.Suite(suite.Name), colored.FileName("(", suite.File, ")"))

		if suite.Error != "" {
			p.Println(colored.FailedTest("[ERROR]"))
			p.Printf("%s%s\n", tabs(1), colored.ErrorMsg(suite.Error))
			continue
		}

		if suite.Result == policyv1.TestResults_RESULT_SKIPPED {
			p.Println(colored.SkippedTest("[SKIPPED]"))
			continue
		}

		p.Println()
		for _, principal := range suite.Principals {
			p.Printf("%s%s\n", tabs(1), colored.Principal(principal.Name))
			for _, resource := range principal.Resources {
				p.Printf("%s%s\n", tabs(2), colored.Resource(resource.Name)) //nolint:gomnd
				for _, action := range resource.Actions {
					p.Printf("%s%s ", tabs(3), colored.Action(action.Name)) //nolint:gomnd

					switch action.Details.Result {
					case policyv1.TestResults_RESULT_PASSED:
						p.Println(colored.SuccessfulTest("[OK]"))

					case policyv1.TestResults_RESULT_SKIPPED:
						p.Println(colored.SkippedTest("[SKIPPED]"))

					case policyv1.TestResults_RESULT_FAILED:
						traceMap.Add(suite.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
						failure := action.Details.GetFailure()
						p.Println(colored.FailedTest("[FAILED]"))
						p.Printf("%s%s expected: %s, actual: %s\n", tabs(4), colored.ErrorMsg("OUTCOME:"), colored.FailedTest(failure.Expected), colored.FailedTest(failure.Actual))

					case policyv1.TestResults_RESULT_ERRORED:
						traceMap.Add(suite.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
						p.Println(colored.FailedTest("[ERROR]"))
						p.Printf("%s%s %s\n", tabs(4), colored.ErrorMsg("ERROR:"), action.Details.GetError())

					default:
						return fmt.Errorf("unexpected test result %v", action.Details.Result)
					}
				}
			}
		}
	}

	if verbose {
		traceMap.Print(p)
	}

	return nil
}

func displayTree(p *printer.Printer, results *policyv1.TestResults, verbose bool) error {
	tree := pterm.LeveledList{}
	traceMap := make(traces.Map)

	p.Println(colored.Header("Test results"))

	for _, suite := range results.Suites {
		suiteText := fmt.Sprintf("%s (%s)", colored.Suite(suite.Name), colored.FileName(suite.File))

		if suite.Error != "" {
			suiteText = fmt.Sprintf("%s %s", suiteText, colored.FailedTest("[ERROR]"))
			tree = append(tree, pterm.LeveledListItem{
				Level: 0,
				Text:  suiteText,
			})
			tree = append(tree, pterm.LeveledListItem{
				Level: 1,
				Text:  colored.ErrorMsg(suite.Error),
			})
			continue
		}

		if suite.Result == policyv1.TestResults_RESULT_SKIPPED {
			suiteText = fmt.Sprintf("%s %s", suiteText, colored.SkippedTest("[SKIPPED]"))
			tree = append(tree, pterm.LeveledListItem{
				Level: 0,
				Text:  suiteText,
			})
			continue
		}

		tree = append(tree, pterm.LeveledListItem{
			Level: 0,
			Text:  suiteText,
		})

		for _, principal := range suite.Principals {
			tree = append(tree, pterm.LeveledListItem{
				Level: 1,
				Text:  colored.Principal(principal.Name),
			})
			for _, resource := range principal.Resources {
				tree = append(tree, pterm.LeveledListItem{
					Level: 2, //nolint:gomnd
					Text:  colored.Resource(resource.Name),
				})
				for _, action := range resource.Actions {
					actionText := colored.Action(action.Name)

					switch action.Details.Result {
					case policyv1.TestResults_RESULT_PASSED:
						tree = append(tree, pterm.LeveledListItem{
							Level: 3, //nolint:gomnd
							Text:  fmt.Sprintf("%s %s", actionText, colored.SuccessfulTest("[OK]")),
						})

					case policyv1.TestResults_RESULT_SKIPPED:
						tree = append(tree, pterm.LeveledListItem{
							Level: 3, //nolint:gomnd
							Text:  fmt.Sprintf("%s %s", actionText, colored.SkippedTest("[SKIPPED]")),
						})

					case policyv1.TestResults_RESULT_FAILED:
						traceMap.Add(suite.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
						failure := action.Details.GetFailure()
						tree = append(
							tree,
							pterm.LeveledListItem{
								Level: 3, //nolint:gomnd
								Text:  fmt.Sprintf("%s %s", actionText, colored.FailedTest("[FAILED]")),
							},
							pterm.LeveledListItem{
								Level: 4, //nolint:gomnd
								Text:  fmt.Sprintf("%s expected: %s, actual: %s", colored.ErrorMsg("OUTCOME:"), colored.FailedTest(failure.Expected), colored.FailedTest(failure.Actual)),
							},
						)

					case policyv1.TestResults_RESULT_ERRORED:
						traceMap.Add(suite.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
						tree = append(
							tree,
							pterm.LeveledListItem{
								Level: 3, //nolint:gomnd
								Text:  fmt.Sprintf("%s %s", actionText, colored.FailedTest("[ERROR]")),
							},
							pterm.LeveledListItem{
								Level: 4, //nolint:gomnd
								Text:  fmt.Sprintf("%s %s", colored.ErrorMsg("ERROR:"), action.Details.GetError()),
							},
						)

					default:
						return fmt.Errorf("unexpected test result %v", action.Details.Result)
					}
				}
			}
		}
	}

	root := pterm.NewTreeFromLeveledList(tree)
	err := pterm.DefaultTree.WithRoot(root).Render()
	if err != nil {
		return err
	}

	if verbose {
		traceMap.Print(p)
	}

	return nil
}

func tabs(numberOf int) string {
	return strings.Repeat("  ", numberOf)
}
