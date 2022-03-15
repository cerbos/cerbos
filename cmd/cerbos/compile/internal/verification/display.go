// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"
	"strings"

	"github.com/pterm/pterm"

	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/colored"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/printer"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/verification/internal/traces"
	"github.com/cerbos/cerbos/internal/verify"
)

func Display(p *printer.Printer, result *verify.Result, output flagset.OutputFormat, verbose, noColor bool) error {
	switch output {
	case flagset.OutputFormatJSON:
		if err := p.PrintJSON(result, noColor); err != nil {
			return err
		}

		if result.Failed {
			return errors.ErrTestsFailed
		}

		return nil
	case flagset.OutputFormatTree:
		return displayTree(p, result, verbose)
	case flagset.OutputFormatList:
		return displayList(p, result, verbose)
	}

	return errors.ErrTestsFailed
}

func displayList(p *printer.Printer, result *verify.Result, verbose bool) error {
	p.Println(colored.Header("Test results"))
	traceMap := make(traces.Map)
	for _, sn := range result.Suites {
		p.Printf("%s %s ", colored.Suite(sn.Name), colored.FileName("(", sn.File, ")"))
		if sn.Failed {
			p.Println(colored.FailedTest("[FAILED]"))
			p.Printf("%s%s\n", tabs(1), colored.ErrorMsg(sn.Status))
			continue
		}

		if sn.Skipped {
			p.Println(colored.SkippedTest("[SKIPPED]"))
			continue
		}

		p.Println()
		for _, principal := range sn.Principals {
			p.Printf("%s%s\n", tabs(1), colored.Principal(principal.Name))
			for _, resource := range principal.Resources {
				p.Printf("%s%s\n", tabs(2), colored.Resource(resource.Name)) //nolint:gomnd
				for _, action := range resource.Actions {
					p.Printf("%s%s ", tabs(3), colored.Action(action.Name)) //nolint:gomnd
					if action.Details.Skipped {
						p.Println(colored.SkippedTest("[SKIPPED]"))
						continue
					}

					if action.Details.Failed {
						p.Println(colored.FailedTest("[FAILED]"))
						p.Printf("\t%s %s\n", colored.ErrorMsg("ERROR:"), action.Details.Error)
						if action.Details.Outcome != nil {
							p.Printf("\t%s %s\n", colored.ErrorMsg("OUTCOME:"), action.Details.Outcome.Display(colored.FailedTest))
						}
						if verbose && action.Details.EngineTrace != "" {
							traceMap.Add(sn.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
						}
						continue
					}

					p.Println(colored.SuccessfulTest("[OK]"))
				}
			}
		}

		if sn.Failed {
			p.Println(colored.ErrorMsg("Invalid test suite"))
		}
	}

	traceMap.Print(p)

	if result.Failed {
		return errors.ErrTestsFailed
	}

	return nil
}

func displayTree(p *printer.Printer, result *verify.Result, verbose bool) error {
	tree := pterm.LeveledList{}

	p.Println(colored.Header("Test results"))
	traceMap := make(traces.Map)
	for _, sn := range result.Suites {
		suiteText := fmt.Sprintf("%s (%s)", colored.Suite(sn.Name), colored.FileName(sn.File))
		if sn.Failed {
			suiteText = fmt.Sprintf("%s %s", suiteText, colored.FailedTest("[FAILED]"))
			tree = append(tree, pterm.LeveledListItem{
				Level: 0,
				Text:  suiteText,
			})
			tree = append(tree, pterm.LeveledListItem{
				Level: 1,
				Text:  colored.ErrorMsg(sn.Status),
			})
			continue
		}

		if sn.Skipped {
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

		for _, principal := range sn.Principals {
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

					if action.Details.Failed {
						actionText = fmt.Sprintf("%s %s", actionText, colored.FailedTest("[FAILED]"))
					}

					if action.Details.Skipped {
						actionText = fmt.Sprintf("%s %s", actionText, colored.SkippedTest("[SKIPPED]"))
					}

					if !action.Details.Failed && !action.Details.Skipped {
						actionText = fmt.Sprintf("%s %s", actionText, colored.SuccessfulTest("[OK]"))
					}

					tree = append(tree, pterm.LeveledListItem{
						Level: 3, //nolint:gomnd
						Text:  actionText,
					})

					if action.Details.Failed {
						tree = append(tree, pterm.LeveledListItem{
							Level: 4, //nolint:gomnd
							Text:  fmt.Sprintf("%s %s", colored.ErrorMsg("ERROR:"), action.Details.Error),
						})
						if action.Details.Outcome != nil {
							tree = append(tree, pterm.LeveledListItem{
								Level: 4, //nolint:gomnd
								Text:  fmt.Sprintf("%s %s", colored.ErrorMsg("OUTCOME:"), action.Details.Outcome.Display(colored.FailedTest)),
							})
						}
						if verbose && action.Details.EngineTrace != "" {
							traceMap.Add(sn.Name, principal.Name, resource.Name, action.Name, action.Details.EngineTrace)
						}
					}
				}
			}
		}
	}

	root := pterm.NewTreeFromLeveledList(tree)
	err := pterm.DefaultTree.WithRoot(root).Render()
	if err != nil {
		return errors.ErrTestsFailed
	}

	traceMap.Print(p)

	if result.Failed {
		return errors.ErrTestsFailed
	}

	return nil
}

func tabs(numberOf int) string {
	return strings.Repeat("  ", numberOf)
}
