// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"

	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/colored"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/compile/internal/printer"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/pterm/pterm"
)

func Display(p *printer.Printer, result *verify.Result, output flagset.OutputFormat, verbose bool) error {
	switch output {
	case flagset.OutputFormatJSON:
		if err := p.PrintJSON(result); err != nil {
			return err
		}

		if result.Failed {
			return errors.ErrFailed
		}

		return nil
	case flagset.OutputFormatTree:
		return displayTree(p, result, verbose)
	case flagset.OutputFormatPretty:
		return displayPretty(p, result, verbose)
	}

	return errors.ErrFailed
}

func displayPretty(p *printer.Printer, result *verify.Result, verbose bool) error {
	p.Println(colored.Header("Test results"))
	for _, sn := range result.Suites {
		p.Printf("= %s %s ", colored.Suite(sn.Name), colored.FileName("(", sn.File, ")"))
		if sn.Failed {
			p.Println(colored.FailedTest("[FAILED]"))
			p.Printf("== %s\n", colored.ErrorMsg(sn.Status))
			continue
		}

		if sn.Skipped {
			p.Println(colored.SkippedTest("[SKIPPED]"))
			continue
		}

		p.Println()
		for _, principal := range sn.Principals {
			p.Println()
			p.Printf("== %s\n", colored.Principal(principal.Name))
			for _, resource := range principal.Resources {
				p.Println()
				p.Printf("=== %s\n", colored.Resource(resource.Name))
				for _, action := range resource.Actions {
					p.Printf("==== %s ", colored.Action(action.Name))
					if action.Data.Skipped {
						p.Println(colored.SkippedTest("[SKIPPED]"))
						continue
					}

					if action.Data.Failed {
						p.Println(colored.FailedTest("[FAILED]"))
						p.Printf("\tError: %s\n", action.Data.Error)
						if verbose {
							p.Printf("\tTrace: \n%s\n", action.Data.EngineTrace)
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

	if result.Failed {
		return errors.ErrTestsFailed
	}

	return nil
}

func displayTree(p *printer.Printer, result *verify.Result, verbose bool) error {
	tree := pterm.LeveledList{}

	p.Println(colored.Header("Test results"))
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

					if action.Data.Failed {
						actionText = fmt.Sprintf("%s %s", actionText, colored.FailedTest("[FAILED]"))
					}

					if action.Data.Skipped {
						actionText = fmt.Sprintf("%s %s", actionText, colored.SkippedTest("[SKIPPED]"))
					}

					if !action.Data.Failed && !action.Data.Skipped {
						actionText = fmt.Sprintf("%s %s", actionText, colored.SuccessfulTest("[OK]"))
					}

					tree = append(tree, pterm.LeveledListItem{
						Level: 3, //nolint:gomnd
						Text:  actionText,
					})

					if action.Data.Failed {
						tree = append(tree, pterm.LeveledListItem{
							Level: 4, //nolint:gomnd
							Text:  fmt.Sprintf("%s %s", colored.ErrorMsg("ERROR:"), action.Data.Error),
						})
						if verbose && action.Data.EngineTrace != "" {
							tree = append(tree, pterm.LeveledListItem{
								Level: 4, //nolint:gomnd
								Text:  fmt.Sprintf("%s %s", colored.Trace("TRACE:"), action.Data.EngineTrace),
							})
						}
					}
				}
			}
		}
	}

	root := pterm.NewTreeFromLeveledList(tree)
	err := pterm.DefaultTree.WithRoot(root).Render()
	if err != nil {
		return errors.ErrFailed
	}

	if result.Failed {
		return errors.ErrTestsFailed
	}

	return nil
}
