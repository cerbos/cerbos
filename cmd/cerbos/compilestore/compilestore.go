// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilestore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/pterm/pterm"
	"helm.sh/helm/v3/pkg/strvals"

	internalcompile "github.com/cerbos/cerbos/cmd/cerbos/internal/compilation"
	"github.com/cerbos/cerbos/cmd/cerbos/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbos/internal/lint"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/printer/colored"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db"
	"github.com/cerbos/cerbos/internal/storage/index"
)

const (
	help = `
Examples:

# Compile store

cerbos compile-store /path/to/cerbos/config.yaml

# Compile database store and disable invalid policies 

cerbos compile-store --disable-invalid /path/to/cerbos/config.yaml
`
)

//nolint:govet
type Cmd struct { //betteralign:ignore
	Config         string   `help:"Path to config file" arg:"" required:"" type:"existingfile" placeholder:".cerbos.yaml" env:"CERBOS_CONFIG"`
	Set            []string `help:"Config overrides" placeholder:"server.adminAPI.enabled=true"`
	DisableInvalid bool     `help:"Disable invalid policies if database store" placeholder:"false"`
	AssumeYes      bool     `help:"Answer yes to all confirmation questions" placeholder:"false"`
	flagset.Format
	flagset.Color
}

func (c *Cmd) Run(k *kong.Kong) error {
	if err := c.loadConfig(); err != nil {
		return err
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	colorLevel := c.Level.Resolve(c.Disable)
	color.NoColor = !colorLevel.Enabled()
	if colorLevel.Enabled() {
		pterm.EnableColor()
	} else {
		pterm.DisableColor()
	}

	p := printer.New(k.Stdout, k.Stderr)
	cm, disable, err := c.compileManager(ctx)
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return lint.Display(p, idxErr, c.Format, colorLevel)
		}

		return err
	}

	var compErr *compile.ErrorSet
	if err := cm.CompileAll(ctx); err != nil && !errors.As(err, &compErr) {
		return fmt.Errorf("failed to compile policies: %w", err)
	} else if err == nil {
		return nil
	}

	if !c.DisableInvalid {
		return internalcompile.Display(p, *compErr, c.Format, colorLevel)
	}

	policyKeys := make(map[string][]errWithDesc)
	for _, err := range compErr.Errors().GetErrors() {
		key := strings.TrimSuffix(strings.TrimPrefix(err.GetFile(), "<"), ">")
		policyKeys[key] = append(policyKeys[key], errWithDesc{Err: err.GetError(), Description: err.GetDescription()})
	}

	if len(policyKeys) == 0 {
		return nil
	}

	return c.disableInvalidPolicies(ctx, p, colorLevel, disable, policyKeys)
}

type errWithDesc struct {
	Err         string `json:"error"`
	Description string `json:"description"`
}

func (c *Cmd) loadConfig() error {
	confOverrides := map[string]any{}
	for _, override := range c.Set {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}

	if err := config.Load(c.Config, confOverrides); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	return nil
}

type disableFn func(ctx context.Context, policyKey ...string) (disabledPolicies uint32, err error)

func (c *Cmd) compileManager(ctx context.Context) (*compile.Manager, disableFn, error) {
	store, err := storage.New(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create store: %w", err)
	}

	var fn disableFn
	ss, ok := store.(storage.SourceStore)
	if !ok {
		return nil, nil, fmt.Errorf("the configured store is not a source store")
	}

	if ms, ok := store.(storage.MutableStore); ok {
		fn = ms.Disable
	} else if c.DisableInvalid {
		return nil, nil, errors.New("--disable-invalid flag is only supported by mutable stores")
	}

	cm, err := compile.NewManager(ctx, ss)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create compile manager: %w", err)
	}

	return cm, fn, nil
}

func (c *Cmd) disableInvalidPolicies(ctx context.Context, p *printer.Printer, colorLevel outputcolor.Level, disable disableFn, policyKeys map[string][]errWithDesc) error {
	var confirmed bool
	if !c.AssumeYes {
		confirmed = confirm(
			ctx, p,
			fmt.Sprintf(
				"%s\n%s",
				colored.Header(fmt.Sprintf("Continuing with this command going to disable the following %d policies, and more if those policies are required by other policies or the scope chain is broken:", len(policyKeys))),
				strings.Join(slices.Collect(func(yield func(string) bool) {
					for k := range policyKeys {
						if !yield(colored.PolicyKey(k)) {
							return
						}
					}
				}), "\n"),
			),
		)
	} else {
		confirmed = true
	}

	if !confirmed {
		return nil
	}

	var integrityErr *db.IntegrityErr
	if _, err := disable(ctx, slices.Collect(maps.Keys(policyKeys))...); err != nil && !errors.As(err, &integrityErr) {
		return fmt.Errorf("failed to disable policies: %w", err)
	} else if integrityErr == nil {
		return display(p, c.Format, colorLevel, policyKeys)
	}

	for invalidPolicyKey, ierr := range integrityErr.Errors {
		if ierr.GetBreaksScopeChain() != nil {
			for _, descendant := range ierr.GetBreaksScopeChain().GetDescendants() {
				policyKeys[descendant] = append(policyKeys[descendant], errWithDesc{
					Err:         "descendant of invalid scope policy",
					Description: fmt.Sprintf("Policy %s is invalid and all of its descendants should be disabled to avoid breaking the scope chain", invalidPolicyKey),
				})
			}
		}

		if ierr.GetRequiredByOtherPolicies() != nil {
			for _, dependents := range ierr.GetRequiredByOtherPolicies().GetDependents() {
				policyKeys[dependents] = append(policyKeys[dependents], errWithDesc{
					Err:         "dependant of invalid policy",
					Description: fmt.Sprintf("This policy depends on %s which is invalid", invalidPolicyKey),
				})
			}
		}
	}

	disabledPolicies, err := disable(ctx, slices.Collect(maps.Keys(policyKeys))...)
	if err != nil || disabledPolicies == 0 {
		return fmt.Errorf("failed to disable policies: %w", err)
	}

	return display(p, c.Format, colorLevel, policyKeys)
}

func (c *Cmd) Help() string {
	return help
}

func confirm(ctx context.Context, p *printer.Printer, msg string) bool {
	p.Printf("%s", msg)
	p.Printf("\n\nDo you want to continue [y/yes]?: ")

	ch := make(chan string, 1)

	go func() {
		var input string
		if _, err := fmt.Fscan(os.Stdin, &input); err != nil {
			panic(fmt.Errorf("failed to read confirmation input: %w", err))
		}

		ch <- input
		close(ch)
	}()

	var input string
	select {
	case input = <-ch:
		input = strings.ToLower(input)
	case <-ctx.Done():
		return false
	}

	if input == "y" || input == "yes" {
		return true
	}

	return false
}
