// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compilestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/fatih/color"
	"github.com/pterm/pterm"
	"helm.sh/helm/v3/pkg/strvals"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/cmd/cerbos/internal/compilation"
	"github.com/cerbos/cerbos/cmd/cerbos/internal/flagset"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db"
	"github.com/cerbos/cerbos/internal/storage/db/mysql"
	"github.com/cerbos/cerbos/internal/storage/db/postgres"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/git"
	"github.com/cerbos/cerbos/internal/util"
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
	Config         string   `help:"Path to config file" arg:"" required:"" type:"path" placeholder:".cerbos.yaml" env:"CERBOS_CONFIG"`
	Set            []string `help:"Config overrides" placeholder:"server.adminAPI.enabled=true"`
	DisableInvalid bool     `help:"Disable invalid policies if database store" placeholder:"false"`
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
		return err
	}

	if c.DisableInvalid && disable == nil {
		return errors.New("only database stores support --disable-invalid flag")
	}

	var compErr *compile.ErrorSet
	if err := cm.GetAllStreaming(ctx, func(_ *runtimev1.RunnablePolicySet) error {
		return nil
	}); err != nil && !errors.As(err, &compErr) {
		return fmt.Errorf("failed to compile policies: %w", err)
	} else if err == nil {
		return nil
	}

	if !c.DisableInvalid || disable == nil {
		return internalcompile.Display(p, *compErr, c.Format, colorLevel)
	}

	policyKeys := make(util.StringSet)
	for _, err := range compErr.Errors().GetErrors() {
		policyKeys[strings.TrimSuffix(strings.TrimPrefix(err.GetFile(), "<"), ">")] = struct{}{}
	}

	if len(policyKeys) == 0 {
		return nil
	}

	return c.disableInvalidPolicies(ctx, p, disable, policyKeys)
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
	conf, err := storage.GetConf()
	if err != nil {
		return nil, nil, err
	}

	var ss storage.SourceStore
	var fn disableFn
	switch conf.Driver {
	case blob.DriverName:
		conf := new(blob.Conf)
		if err := config.GetSection(conf); err != nil {
			return nil, nil, fmt.Errorf("failed to read blob configuration: %w", err)
		}

		store, err := blob.NewStore(ctx, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create to blob store: %w", err)
		}
		ss = store
	case disk.DriverName:
		conf := new(disk.Conf)
		if err := config.GetSection(conf); err != nil {
			return nil, nil, fmt.Errorf("failed to read disk configuration: %w", err)
		}

		store, err := disk.NewStore(ctx, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create to disk store: %w", err)
		}
		ss = store
	case git.DriverName:
		conf := new(git.Conf)
		if err := config.GetSection(conf); err != nil {
			return nil, nil, fmt.Errorf("failed to read git configuration: %w", err)
		}

		store, err := git.NewStore(ctx, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create to git store: %w", err)
		}
		ss = store
	case mysql.DriverName:
		conf := new(mysql.Conf)
		if err := config.GetSection(conf); err != nil {
			return nil, nil, fmt.Errorf("failed to read mysql configuration: %w", err)
		}

		store, err := mysql.NewStore(ctx, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create to mysql store: %w", err)
		}
		ss = store
		fn = store.Disable
	case postgres.DriverName:
		conf := new(postgres.Conf)
		if err := config.GetSection(conf); err != nil {
			return nil, nil, fmt.Errorf("failed to read postgres configuration: %w", err)
		}

		store, err := postgres.NewStore(ctx, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create to postgres store: %w", err)
		}
		ss = store
		fn = store.Disable
	case sqlite3.DriverName:
		conf := new(sqlite3.Conf)
		if err := config.GetSection(conf); err != nil {
			return nil, nil, fmt.Errorf("failed to read sqlite3 configuration: %w", err)
		}

		store, err := sqlite3.NewStore(ctx, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create to sqlite3 store: %w", err)
		}
		ss = store
		fn = store.Disable
	default:
		return nil, nil, fmt.Errorf("unsupported driver: %s", conf.Driver)
	}

	cm, err := compile.NewManager(ctx, ss)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create compile manager: %w", err)
	}

	return cm, fn, nil
}

func (c *Cmd) disableInvalidPolicies(ctx context.Context, p *printer.Printer, disable disableFn, policyKeys util.StringSet) error {
	var integrityErr *db.IntegrityErr
	pk := policyKeys.ToSlice()
	if disabledPolicies, err := disable(ctx, pk...); err != nil && !errors.As(err, &integrityErr) {
		return fmt.Errorf("failed to disable policies: %w", err)
	} else if integrityErr == nil {
		p.Printf("Successfully disabled %d policies breaking the store: %s\n", disabledPolicies, strings.Join(pk, ", "))
	}

	for _, ierr := range integrityErr.Errors {
		if ierr.GetBreaksScopeChain() != nil {
			for _, descendant := range ierr.GetBreaksScopeChain().GetDescendants() {
				policyKeys[descendant] = struct{}{}
			}
		}

		if ierr.GetRequiredByOtherPolicies() != nil {
			for _, dependents := range ierr.GetRequiredByOtherPolicies().GetDependents() {
				policyKeys[dependents] = struct{}{}
			}
		}
	}

	pk = policyKeys.ToSlice()
	disabledPolicies, err := disable(ctx, pk...)
	if err != nil || disabledPolicies == 0 {
		return fmt.Errorf("failed to disable policies: %w", err)
	}

	p.Printf("Successfully disabled %d policies breaking the store: %s\n", disabledPolicies, strings.Join(pk, ", "))
	return nil
}

func (c *Cmd) Help() string {
	return help
}
