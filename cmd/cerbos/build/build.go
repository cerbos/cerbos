package build

import (
	"github.com/alecthomas/kong"
	"os"
	"github.com/cerbos/cerbos/internal/storage/index"
	"fmt"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"os/signal"
	"context"
	"errors"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/fatih/color"
	"github.com/pterm/pterm"
	"github.com/cerbos/cerbos/internal/printer"
	"github.com/cerbos/cerbos/internal/wasm"
)

const help = `
Examples:

# Build policies found in the specified local store
cerbos build --store /path/to/policy/repo

Environment must provide:
- Rust toolchain.
- wasm-pack (https://rustwasm.github.io/wasm-pack/)
`

type Cmd struct {
	Store     string `help:"Directory containing policies" required:"" type:"existingdir"`
	WorkDir   string `help:"Working directory. Defaults to OS temp directory" type:"existingdir"`
	OutputDir string `help:"Output directory" required:"" type:"existingdir"`
	PolicyVer string `help:"Policy version"`
	Resource  string `help:"Resource kind" required:""`
	Scope     string `help:"Scope" default:""`
	Target    struct {
		Os   string `help:"Target OS" enum:"web,node,deno" default:"web"`
		Arch string `help:"Target architecture" enum:"wasm" default:"wasm"`
	} `help:"target platform" embed:"" prefix:"target."`
	Color   *outputcolor.Level `help:"Output color level (auto,never,always,256,16m). Defaults to auto." xor:"color"`
	NoColor bool               `help:"Disable colored output" xor:"color"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	colorLevel := c.Color.Resolve(c.NoColor)

	color.NoColor = !colorLevel.Enabled()

	if colorLevel.Enabled() {
		pterm.EnableColor()
	} else {
		pterm.DisableColor()
	}

	p := printer.New(k.Stdout, k.Stderr)

	if c.Scope != "" {
		// TODO: Support scoped policies
		return fmt.Errorf("scopes aren't supported")
	}

	idx, err := index.Build(ctx, os.DirFS(c.Store))
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			displayList(p, idxErr)
			return idxErr
		}

		return fmt.Errorf("failed to open directory %s: %w", c.Store, err)
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	builder, err := wasm.NewBuilder(store, c.workDir(), c.OutputDir)
	_, err = builder.FromPolicy(ctx, c.Resource, c.PolicyVer, c.Scope)
	if err != nil {
		return err
	}
	return nil
}

func (c *Cmd) workDir() string {
	if c.WorkDir != "" {
		return c.WorkDir
	}

	return os.TempDir()
}

func (c *Cmd) Help() string {
	return help
}
