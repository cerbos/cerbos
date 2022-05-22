package build

import "github.com/alecthomas/kong"

const help = `
Examples:

# Build policies found in the specified local store

cerbos build --store /path/to/policy/repo
`

type Cmd struct {
	Store     string `help:"Directory containing policies" required:"" type:"existingdir"`
	WorkDir   string `help:"Working directory. Defaults to OS temp directory" type:"existingdir"`
	OutputDir string `help:"Output directory. Defaults to current directory" type:"existingdir"`
	Version   string `help:"Policy version"`
	Resource  string `help:"Resource kind" required:""`
	Scope     string `help:"Scope"`
	Target    struct {
		Os   string `help:"Target OS" enum:"web,node,deno" default:"web"`
		Arch string `help:"Target architecture" enum:"wasm" default:"wasm"`
	} `help:"target platform" embed:"" prefix:"target."`
}

func (c *Cmd) Run(k *kong.Kong) error {
	k.Printf("%+v", *c)
	return nil
}

func (c *Cmd) Help() string {
	return help
}
