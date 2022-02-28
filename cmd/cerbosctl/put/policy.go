// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/client"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/util"
)

const policyCmdHelp = `# Put policies
cerbosctl put policies ./path/to/policy.yaml
cerbosctl put policy ./path/to/policy.yaml
cerbosctl put p ./path/to/policy.yaml

# Put multiple policies
cerbosctl put policy ./path/to/policy.yaml ./path/to/other/policy.yaml

# Put policies under a directory
cerbosctl put policy ./dir/to/policies ./other/dir/to/policies

# Put policies under a directory recursively
cerbosctl put policy --recursive ./dir/to/policies
cerbosctl put policy -R ./dir/to/policies`

type PolicyCmd struct {
	Paths []string `arg:"" type:"path" help:"Path to policy file or directory"`
}

func (pc *PolicyCmd) Run(k *kong.Kong, put *Cmd, ctx *cmdclient.Context) error {
	if len(pc.Paths) == 0 {
		return fmt.Errorf("no filename(s) provided")
	}

	policies, err := pc.findFiles(pc.Paths, put.Recursive)
	if err != nil {
		return err
	}

	err = ctx.AdminClient.AddOrUpdatePolicy(context.TODO(), policies)
	if err != nil {
		return fmt.Errorf("failed to add or update the policies: %w", err)
	}

	return nil
}

func (pc *PolicyCmd) Help() string {
	return policyCmdHelp
}

func (pc *PolicyCmd) findFiles(paths []string, recursive bool) (*client.PolicySet, error) {
	policies := client.NewPolicySet()
	for _, path := range paths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		//nolint:nestif
		if fileInfo.IsDir() {
			fsys := os.DirFS(path)
			err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					switch {
					case recursive:
						return nil
					case d.Name() != ".":
						return fs.SkipDir
					}
				}

				if !util.IsSupportedFileType(d.Name()) {
					return nil
				}

				policies.AddPolicyFromFS(fsys, path)

				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			if !util.IsSupportedFileType(fileInfo.Name()) {
				return nil, fmt.Errorf("unsupported file type %q: %w", path, err)
			}

			policies.AddPolicyFromFile(path)
		}
	}

	if err := policies.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate policy set: %w", err)
	}

	return policies, nil
}
