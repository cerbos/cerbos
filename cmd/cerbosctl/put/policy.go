// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/alecthomas/kong"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/policy"
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

	ps := client.NewPolicySet()
	ps.AddPolicies(policies...)

	err = ctx.AdminClient.AddOrUpdatePolicy(context.TODO(), ps)
	if err != nil {
		return fmt.Errorf("failed to add or update the policies: %w", err)
	}

	return nil
}

func (pc *PolicyCmd) Help() string {
	return policyCmdHelp
}

func (pc *PolicyCmd) findFiles(paths []string, recursive bool) ([]*policyv1.Policy, error) {
	var policies []*policyv1.Policy
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

				if d.IsDir() && recursive {
					return nil
				} else if d.IsDir() && !recursive && d.Name() != "." {
					return fs.SkipDir
				}

				if d.IsDir() {
					return nil
				}

				if !util.IsSupportedFileType(d.Name()) {
					return nil
				}

				p := &policyv1.Policy{}
				if err := util.LoadFromJSONOrYAML(fsys, path, p); err != nil {
					return nil //nolint:nilerr
				}

				if err := policy.Validate(p); err != nil {
					return nil //nolint:nilerr
				}
				policies = append(policies, p)

				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			if !util.IsSupportedFileType(fileInfo.Name()) {
				return nil, fmt.Errorf("unsupported file type %q: %w", path, err)
			}

			f, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open file %q: %w", path, err)
			}

			p, err := policy.ReadPolicy(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read policy file %q: %w", path, err)
			}

			if err := policy.Validate(p); err != nil {
				return nil, fmt.Errorf("failed to validate policy file %q: %w", path, err)
			}

			policies = append(policies, p)
		}
	}

	return policies, nil
}
