// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package put

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/client"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put/internal/errors"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put/internal/files"
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

	policies := client.NewPolicySet()
	var errs []error
	err := files.Find(pc.Paths, put.Recursive, util.FileTypePolicy, func(file files.Found) error {
		_, err := policies.AddPolicyFromFileWithErr(file.AbsolutePath)
		if err != nil {
			errs = append(errs, errors.NewPutError(file.AbsolutePath, err.Error()))
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = ctx.AdminClient.AddOrUpdatePolicy(context.TODO(), policies)
	if err != nil {
		return fmt.Errorf("failed to add or update the policies: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Uploaded: %d\nIgnored: %d\n", policies.Size(), len(errs))
	if len(errs) != 0 {
		_, _ = fmt.Fprintln(k.Stdout, "Errors:")
	}
	for _, putErr := range errs {
		_, _ = fmt.Fprintf(k.Stdout, "- %s\n", putErr.Error())
	}

	return nil
}

func (pc *PolicyCmd) Help() string {
	return policyCmdHelp
}
