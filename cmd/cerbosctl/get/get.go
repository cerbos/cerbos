// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

const (
	getExample = `# List derived_roles
cerbosctl get derived_roles
cerbosctl get derived_role
cerbosctl get dr

# List and filter derived_roles
cerbosctl get derived_roles --name my_derived_roles

# List principal policies
cerbosctl get principal_policy
cerbosctl get principal_policies
cerbosctl get pp

# List and filter principal policies
cerbosctl get principal_policies --name donald_duck --version default

# List resource policies
cerbosctl get resource_policy
cerbosctl get resource_policies
cerbosctl get rp

# List and filter resource policies
cerbosctl get resource_policies --name leave_request --version default

# List all schemas
cerbosctl get schema
cerbosctl get schemas
cerbosctl get s

# Get policy
cerbosctl get policy derived_roles.my_derived_roles -oyaml

# Get policy (disk, git, blob stores)
cerbosctl get policy blog_derived_roles.yaml principal.yaml

# Get policy (mutable stores)
cerbosctl get policy derived_roles.my_derived_roles`
)

type Arguments struct {
	Output    string
	Name      []string
	Version   []string
	NoHeaders bool
}

var getArgs = &Arguments{}

func NewGetCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get",
		Short:   "Get",
		Example: getExample,
		RunE:    fn(runGetCmd),
	}

	cmd.Flags().BoolVar(&getArgs.NoHeaders, "no-headers", false, "Print no headers")
	cmd.Flags().StringVarP(&getArgs.Output, "output", "o", "json", "Output format for the policies; json, yaml, prettyjson formats are supported")
	cmd.Flags().StringSliceVar(&getArgs.Name, "name", []string{}, "Filter policies by name.")
	cmd.Flags().StringSliceVar(&getArgs.Version, "version", []string{}, "Filter policies by version.")

	return cmd
}

func runGetCmd(c client.AdminClient, cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		err := cmd.Help()
		if err != nil {
			return fmt.Errorf("failed to print help when no arguments provided")
		}
		return fmt.Errorf("no arguments provided")
	}

	resType, err := getResourceType(args[0])
	if err != nil {
		return fmt.Errorf("failed to get cmd and policy type from command arguments")
	}

	switch resType {
	case DerivedRole, PrincipalPolicy, ResourcePolicy:
		if len(args) == 1 {
			err = listPolicies(c, cmd, getArgs, resType)
			if err != nil {
				return fmt.Errorf("failed to list policies: %w", err)
			}

			return nil
		}

		err = getPolicy(c, cmd, getArgs, args[1:]...)
		if err != nil {
			return fmt.Errorf("failed to get policy: %w", err)
		}
	case Schema:
		if len(args) == 1 {
			err = listSchemas(c, cmd, getArgs)
			if err != nil {
				return fmt.Errorf("failed to list schemas: %w", err)
			}

			return nil
		}

		err = getSchema(c, cmd, getArgs, args[1:]...)
		if err != nil {
			return fmt.Errorf("failed to get schema: %w", err)
		}
	default:
		return fmt.Errorf("failed to determine command type")
	}

	return nil
}

func getResourceType(arg string) (ResourceType, error) {
	switch arg {
	case "dr", "derived_role", "derived_roles":
		return DerivedRole, nil
	case "pp", "principal_policy", "principal_policies":
		return PrincipalPolicy, nil
	case "rp", "resource_policy", "resource_policies":
		return ResourcePolicy, nil
	case "s", "schema", "schemas":
		return Schema, nil
	default:
		return Unspecified, fmt.Errorf("unknown command type")
	}
}

type ResourceType uint

const (
	Unspecified ResourceType = iota
	DerivedRole
	PrincipalPolicy
	ResourcePolicy
	Schema
)
