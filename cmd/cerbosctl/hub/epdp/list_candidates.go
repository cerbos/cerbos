// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package epdp

import (
	"context"
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/index"
)

const listCandidatesCmdHelp = `# List candidates

cerbosctl hub epdp list-candidates ./path/to/repo

cerbosctl hub epdp lc ./path/to/repo

# List candidates, print no headers

cerbosctl hub epdp list-candidates ./path/to/repo --no-headers

cerbosctl hub epdp lc ./path/to/repo --no-headers`

const (
	embeddedPDPKey       = "hub.cerbos.cloud/embedded-pdp"
	policyNotFoundInRepo = ""
)

type loadPolicyFn func(ctx context.Context, name string) (*policy.Wrapper, error)

type ListCandidatesCmd struct {
	Path      string `arg:"" type:"path" help:"Path to repository"`
	NoHeaders bool   `help:"Do not output headers"`
}

func (c *ListCandidatesCmd) Run(k *kong.Kong) error {
	ctx := context.Background()
	idx, err := index.Build(ctx, os.DirFS(c.Path))
	if err != nil {
		return fmt.Errorf("failed to build index: %w", err)
	}

	policyIDs, err := idx.ListPolicyIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	tw := printer.NewTableWriter(k.Stdout)
	if !c.NoHeaders {
		tw.SetHeader([]string{"POLICY ID", "PATH"})
	}

	candidates, err := listCandidates(ctx, loadPolicy(idx), policyIDs...)
	if err != nil {
		return fmt.Errorf("failed to list candidates: %w", err)
	}

	for policyKey, policyID := range candidates {
		tw.Append([]string{namer.PolicyKeyFromFQN(policyKey), policyID})
	}
	tw.Render()

	return nil
}

func (c *ListCandidatesCmd) Help() string {
	return listCandidatesCmdHelp
}

func listCandidates(ctx context.Context, loadPolicyFn loadPolicyFn, policyIDs ...string) (map[string]string, error) {
	allPolicies := make(map[string]string, len(policyIDs))
	annotatedPolicies := make(map[string]string, len(policyIDs))
	for _, policyID := range policyIDs {
		p, err := loadPolicyFn(ctx, policyID)
		if err != nil {
			return nil, err
		}

		policyKey := namer.PolicyKeyFromFQN(p.FQN)
		allPolicies[policyKey] = policyID
		if pID, ok := annotatedPolicies[policyKey]; ok && pID == policyNotFoundInRepo {
			annotatedPolicies[policyKey] = policyID
		}
		if p.Metadata == nil || p.Metadata.Annotations == nil {
			continue
		}

		//nolint:nestif
		if value, ok := p.Metadata.Annotations[embeddedPDPKey]; ok && value == "true" {
			annotatedPolicies[policyKey] = policyID
			fqns := namer.FQNTree(p.Policy)
			if len(fqns) > 1 {
				for _, fqn := range fqns[1:] {
					if _, ok := annotatedPolicies[namer.PolicyKeyFromFQN(fqn)]; !ok {
						if pID, ok := allPolicies[namer.PolicyKeyFromFQN(fqn)]; ok {
							annotatedPolicies[namer.PolicyKeyFromFQN(fqn)] = pID
						} else {
							annotatedPolicies[namer.PolicyKeyFromFQN(fqn)] = policyNotFoundInRepo
						}
					}
				}
			}
		}
	}

	var policies map[string]string
	if len(annotatedPolicies) != 0 {
		policies = annotatedPolicies
	} else {
		policies = allPolicies
	}

	for policyKey, policyID := range policies {
		if policyID == policyNotFoundInRepo {
			delete(policies, policyKey)
		}
	}

	return policies, nil
}

func loadPolicy(idx index.Index) loadPolicyFn {
	return func(ctx context.Context, name string) (*policy.Wrapper, error) {
		policies, err := idx.LoadPolicy(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy %s: %w", name, err)
		}

		if len(policies) == 0 {
			return nil, fmt.Errorf("failed to find any policy with the name %s", name)
		}

		return policies[0], nil
	}
}
