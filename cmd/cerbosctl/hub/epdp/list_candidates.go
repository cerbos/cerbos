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

const embeddedPDPKey = "hub.cerbos.cloud/embedded-pdp"

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

	for _, c := range candidates {
		tw.Append([]string{namer.PolicyKeyFromFQN(c.policyKey), c.storeIdentifier})
	}
	tw.Render()

	return nil
}

func listCandidates(ctx context.Context, loadPolicyFn loadPolicyFn, policyIDs ...string) ([]candidate, error) {
	allPolicies := make([]candidate, len(policyIDs))
	var annotatedPolicies []candidate
	for i, policyID := range policyIDs {
		p, err := loadPolicyFn(ctx, policyID)
		if err != nil {
			return nil, err
		}

		if p.Metadata == nil {
			allPolicies[i] = candidate{
				policyKey:       namer.PolicyKeyFromFQN(p.FQN),
				storeIdentifier: "-",
			}
			continue
		}

		allPolicies[i] = candidate{
			policyKey:       namer.PolicyKeyFromFQN(p.FQN),
			storeIdentifier: p.Metadata.StoreIdentifier,
		}

		if value, ok := p.Metadata.Annotations[embeddedPDPKey]; ok && value == "true" {
			annotatedPolicies = append(annotatedPolicies, candidate{
				policyKey:       namer.PolicyKeyFromFQN(p.FQN),
				storeIdentifier: p.Metadata.StoreIdentifier,
			})
		}
	}

	if len(annotatedPolicies) != 0 {
		return annotatedPolicies, nil
	}

	return allPolicies, nil
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

type candidate struct {
	policyKey       string
	storeIdentifier string
}
