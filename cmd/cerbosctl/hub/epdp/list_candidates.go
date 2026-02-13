// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package epdp

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage/index"
)

const listCandidatesCmdHelp = `# List candidates for inclusion in embedded PDP

cerbosctl hub epdp list-candidates ./path/to/repo

cerbosctl hub epdp lc ./path/to/repo

# List candidates, print no headers

cerbosctl hub epdp list-candidates ./path/to/repo --no-headers

cerbosctl hub epdp lc ./path/to/repo --no-headers`

const (
	embeddedPDPKey      = "hub.cerbos.cloud/embedded-pdp"
	policyIDNotFoundYet = ""
)

type ListCandidatesCmd struct { //betteralign:ignore
	Path      string `arg:"" type:"path" help:"Path to repository"`
	NoHeaders bool   `help:"Do not output headers"`
}

func (c *ListCandidatesCmd) Run(k *kong.Kong) error {
	tw := printer.NewTableWriter(k.Stdout)
	if !c.NoHeaders {
		tw.Header([]string{"POLICY ID", "PATH"})
	}

	candidates, err := listCandidates(context.Background(), os.DirFS(c.Path))
	if err != nil {
		return fmt.Errorf("failed to list candidates: %w", err)
	}

	for policyKey, policyID := range candidates {
		if err := tw.Append([]string{policyKey, policyID}); err != nil {
			return fmt.Errorf("failed to append row to the table: %w", err)
		}
	}

	if err := tw.Render(); err != nil {
		return fmt.Errorf("failed to render table: %w", err)
	}

	return nil
}

func (c *ListCandidatesCmd) Help() string {
	return listCandidatesCmdHelp
}

func listCandidates(ctx context.Context, fsys fs.FS) (map[string]string, error) {
	idx, err := index.Build(ctx, fsys)
	if err != nil {
		return nil, fmt.Errorf("failed to build index: %w", err)
	}

	policyIDs, err := idx.ListPolicyIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	allPolicies := make(map[string]string, len(policyIDs))
	annotatedPolicies := make(map[string]string, len(policyIDs))
	for _, policyID := range policyIDs {
		policies, err := idx.LoadPolicy(ctx, policyID)
		if err != nil {
			return nil, err
		}
		if len(policies) == 0 {
			return nil, fmt.Errorf("failed to load policy %s", policyID)
		}

		wp := policies[0]
		policyKey := namer.PolicyKeyFromFQN(wp.FQN)
		allPolicies[policyKey] = policyID
		if pID, ok := annotatedPolicies[policyKey]; ok && pID == policyIDNotFoundYet {
			annotatedPolicies[policyKey] = policyID
		}
		if wp.Metadata == nil || wp.Metadata.Annotations == nil {
			continue
		}

		//nolint:nestif
		if value, ok := wp.Metadata.Annotations[embeddedPDPKey]; ok && value == "true" {
			annotatedPolicies[policyKey] = policyID
			fqns := namer.FQNTree(wp.Policy)
			if len(fqns) > 1 {
				for _, fqn := range fqns[1:] {
					key := namer.PolicyKeyFromFQN(fqn)
					if _, ok := annotatedPolicies[key]; !ok {
						if pID, ok := allPolicies[key]; ok {
							annotatedPolicies[key] = pID
						} else {
							annotatedPolicies[key] = policyIDNotFoundYet
						}
					}
				}
			}
		}
	}

	if len(annotatedPolicies) != 0 {
		return annotatedPolicies, nil
	}

	return allPolicies, nil
}
