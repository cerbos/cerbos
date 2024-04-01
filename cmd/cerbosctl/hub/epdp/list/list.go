// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"context"
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
	"github.com/cerbos/cerbos/internal/storage/index"
)

const embeddedPDPKey = "hub.cerbos.cloud/embedded-pdp"

type Cmd struct {
	Path      string `arg:"" type:"path" help:"Path to repository"`
	NoHeaders bool   `help:"Do not output headers"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	idx, err := index.Build(context.Background(), os.DirFS(c.Path))
	if err != nil {
		return fmt.Errorf("failed to build index: %w", err)
	}

	policyIDs, err := idx.ListPolicyIDs(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	policies, err := idx.LoadPolicy(context.Background(), policyIDs...)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	tw := printer.NewTableWriter(k.Stdout)
	if !c.NoHeaders {
		tw.SetHeader([]string{"POLICY ID", "PATH"})
	}

	items := make([]item, len(policies))
	foundAnnotation := false
	for i, p := range policies {
		hasAnnotation := false
		if value, ok := p.Metadata.Annotations[embeddedPDPKey]; ok && value == "true" {
			foundAnnotation = true
			hasAnnotation = true
		}
		items[i] = item{
			storeIdentifier: p.Metadata.StoreIdentifier,
			fqn:             p.FQN,
			hasAnnotation:   hasAnnotation,
		}
	}

	for _, i := range items {
		if !foundAnnotation {
			tw.Append([]string{i.fqn, i.storeIdentifier})
		} else if i.hasAnnotation {
			tw.Append([]string{i.fqn, i.storeIdentifier})
		}
	}

	tw.Render()
	return nil
}

type item struct {
	storeIdentifier string
	fqn             string
	hasAnnotation   bool
}
