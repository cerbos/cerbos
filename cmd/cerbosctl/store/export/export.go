// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	internalclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/store/export/internal"
	"github.com/cerbos/cerbos/internal/util"
)

const help = `# Export policies and schemas from the store into a directory
cerbosctl store export path/to/dir

# Export policies and schemas from the store into a zip archive
cerbosctl store export archive.zip

# Export policies and schemas from the store into a gzip archive
cerbosctl store export path/to/archive.gzip
cerbosctl store export path/to/archive.tar.gz`

type Cmd struct {
	Path string `arg:"" help:"Path to write policies and schemas" type:"path"`
}

func (c *Cmd) Run(k *kong.Kong, clientCtx *internalclient.Context) error {
	policies, err := clientCtx.AdminClient.ListPolicies(context.Background(), cerbos.WithIncludeDisabled())
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	schemas, err := clientCtx.AdminClient.ListSchemas(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list schemas: %w", err)
	}

	exporter, err := internal.NewExporter(c.Path)
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}
	defer exporter.Close()

	if err := cerbos.BatchAdminClientCall2(context.Background(), clientCtx.AdminClient.GetPolicy, func(_ context.Context, policies []*policyv1.Policy) error {
		for _, p := range policies {
			name := p.Metadata.StoreIdentifier

			ext, ok := util.IsSupportedFileTypeExt(name)
			if !ok {
				name = strings.ReplaceAll(name, "/", "_")
			}

			jsonString := protojson.Format(p)
			switch ext {
			case ".json":
				if err := exporter.WriteJSON(name, []byte(jsonString)); err != nil {
					return fmt.Errorf("failed to write policy %s: %w", name, err)
				}
			case ".yml", ".yaml":
				if err := exporter.WriteYAML(name, []byte(jsonString)); err != nil {
					return fmt.Errorf("failed to write policy %s: %w", name, err)
				}
			default:
				name = fmt.Sprintf("%s.yaml", name)
				if err := exporter.WriteYAML(name, []byte(jsonString)); err != nil {
					return fmt.Errorf("failed to write policy %s: %w", name, err)
				}
			}

			_, _ = fmt.Fprintf(k.Stdout, "🗸 %s (policy)\n", name)
		}

		return nil
	}, policies...); err != nil {
		return fmt.Errorf("error while getting policies: %w", err)
	}

	if err := cerbos.BatchAdminClientCall2(context.Background(), clientCtx.AdminClient.GetSchema, func(_ context.Context, schemas []*schemav1.Schema) error {
		for _, s := range schemas {
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, s.Definition, "", "  "); err != nil {
				return fmt.Errorf("failed to indent schema definition JSON: %w", err)
			}

			name := filepath.Join(util.SchemasDirectory, s.Id)
			if err := exporter.WriteJSON(name, pretty.Bytes()); err != nil {
				return fmt.Errorf("failed to write schema %s: %w", name, err)
			}

			_, _ = fmt.Fprintf(k.Stdout, "🗸 %s (schema)\n", name)
		}

		return nil
	}, schemas...); err != nil {
		return fmt.Errorf("error while getting schemas: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "\nExported %d policies and %d schemas to %s\n", len(policies), len(schemas), c.Path)
	return nil
}

func (c *Cmd) Help() string {
	return help
}
