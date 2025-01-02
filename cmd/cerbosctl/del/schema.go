// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package del

import (
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/del/internal/schema"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const schemaCmdHelp = `# Delete schemas
cerbosctl delete schemas principal.json
cerbosctl delete schema principal.json
cerbosctl delete s principal.json

# Delete multiple schemas
cerbosctl delete schemas principal.json leave_request.json
cerbosctl delete schema principal.json leave_request.json
cerbosctl delete s principal.json leave_request.json`

type SchemaCmd struct {
	SchemaIds []string `arg:"" name:"id" help:"list of schema ids to delete"` //nolint:revive
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	if len(c.Schema.SchemaIds) == 0 {
		return fmt.Errorf("no schema id(s) provided")
	}

	deletedSchemas, err := schema.Delete(ctx.AdminClient, c.Schema.SchemaIds...)
	if err != nil {
		return fmt.Errorf("failed to delete schemas: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Number of schemas deleted is %d", deletedSchemas)
	return nil
}

func (sc *SchemaCmd) Help() string {
	return schemaCmdHelp
}
