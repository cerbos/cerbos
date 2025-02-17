// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package del_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/test"
)

const timeout = 30 * time.Second

func TestDeleteCmd(t *testing.T) {
	s := internal.StartTestServer(t)
	defer s.Stop() //nolint:errcheck

	globals := internal.CreateGlobalsFlagset(t, s.GRPCAddr())
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	cctx := mkClients(t, globals)
	loadSchemas(t, cctx.AdminClient)
	testDeleteCmd(ctx, cctx, globals)(t)
}

func testDeleteCmd(ctx context.Context, cctx *cmdclient.Context, globals *flagset.Globals) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		t.Run("cerbosctl delete", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"delete"})
				require.Error(t, err)
			})
			t.Run("possible arguments after delete command", func(t *testing.T) {
				testCases := []struct {
					args    []string
					wantErr bool
				}{
					{
						[]string{"schemas", "schema", "s"},
						false,
					},
				}

				for _, tc := range testCases {
					for _, arg := range tc.args {
						cli := root.Cli{}
						p := mustNew(t, &cli)
						_, err := p.Parse([]string{"delete", arg, "principal.json"})
						if tc.wantErr {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					}
				}
			})
			t.Run("delete and check", func(t *testing.T) {
				testCases := []struct {
					schemaID string
				}{
					{
						schemaID: "address.json",
					},
					{
						schemaID: "complex_object.json",
					},
				}
				for idx, tc := range testCases {
					t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						schemas, err := cctx.AdminClient.GetSchema(ctx, tc.schemaID)
						require.NoError(t, err)
						require.NotNil(t, schemas)
						require.NotNil(t, schemas[0])

						kctx, err := p.Parse([]string{"delete", "schema", tc.schemaID})
						require.NoError(t, err)
						err = kctx.Run(cctx, globals)
						require.NoError(t, err)

						require.Contains(t, out.String(), "Number of schemas deleted is 1")

						schemas, err = cctx.AdminClient.GetSchema(ctx, tc.schemaID)
						require.Error(t, err)
						require.Nil(t, schemas)
					})
				}
			})
			t.Run("delete nonexisting schema", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				out := bytes.NewBufferString("")
				p.Stdout = out

				kctx, err := p.Parse([]string{"delete", "schema", "nonexistent.json"})
				require.NoError(t, err)
				err = kctx.Run(cctx, globals)
				require.NoError(t, err)
			})
		})
	}
}

func loadSchemas(t *testing.T, ac *cerbos.GRPCAdminClient) {
	t.Helper()

	fsys := os.DirFS(test.PathToDir(t, filepath.Join("schema", "fs", schema.Directory)))

	s, err := schema.ReadSchemaFromFile(fsys, "address.json")
	require.NoError(t, err)
	s2, err := schema.ReadSchemaFromFile(fsys, "complex_object.json")
	require.NoError(t, err)

	ss := cerbos.NewSchemaSet()
	ss.AddSchemas(s)
	ss.AddSchemas(s2)
	require.NoError(t, ac.AddOrUpdateSchema(t.Context(), ss))
}

func mkClients(t *testing.T, globals *flagset.Globals) *cmdclient.Context {
	t.Helper()

	c, err := cmdclient.GetClient(globals)
	require.NoError(t, err)

	ac, err := cmdclient.GetAdminClient(globals)
	require.NoError(t, err)

	return &cmdclient.Context{Client: c, AdminClient: ac}
}

func mustNew(t *testing.T, cli any) *kong.Kong {
	t.Helper()
	options := []kong.Option{
		kong.Name("cerbosctl"),
		kong.Description("A CLI for managing Cerbos"),
		kong.UsageOnError(),
	}
	parser, err := kong.New(cli, options...)
	require.NoError(t, err)
	return parser
}
