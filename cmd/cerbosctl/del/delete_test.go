// Copyright 2021-2023 Zenauth Ltd.
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

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername     = "cerbos"
	adminPassword     = "cerbosAdmin"
	readyTimeout      = 60 * time.Second
	timeout           = 30 * time.Second
	readyPollInterval = 50 * time.Millisecond
)

func TestDeleteCmd(t *testing.T) {
	s := mkServer(t)
	defer s.Stop() //nolint:errcheck

	globals := mkGlobals(t, s.GRPCAddr())
	ctx, _ := context.WithTimeout(context.Background(), timeout)
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

func loadSchemas(t *testing.T, ac client.AdminClient) {
	t.Helper()

	fsys := os.DirFS(test.PathToDir(t, filepath.Join("schema", "fs", schema.Directory)))

	s, err := schema.ReadSchemaFromFile(fsys, "address.json")
	require.NoError(t, err)
	s2, err := schema.ReadSchemaFromFile(fsys, "complex_object.json")
	require.NoError(t, err)

	ss := client.NewSchemaSet()
	ss.AddSchemas(s)
	ss.AddSchemas(s2)
	require.NoError(t, ac.AddOrUpdateSchema(context.Background(), ss))
}

func mkServerOpts(t *testing.T) []testutil.ServerOpt {
	t.Helper()

	serverOpts := []testutil.ServerOpt{
		testutil.WithPolicyRepositorySQLite3(fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))),
		testutil.WithAdminAPI(adminUsername, adminPassword),
	}

	return serverOpts
}

func mkServer(t *testing.T) *testutil.ServerInfo {
	t.Helper()

	s, err := testutil.StartCerbosServer(mkServerOpts(t)...)
	require.NoError(t, err)
	require.Eventually(t, serverIsReady(s), readyTimeout, readyPollInterval)

	return s
}

func serverIsReady(s *testutil.ServerInfo) func() bool {
	return func() bool {
		ctx, cancelFunc := context.WithTimeout(context.Background(), readyPollInterval)
		defer cancelFunc()

		ready, err := s.IsReady(ctx)
		if err != nil {
			return false
		}

		return ready
	}
}

func mkGlobals(t *testing.T, address string) *flagset.Globals {
	t.Helper()

	return &flagset.Globals{
		Server:    address,
		Username:  adminUsername,
		Password:  adminPassword,
		Plaintext: true,
	}
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
