// Copyright 2021-2026 Zenauth Ltd.
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
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
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
	loadPolicies(t, cctx.AdminClient)
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
					ids     []string
					wantErr bool
				}{
					{
						[]string{"policies", "policy", "p"},
						[]string{"derived_roles.my_derived_roles"},
						false,
					},
					{
						[]string{"policies", "policy", "p"},
						[]string{"derived_roles.my_derived_roles", "resource.leave_request.vdefault"},
						false,
					},
					{
						[]string{"schemas", "schema", "s"},
						[]string{"principal.json"},
						false,
					},
					{
						[]string{"schemas", "schema", "s"},
						[]string{"principal.json", "leave_request.json"},
						false,
					},
				}

				for idx, tc := range testCases {
					t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
						for _, arg := range tc.args {
							cli := root.Cli{}
							p := mustNew(t, &cli)
							_, err := p.Parse(append([]string{"delete", arg}, tc.ids...))
							if tc.wantErr {
								require.Error(t, err)
							} else {
								require.NoError(t, err)
							}
						}
					})
				}
			})
			t.Run("delete and check", func(t *testing.T) {
				testCases := []struct {
					kind string
					ids  []string
				}{
					{
						kind: "policy",
						ids:  []string{"derived_roles.apatr_common_roles"},
					},
					{
						kind: "policies",
						ids:  []string{"derived_roles.alpha", "resource.global.vdefault"},
					},
					{
						kind: "schema",
						ids:  []string{"address.json"},
					},
					{
						kind: "schemas",
						ids:  []string{"complex_object.json", "customer_absolute.json"},
					},
				}

				for idx, tc := range testCases {
					t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						switch tc.kind {
						case "policies", "policy", "p":
							policies, err := cctx.AdminClient.GetPolicy(ctx, tc.ids...)
							require.NoError(t, err)
							require.NotNil(t, policies)
							require.Len(t, policies, len(tc.ids))
							t.Log(namer.PolicyKey(policies[0]))
						case "schemas", "schema", "s":
							schemas, err := cctx.AdminClient.GetSchema(ctx, tc.ids...)
							require.NoError(t, err)
							require.NotNil(t, schemas)
							require.Len(t, schemas, len(tc.ids))
						default:
							t.Fatalf("unknown kind: %s", tc.kind)
						}

						kctx, err := p.Parse(append([]string{"delete", tc.kind}, tc.ids...))
						require.NoError(t, err)
						err = kctx.Run(cctx, globals)
						require.NoError(t, err)

						switch tc.kind {
						case "policies", "policy", "p":
							t.Log(out.String())
							require.Contains(t, out.String(), fmt.Sprintf("Number of policies deleted is %d", len(tc.ids)))
						case "schemas", "schema", "s":
							require.Contains(t, out.String(), fmt.Sprintf("Number of schemas deleted is %d", len(tc.ids)))
						default:
							t.Fatalf("unknown kind: %s", tc.kind)
						}

						switch tc.kind {
						case "policies", "policy", "p":
							policies, err := cctx.AdminClient.GetPolicy(ctx, tc.ids...)
							require.NoError(t, err)
							require.Nil(t, policies)
						case "schemas", "schema", "s":
							schemas, err := cctx.AdminClient.GetSchema(ctx, tc.ids...)
							require.Error(t, err)
							require.Nil(t, schemas)
						default:
							t.Fatalf("unknown kind: %s", tc.kind)
						}
					})
				}
			})
			t.Run("delete nonexistent", func(t *testing.T) {
				testCases := []struct {
					kind string
					ids  []string
				}{
					{
						"policies",
						[]string{"derived_roles.non_existent_derived_roles"},
					},
					{
						"schemas",
						[]string{"nonexistent.json"},
					},
				}

				for idx, tc := range testCases {
					t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						kctx, err := p.Parse(append([]string{"delete", tc.kind}, tc.ids...))
						require.NoError(t, err)
						err = kctx.Run(cctx, globals)
						require.NoError(t, err)
					})
				}
			})
		})
	}
}

func loadPolicies(t *testing.T, ac *cerbos.GRPCAdminClient) {
	t.Helper()

	fsys := os.DirFS(test.PathToDir(t, "store"))

	p, err := policy.ReadPolicyFromFile(fsys, filepath.Join("derived_roles", "common_roles.yaml"))
	require.NoError(t, err)
	p2, err := policy.ReadPolicyFromFile(fsys, filepath.Join("derived_roles", "derived_roles_01.yaml"))
	require.NoError(t, err)
	p3, err := policy.ReadPolicyFromFile(fsys, filepath.Join("resource_policies", "policy_08.yaml"))
	require.NoError(t, err)

	t.Logf("Loading %s", namer.PolicyKey(p))
	t.Logf("Loading %s", namer.PolicyKey(p2))
	t.Logf("Loading %s", namer.PolicyKey(p3))

	ps := cerbos.NewPolicySet()
	ps.AddPolicies(p)
	ps.AddPolicies(p2)
	ps.AddPolicies(p3)
	require.NoError(t, ac.AddOrUpdatePolicy(t.Context(), ps))
}

func loadSchemas(t *testing.T, ac *cerbos.GRPCAdminClient) {
	t.Helper()

	fsys := os.DirFS(test.PathToDir(t, filepath.Join("schema", "fs", schema.Directory)))

	s, err := schema.ReadSchemaFromFile(fsys, "address.json")
	require.NoError(t, err)
	s2, err := schema.ReadSchemaFromFile(fsys, "complex_object.json")
	require.NoError(t, err)
	s3, err := schema.ReadSchemaFromFile(fsys, "customer_absolute.json")
	require.NoError(t, err)

	ss := cerbos.NewSchemaSet()
	ss.AddSchemas(s)
	ss.AddSchemas(s2)
	ss.AddSchemas(s3)
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
