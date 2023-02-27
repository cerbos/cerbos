// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package enable_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername     = "cerbos"
	adminPassword     = "cerbosAdmin"
	policiesPerType   = 30
	readyTimeout      = 60 * time.Second
	timeout           = 30 * time.Second
	readyPollInterval = 50 * time.Millisecond
)

func TestEnableCmd(t *testing.T) {
	s := mkServer(t)
	defer s.Stop() //nolint:errcheck

	globals := mkGlobals(t, s.GRPCAddr())
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	cctx := mkClients(t, globals)
	loadPolicies(t, cctx.AdminClient)
	testEnableCmd(ctx, cctx, globals)(t)
}

func testEnableCmd(ctx context.Context, cctx *cmdclient.Context, globals *flagset.Globals) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		t.Run("cerbosctl enable", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"enable"})
				require.Error(t, err)
			})
			t.Run("possible arguments after enable command", func(t *testing.T) {
				testCases := []struct {
					args    []string
					wantErr bool
				}{
					{
						[]string{"policy", "policies", "p"},
						false,
					},
				}

				for _, tc := range testCases {
					for _, arg := range tc.args {
						cli := root.Cli{}
						p := mustNew(t, &cli)
						_, err := p.Parse([]string{"enable", arg, "resource.leave_request.vdefault"})
						if tc.wantErr {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					}
				}
			})
			t.Run("enable and check", func(t *testing.T) {
				testCases := []struct {
					policyKey string
				}{
					{
						policyKey: "derived_roles.my_derived_roles_1",
					},
					{
						policyKey: "principal.donald_duck_1.vdefault",
					},
					{
						policyKey: "principal.donald_duck_1.vdefault/acme.hr",
					},
					{
						policyKey: "resource.leave_request_1.vdefault",
					},
					{
						policyKey: "resource.leave_request_1.vdefault/acme.hr.uk",
					},
				}
				for idx, tc := range testCases {
					t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						policies, err := cctx.AdminClient.GetPolicy(ctx, tc.policyKey)
						require.NoError(t, err)
						require.NotNil(t, policies)
						require.NotNil(t, policies[0])
						require.True(t, policies[0].Disabled)

						kctx, err := p.Parse([]string{"enable", "policy", tc.policyKey})
						require.NoError(t, err)
						err = kctx.Run(cctx, globals)
						require.NoError(t, err)

						policies, err = cctx.AdminClient.GetPolicy(ctx, tc.policyKey)
						require.NoError(t, err)
						require.NotNil(t, policies)
						require.NotNil(t, policies[0])
						require.False(t, policies[0].Disabled)
						require.Contains(t, out.String(), "Number of policies enabled is 1")
					})
				}
			})
			t.Run("enable nonexisting policy", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				out := bytes.NewBufferString("")
				p.Stdout = out

				kctx, err := p.Parse([]string{"enable", "policy", "resource.nonexistent.vnone/none"})
				require.NoError(t, err)
				err = kctx.Run(cctx, globals)
				require.NoError(t, err)
			})
		})
	}
}

func loadPolicies(t *testing.T, ac client.AdminClient) {
	t.Helper()

	for i := 0; i < policiesPerType; i++ {
		ps := client.NewPolicySet()
		ps.AddPolicies(test.GenDisabledPrincipalPolicy(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(test.GenDisabledResourcePolicy(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(test.GenDisabledDerivedRoles(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(withScope(test.GenDisabledResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme"))
		ps.AddPolicies(withScope(test.GenDisabledResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr"))
		ps.AddPolicies(withScope(test.GenDisabledResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr.uk"))
		ps.AddPolicies(withScope(test.GenDisabledPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme"))
		ps.AddPolicies(withScope(test.GenDisabledPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme.hr"))

		require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))
	}
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

func withScope(p *policyv1.Policy, scope string) *policyv1.Policy {
	//nolint:exhaustive
	switch policy.GetKind(p) {
	case policy.PrincipalKind:
		p.GetPrincipalPolicy().Scope = scope
	case policy.ResourceKind:
		p.GetResourcePolicy().Scope = scope
	}
	return p
}
