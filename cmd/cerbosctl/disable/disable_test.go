// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package disable_test

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	policiesPerType = 30
	timeout         = 30 * time.Second
)

func TestDisableCmd(t *testing.T) {
	s := internal.StartTestServer(t)
	defer s.Stop() //nolint:errcheck

	globals := internal.CreateGlobalsFlagset(t, s.GRPCAddr())
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	cctx := mkClients(t, globals)
	loadPolicies(t, cctx.AdminClient)
	testDisableCmd(ctx, cctx, globals)(t)
}

func testDisableCmd(ctx context.Context, cctx *cmdclient.Context, globals *flagset.Globals) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		t.Run("cerbosctl disable", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"disable"})
				require.Error(t, err)
			})
			t.Run("possible arguments after disable command", func(t *testing.T) {
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
						_, err := p.Parse([]string{"disable", arg, "resource.leave_request.vdefault"})
						if tc.wantErr {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					}
				}
			})
			t.Run("disable and check", func(t *testing.T) {
				testCases := []struct {
					policyKey    string
					wantDisabled bool
				}{
					{
						policyKey:    "derived_roles.my_derived_roles_1",
						wantDisabled: true,
					},
					{
						policyKey:    "principal.donald_duck_1.vdefault",
						wantDisabled: false,
					},
					{
						policyKey:    "principal.donald_duck_1.vdefault/acme.hr",
						wantDisabled: true,
					},
					{
						policyKey:    "resource.leave_request_1.vdefault",
						wantDisabled: false,
					},
					{
						policyKey:    "resource.leave_request_1.vdefault/acme.hr.uk",
						wantDisabled: true,
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
						require.False(t, policies[0].Disabled)

						kctx, err := p.Parse([]string{"disable", "policy", tc.policyKey})
						require.NoError(t, err)
						err = kctx.Run(cctx, globals)
						if tc.wantDisabled {
							require.NoError(t, err)
						} else {
							require.Error(t, err)
						}

						policies, err = cctx.AdminClient.GetPolicy(ctx, tc.policyKey)
						require.NoError(t, err)
						if tc.wantDisabled {
							require.NotNil(t, policies)
							require.NotNil(t, policies[0])
							require.True(t, policies[0].Disabled)
							require.Contains(t, out.String(), "Number of policies disabled is 1")
						} else {
							require.NotNil(t, policies)
							require.NotNil(t, policies[0])
							require.False(t, policies[0].Disabled)
						}
					})
				}
			})
			t.Run("disable nonexisting policy", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				out := bytes.NewBufferString("")
				p.Stdout = out

				kctx, err := p.Parse([]string{"disable", "policy", "resource.nonexistent.vnone/none"})
				require.NoError(t, err)
				err = kctx.Run(cctx, globals)
				require.NoError(t, err)
			})
		})
	}
}

func loadPolicies(t *testing.T, ac *cerbos.GRPCAdminClient) {
	t.Helper()

	for i := 0; i < policiesPerType; i++ {
		ps := cerbos.NewPolicySet()

		ps.AddPolicies(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme"))
		ps.AddPolicies(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr"))
		ps.AddPolicies(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr.uk"))
		ps.AddPolicies(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme"))
		ps.AddPolicies(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme.hr"))

		require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))
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
