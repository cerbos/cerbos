// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package get_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername     = "cerbos"
	adminPassword     = "cerbosAdmin"
	policiesPerType   = 30
	readyTimeout      = 60 * time.Second
	readyPollInterval = 50 * time.Millisecond
)

var policyKeyRegex = regexp.MustCompile(`(derived_roles|principal|resource)\.(.+)(\.(.+))?`)

func TestGetCmd(t *testing.T) {
	s := mkServer(t)
	defer s.Stop() //nolint:errcheck

	globals := mkGlobals(t, s.GRPCAddr())
	ctx := mkClients(t, globals)
	loadPolicies(t, ctx.AdminClient)
	testGetCmd(ctx, globals)(t)
}

func testGetCmd(clientCtx *cmdclient.Context, globals *flagset.Globals) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		t.Run("cerbosctl get", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"get"})
				require.Error(t, err)
			})
			t.Run("wrong flags in wrong commands", func(t *testing.T) {
				testCases := []struct {
					args    []string
					wantErr bool
				}{
					{strings.Split("get schema --no-headers", " "), false},
					{strings.Split("get derived_roles --name=a", " "), false},
					{strings.Split("get principal_policies --name=a --version=default", " "), false},
					{strings.Split("get resource_policies --name=a --version=default", " "), false},
					{strings.Split("get derived_roles --version=abc", " "), true},
					{strings.Split("get derived_roles a.b.c --no-headers", " "), true},
					{strings.Split("get derived_roles a.b.c --sort-by policyId", " "), true},
					{strings.Split("get derived_roles --sort-by policyId", " "), false},
					{strings.Split("get derived_roles --sort-by version", " "), true},
				}
				for _, tc := range testCases {
					p := mustNew(t, &root.Cli{})
					_, err := p.Parse(tc.args)
					if tc.wantErr {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
				}
			})
			t.Run("possible arguments after get command", func(t *testing.T) {
				testCases := []struct {
					args    []string
					wantErr bool
				}{
					{
						[]string{"derived_role", "derived_roles", "dr"},
						false,
					},
					{
						[]string{"principal_policy", "principal_policies", "pp"},
						false,
					},
					{
						[]string{"resource_policy", "resource_policies", "rp"},
						false,
					},
					{
						[]string{"schema", "schemas", "s"},
						false,
					},
					{
						[]string{"something", "hello"},
						true,
					},
				}

				for _, tc := range testCases {
					for _, arg := range tc.args {
						cli := root.Cli{}
						p := mustNew(t, &cli)
						_, err := p.Parse([]string{"get", arg})
						if tc.wantErr {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					}
				}
			})
			t.Run("compare policy count", func(t *testing.T) {
				testCases := []struct {
					args      []string
					wantCount int
				}{
					{
						args:      []string{"principal_policy", "principal_policies", "pp"},
						wantCount: policiesPerType * 3,
					},
					{
						args:      []string{"derived_role", "derived_roles", "dr"},
						wantCount: policiesPerType,
					},
					{
						args:      []string{"resource_policy", "resource_policies", "rp"},
						wantCount: policiesPerType * 4,
					},
				}

				for _, tc := range testCases {
					for _, arg := range tc.args {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						ctx, err := p.Parse([]string{"get", arg, "--no-headers"})
						require.NoError(t, err)
						err = ctx.Run(clientCtx, globals)
						require.NoError(t, err)
						require.Equal(t, tc.wantCount, noOfPoliciesInCmdOutput(t, out.String()))
					}
				}
			})

			t.Run("compare output", func(t *testing.T) {
				testCases := []struct {
					policy *policyv1.Policy
					kind   policy.Kind
					name   string
				}{
					{
						policy: withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))),
						kind:   policy.DerivedRolesKind,
						name:   "derived_roles.my_derived_roles_1",
					},
					{
						policy: withMeta(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1)))),
						kind:   policy.PrincipalKind,
						name:   "principal.donald_duck_1.vdefault",
					},
					{
						policy: withMeta(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1))), "acme.hr")),
						kind:   policy.PrincipalKind,
						name:   "principal.donald_duck_1.vdefault/acme.hr",
					},
					{
						policy: withMeta(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1)))),
						kind:   policy.ResourceKind,
						name:   "resource.leave_request_1.vdefault",
					},
					{
						policy: withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1))), "acme.hr.uk")),
						kind:   policy.ResourceKind,
						name:   "resource.leave_request_1.vdefault/acme.hr.uk",
					},
				}
				for _, tc := range testCases {
					p := mustNew(t, &root.Cli{})
					out := bytes.NewBufferString("")
					p.Stdout = out

					var ctx *kong.Context
					var err error
					switch tc.kind {
					case policy.DerivedRolesKind:
						ctx, err = p.Parse([]string{"get", "dr", tc.name, "-ojson"})
						require.NoError(t, err)
					case policy.PrincipalKind:
						ctx, err = p.Parse([]string{"get", "pp", tc.name, "-ojson"})
						require.NoError(t, err)
					case policy.ResourceKind:
						ctx, err = p.Parse([]string{"get", "rp", tc.name, "-ojson"})
						require.NoError(t, err)
					}

					err = ctx.Run(clientCtx, globals)
					require.NoError(t, err)
					expected, err := protojson.Marshal(tc.policy)
					require.NoError(t, err)
					require.JSONEq(t, string(expected), out.String())
				}
			})

			t.Run("invalid policy key type for commands", func(t *testing.T) {
				testCases := []struct {
					args []string
				}{
					{strings.Split("get derived_roles principal.donald_duck_1.default", " ")},
					{strings.Split("get derived_roles resource.leave_request_1.default", " ")},
					{strings.Split("get principal_policies derived_roles.my_derived_roles_1", " ")},
					{strings.Split("get principal_policies resource.leave_request_1.default", " ")},
					{strings.Split("get resource_policies derived_roles.my_derived_roles_1", " ")},
					{strings.Split("get resource_policies principal.donald_duck_1.default", " ")},
				}

				for _, tc := range testCases {
					p := mustNew(t, &root.Cli{})
					out := bytes.NewBufferString("")
					p.Stdout = out

					ctx, err := p.Parse(tc.args)
					require.NoError(t, err)
					err = ctx.Run(clientCtx, globals)
					require.Error(t, err)
				}
			})
		})
	}
}

func noOfPoliciesInCmdOutput(t *testing.T, cmdOut string) int {
	t.Helper()

	count := 0
	for _, line := range strings.Split(strings.TrimSuffix(cmdOut, "\n"), "\n") {
		if policyKeyRegex.MatchString(line) {
			count++
		}
	}
	return count
}

func loadPolicies(t *testing.T, ac client.AdminClient) {
	t.Helper()

	for i := 0; i < policiesPerType; i++ {
		ps := client.NewPolicySet()

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

func withMeta(p *policyv1.Policy) *policyv1.Policy {
	return policy.WithMetadata(p, "", nil, namer.PolicyKey(p))
}
