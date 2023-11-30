// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package get_test

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

const policiesPerType = 30

var policyKeyRegex = regexp.MustCompile(`(derived_roles|export_variables|principal|resource)\.(.+)(\.(.+))?`)

func TestGetCmd(t *testing.T) {
	s := internal.StartTestServer(t)
	defer s.Stop() //nolint:errcheck

	globals := internal.CreateGlobalsFlagset(t, s.GRPCAddr())
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
					{strings.Split("get export_variables --name=a", " "), false},
					{strings.Split("get principal_policies --name=a --version=default", " "), false},
					{strings.Split("get resource_policies --name=a --version=default", " "), false},
					{strings.Split("get derived_roles --version=abc", " "), true},
					{strings.Split("get derived_roles a.b.c --no-headers", " "), true},
					{strings.Split("get derived_roles a.b.c --sort-by policyId", " "), true},
					{strings.Split("get derived_roles a.b.c --include-disabled", " "), true},
					{strings.Split("get derived_roles --include-disabled", " "), false},
					{strings.Split("get derived_roles --sort-by policyId", " "), false},
					{strings.Split("get derived_roles --sort-by version", " "), true},
					// regexp filtering
					{strings.Split("get derived_roles --name-regexp=a --scope-regexp=a", " "), true},
					{strings.Split("get derived_roles --name-regexp=a --scope-regexp=a --version-regexp=a", " "), true},
					{strings.Split("get derived_roles --name=a --name-regexp=a", " "), true},
					{strings.Split("get export_variables --name-regexp=a --scope-regexp=a", " "), true},
					{strings.Split("get export_variables --name-regexp=a --scope-regexp=a --version-regexp=a", " "), true},
					{strings.Split("get export_variables --name=a --name-regexp=a", " "), true},
					{strings.Split("get resource_policies --name-regexp=a --scope-regexp=a --version-regexp=a", " "), false},
					{strings.Split("get resource_policies --name=a --name-regexp=a", " "), true},
					{strings.Split("get resource_policies --version=a --version-regexp=a", " "), true},
					{strings.Split("get principal_policies --name-regexp=a --scope-regexp=a --version-regexp=a", " "), false},
					{strings.Split("get principal_policies --name=a --name-regexp=a", " "), true},
					{strings.Split("get principal_policies --version=a --version-regexp=a", " "), true},
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
						[]string{"export_variables", "ev"},
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
					args                      []string
					regexpArg                 string
					wantCount                 int
					wantCountWithDisabled     int
					wantCountWithRegexpFilter int
				}{
					{
						args:                      []string{"principal_policy", "principal_policies", "pp"},
						wantCount:                 policiesPerType * 3,
						wantCountWithDisabled:     policiesPerType * 4,
						regexpArg:                 "--scope-regexp=acme",
						wantCountWithRegexpFilter: policiesPerType * 2,
					},
					{
						args:                      []string{"derived_role", "derived_roles", "dr"},
						wantCount:                 policiesPerType,
						wantCountWithDisabled:     policiesPerType * 2,
						regexpArg:                 "--name-regexp=my_derived_",
						wantCountWithRegexpFilter: policiesPerType * 2,
					},
					{
						args:                      []string{"export_variables", "ev"},
						wantCount:                 policiesPerType,
						wantCountWithDisabled:     policiesPerType * 2,
						regexpArg:                 "--name-regexp=my_variables_",
						wantCountWithRegexpFilter: policiesPerType * 2,
					},
					{
						args:                      []string{"resource_policy", "resource_policies", "rp"},
						wantCount:                 policiesPerType * 4,
						wantCountWithDisabled:     policiesPerType * 5,
						regexpArg:                 "--scope-regexp=acme",
						wantCountWithRegexpFilter: policiesPerType * 3,
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

						out = bytes.NewBufferString("")
						p.Stdout = out
						ctx, err = p.Parse([]string{"get", arg, "--include-disabled", "--no-headers"})
						require.NoError(t, err)
						err = ctx.Run(clientCtx, globals)
						require.NoError(t, err)
						require.Equal(t, tc.wantCountWithDisabled, noOfPoliciesInCmdOutput(t, out.String()))

						out = bytes.NewBufferString("")
						p.Stdout = out
						ctx, err = p.Parse([]string{"get", arg, "--include-disabled", tc.regexpArg, "--no-headers"})
						require.NoError(t, err)
						err = ctx.Run(clientCtx, globals)
						require.NoError(t, err)
						require.Equal(t, tc.wantCountWithRegexpFilter, noOfPoliciesInCmdOutput(t, out.String()))
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
						policy: withMeta(test.GenDerivedRoles(test.Suffix("1"))),
						kind:   policy.DerivedRolesKind,
						name:   "derived_roles.my_derived_roles_1",
					},
					{
						policy: withMeta(test.GenExportVariables(test.Suffix("1"))),
						kind:   policy.ExportVariablesKind,
						name:   "export_variables.my_variables_1",
					},
					{
						policy: withMeta(test.GenPrincipalPolicy(test.Suffix("1"))),
						kind:   policy.PrincipalKind,
						name:   "principal.donald_duck_1.vdefault",
					},
					{
						policy: withMeta(withScope(test.GenPrincipalPolicy(test.Suffix("1")), "acme.hr")),
						kind:   policy.PrincipalKind,
						name:   "principal.donald_duck_1.vdefault/acme.hr",
					},
					{
						policy: withMeta(test.GenResourcePolicy(test.Suffix("1"))),
						kind:   policy.ResourceKind,
						name:   "resource.leave_request_1.vdefault",
					},
					{
						policy: withMeta(withScope(test.GenResourcePolicy(test.Suffix("1")), "acme.hr.uk")),
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
					case policy.ExportVariablesKind:
						ctx, err = p.Parse([]string{"get", "ev", tc.name, "-ojson"})
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
					{strings.Split("get derived_roles export_variables.my_variables_1", " ")},
					{strings.Split("get derived_roles principal.donald_duck_1.default", " ")},
					{strings.Split("get derived_roles resource.leave_request_1.default", " ")},
					{strings.Split("get export_variables derived_roles.my_derived_roles_1", " ")},
					{strings.Split("get export_variables principal.donald_duck_1.default", " ")},
					{strings.Split("get export_variables resource.leave_request_1.default", " ")},
					{strings.Split("get principal_policies derived_roles.my_derived_roles_1", " ")},
					{strings.Split("get principal_policies export_variables.my_variables_1", " ")},
					{strings.Split("get principal_policies resource.leave_request_1.default", " ")},
					{strings.Split("get resource_policies derived_roles.my_derived_roles_1", " ")},
					{strings.Split("get resource_policies export_variables.my_variables_1", " ")},
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

func loadPolicies(t *testing.T, ac *cerbos.GRPCAdminClient) {
	t.Helper()

	for i := 0; i < policiesPerType; i++ {
		ps := cerbos.NewPolicySet()

		ps.AddPolicies(withMeta(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i)))))
		ps.AddPolicies(withMeta(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i)))))
		ps.AddPolicies(withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i)))))
		ps.AddPolicies(withMeta(test.GenExportVariables(test.Suffix(strconv.Itoa(i)))))

		ps.AddPolicies(withMeta(test.GenDisabledPrincipalPolicy(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledResourcePolicy(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledDerivedRoles(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledExportVariables(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))

		ps.AddPolicies(withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme")))
		ps.AddPolicies(withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr")))
		ps.AddPolicies(withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr.uk")))
		ps.AddPolicies(withMeta(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme")))
		ps.AddPolicies(withMeta(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme.hr")))
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

func withMeta(p *policyv1.Policy) *policyv1.Policy {
	return policy.WithMetadata(p, "", nil, namer.PolicyKey(p), policy.SourceDriver("test"))
}
