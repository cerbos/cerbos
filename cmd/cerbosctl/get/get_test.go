// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package get_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

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

var policyKeyRegex = regexp.MustCompile(`(derived_roles|export_constants|export_variables|principal|resource|role)\.(.+)(\.(.+))?`)

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
					args    string
					wantErr bool
				}{
					{"get schema --no-headers", false},
					{"get derived_roles --name=a", false},
					{"get export_constants --name=a", false},
					{"get export_variables --name=a", false},
					{"get principal_policies --name=a --version=default", false},
					{"get resource_policies --name=a --version=default", false},
					{"get role_policies --name=a", false},
					{"get role_policies --name=a --version=default", true},
					{"get derived_roles --version=abc", true},
					{"get derived_roles a.b.c --no-headers", true},
					{"get derived_roles a.b.c --sort-by policyId", true},
					{"get derived_roles a.b.c --include-disabled", false},
					{"get derived_roles --include-disabled", false},
					{"get derived_roles --sort-by policyId", false},
					{"get derived_roles --sort-by version", true},
					// regexp filtering
					{"get derived_roles --name-regexp=a --scope-regexp=a", true},
					{"get derived_roles --name-regexp=a --scope-regexp=a --version-regexp=a", true},
					{"get derived_roles --name=a --name-regexp=a", true},
					{"get export_constants --name-regexp=a --scope-regexp=a", true},
					{"get export_constants --name-regexp=a --scope-regexp=a --version-regexp=a", true},
					{"get export_constants --name=a --name-regexp=a", true},
					{"get export_variables --name-regexp=a --scope-regexp=a", true},
					{"get export_variables --name-regexp=a --scope-regexp=a --version-regexp=a", true},
					{"get export_variables --name=a --name-regexp=a", true},
					{"get resource_policies --name-regexp=a --scope-regexp=a --version-regexp=a", false},
					{"get resource_policies --name=a --name-regexp=a", true},
					{"get resource_policies --version=a --version-regexp=a", true},
					{"get principal_policies --name-regexp=a --scope-regexp=a --version-regexp=a", false},
					{"get principal_policies --name=a --name-regexp=a", true},
					{"get principal_policies --version=a --version-regexp=a", true},
					{"get role_policies --name-regexp=a --scope-regexp=a --version-regexp=a", true},
					{"get role_policies --name=a --name-regexp=a", true},
					{"get role_policies --scope=a --scope-regexp=a", true},
				}
				for _, tc := range testCases {
					t.Run(tc.args, func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						_, err := p.Parse(strings.Split(tc.args, " "))
						if tc.wantErr {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					})
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
						[]string{"export_constants", "ec"},
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
						[]string{"role_policy", "role_policies", "rlp"},
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
						t.Run(arg, func(t *testing.T) {
							cli := root.Cli{}
							p := mustNew(t, &cli)
							_, err := p.Parse([]string{"get", arg})
							if tc.wantErr {
								require.Error(t, err)
							} else {
								require.NoError(t, err)
							}
						})
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
						args:                      []string{"export_constants", "ec"},
						wantCount:                 policiesPerType,
						wantCountWithDisabled:     policiesPerType * 2,
						regexpArg:                 "--name-regexp=my_constants_",
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
					{
						args:                      []string{"role_policy", "role_policies", "rlp"},
						wantCount:                 policiesPerType * 3,
						wantCountWithDisabled:     policiesPerType * 4,
						regexpArg:                 "--scope-regexp=acme",
						wantCountWithRegexpFilter: policiesPerType * 2,
					},
				}

				for _, tc := range testCases {
					for _, arg := range tc.args {
						t.Run(arg, func(t *testing.T) {
							p := mustNew(t, &root.Cli{})

							t.Run("default args", func(t *testing.T) {
								out := bytes.NewBufferString("")
								p.Stdout = out
								ctx, err := p.Parse([]string{"get", arg, "--no-headers"})
								require.NoError(t, err)
								err = ctx.Run(clientCtx, globals)
								require.NoError(t, err)
								require.Equal(t, tc.wantCount, noOfPoliciesInCmdOutput(t, out.String()))
							})

							t.Run("include disabled", func(t *testing.T) {
								out := bytes.NewBufferString("")
								p.Stdout = out
								ctx, err := p.Parse([]string{"get", arg, "--include-disabled", "--no-headers"})
								require.NoError(t, err)
								err = ctx.Run(clientCtx, globals)
								require.NoError(t, err)
								require.Equal(t, tc.wantCountWithDisabled, noOfPoliciesInCmdOutput(t, out.String()))
							})

							t.Run("include disabled and filter by regexp", func(t *testing.T) {
								out := bytes.NewBufferString("")
								p.Stdout = out
								ctx, err := p.Parse([]string{"get", arg, "--include-disabled", tc.regexpArg, "--no-headers"})
								require.NoError(t, err)
								err = ctx.Run(clientCtx, globals)
								require.NoError(t, err)
								require.Equal(t, tc.wantCountWithRegexpFilter, noOfPoliciesInCmdOutput(t, out.String()))
							})
						})
					}
				}
			})

			t.Run("compare output", func(t *testing.T) {
				requirePolicyEq := func(t *testing.T, want *policyv1.Policy, haveJSON []byte) {
					t.Helper()

					var have policyv1.Policy
					require.NoError(t, protojson.Unmarshal(haveJSON, &have), "Failed to unmarshal policy")
					require.Empty(t, cmp.Diff(want, &have, protocmp.Transform(), protocmp.IgnoreFields(&policyv1.Metadata{}, "source_attributes")))
				}

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
						policy: withMeta(test.GenExportConstants(test.Suffix("1"))),
						kind:   policy.ExportConstantsKind,
						name:   "export_constants.my_constants_1",
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
					{
						policy: withMeta(test.GenRolePolicy(test.Suffix("1"))),
						kind:   policy.RolePolicyKind,
						name:   "role.acme_admin_1",
					},
				}
				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						var ctx *kong.Context
						var err error
						switch tc.kind {
						case policy.DerivedRolesKind:
							ctx, err = p.Parse([]string{"get", "dr", tc.name, "-ojson"})
							require.NoError(t, err)
						case policy.ExportConstantsKind:
							ctx, err = p.Parse([]string{"get", "ec", tc.name, "-ojson"})
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
						case policy.RolePolicyKind:
							ctx, err = p.Parse([]string{"get", "rlp", tc.name, "-ojson"})
							require.NoError(t, err)
						}

						err = ctx.Run(clientCtx, globals)
						require.NoError(t, err)

						requirePolicyEq(t, tc.policy, out.Bytes())
					})
				}
			})

			t.Run("invalid policy key type for commands", func(t *testing.T) {
				testCases := []string{
					"get derived_roles export_constants.my_constants_1",
					"get derived_roles export_variables.my_variables_1",
					"get derived_roles principal.donald_duck_1.default",
					"get derived_roles resource.leave_request_1.default",
					"get derived_roles role.acme_admin_1",
					"get export_constants derived_roles.my_derived_roles_1",
					"get export_constants export_variables.my_variables_1",
					"get export_constants principal.donald_duck_1.default",
					"get export_constants resource.leave_request_1.default",
					"get export_constants role.acme_admin_1",
					"get export_variables derived_roles.my_derived_roles_1",
					"get export_variables export_constants.my_constants_1",
					"get export_variables principal.donald_duck_1.default",
					"get export_variables resource.leave_request_1.default",
					"get export_variables role.acme_admin_1",
					"get principal_policies derived_roles.my_derived_roles_1",
					"get principal_policies export_constants.my_constants_1",
					"get principal_policies export_variables.my_variables_1",
					"get principal_policies resource.leave_request_1.default",
					"get principal_policies role.acme_admin_1",
					"get resource_policies derived_roles.my_derived_roles_1",
					"get resource_policies export_constants.my_constants_1",
					"get resource_policies export_variables.my_variables_1",
					"get resource_policies principal.donald_duck_1.default",
					"get resource_policies role.acme_admin_1",
					"get role_policies derived_roles.my_derived_roles_1",
					"get role_policies export_constants.my_constants_1",
					"get role_policies export_variables.my_variables_1",
					"get role_policies principal.donald_duck_1.default",
					"get role_policies resource.leave_request_1.default",
				}

				for _, tc := range testCases {
					t.Run(tc, func(t *testing.T) {
						p := mustNew(t, &root.Cli{})
						out := bytes.NewBufferString("")
						p.Stdout = out

						ctx, err := p.Parse(strings.Split(tc, " "))
						require.NoError(t, err)
						err = ctx.Run(clientCtx, globals)
						require.Error(t, err)
					})
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
		ps.AddPolicies(withMeta(test.GenRolePolicy(test.Suffix(strconv.Itoa(i)))))
		ps.AddPolicies(withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i)))))
		ps.AddPolicies(withMeta(test.GenExportConstants(test.Suffix(strconv.Itoa(i)))))
		ps.AddPolicies(withMeta(test.GenExportVariables(test.Suffix(strconv.Itoa(i)))))

		ps.AddPolicies(withMeta(test.GenDisabledPrincipalPolicy(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledResourcePolicy(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledRolePolicy(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledDerivedRoles(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledExportConstants(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))
		ps.AddPolicies(withMeta(test.GenDisabledExportVariables(test.Suffix(fmt.Sprintf("_disabled_%d", i)))))

		ps.AddPolicies(withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme")))
		ps.AddPolicies(withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr")))
		ps.AddPolicies(withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr.uk")))
		ps.AddPolicies(withMeta(withScope(test.GenRolePolicy(test.Suffix(strconv.Itoa(i))), "acme")))
		ps.AddPolicies(withMeta(withScope(test.GenRolePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr")))
		ps.AddPolicies(withMeta(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme")))
		ps.AddPolicies(withMeta(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme.hr")))
		require.NoError(t, ac.AddOrUpdatePolicy(t.Context(), ps))
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
	case policy.RolePolicyKind:
		p.GetRolePolicy().Scope = scope
	}
	return p
}

func withMeta(p *policyv1.Policy) *policyv1.Policy {
	return policy.WithMetadata(p, "", nil, namer.PolicyKey(p), policy.SourceDriver("sqlite3"))
}
