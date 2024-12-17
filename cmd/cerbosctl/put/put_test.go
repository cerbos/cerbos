// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race
// +build !race

package put_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/google/go-cmp/cmp"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

const schemaFileName = "principal.json"

func TestPutCmd(t *testing.T) {
	s := internal.StartTestServer(t)
	defer s.Stop() //nolint:errcheck

	globals := internal.CreateGlobalsFlagset(t, s.GRPCAddr())
	ctx := mkClients(t, globals)
	testPutCmd(ctx, globals)(t)
}

func testPutCmd(clientCtx *cmdclient.Context, globals *flagset.Globals) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		pathToSchema := test.PathToDir(t, filepath.Join("store", "_schemas", schemaFileName))
		sch := string(test.ReadSchemaFromFile(t, pathToSchema))

		ec := withMeta(test.GenExportConstants(test.Suffix(strconv.Itoa(1))))
		ev := withMeta(test.GenExportVariables(test.Suffix(strconv.Itoa(1))))
		dr := withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(1))))
		pp := withMeta(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1))))
		rp := withMeta(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1))))
		rlp := withMeta(test.GenRolePolicy(test.Suffix(strconv.Itoa(1))))

		ecPath := writeToTmpFile(t, ec)
		evPath := writeToTmpFile(t, ev)
		drPath := writeToTmpFile(t, dr)
		ppPath := writeToTmpFile(t, pp)
		rpPath := writeToTmpFile(t, rp)
		rlpPath := writeToTmpFile(t, rlp)

		pathToZip := filepath.Join("testdata", "store.zip")
		t.Run("cerbosctl put", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"put"})
				require.Error(t, err)
			})

			t.Run("put policies recursive", func(t *testing.T) {
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/export_constants"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/export_variables"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/derived_roles"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/principal_policies"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/resource_policies"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/role_policies"))
				put(t, clientCtx, globals, policyKind, "--recursive", pathToZip)

				require.Equal(t, []string{
					"derived_roles.alpha",
					"derived_roles.apatr_common_roles",
					"derived_roles.beta",
					"derived_roles.buyer_derived_roles",
					"derived_roles.import_variables",
					"derived_roles.package_roles",
					"derived_roles.runtime_effective_derived_roles",
					"export_constants.bazqux",
					"export_variables.foobar",
					"principal.arn:aws:iam::123456789012:user/johndoe.vdefault",
					"principal.daisy_duck.vdefault",
					"principal.donald_duck.v20210210",
					"principal.donald_duck.vdefault",
					"principal.donald_duck.vdefault/acme",
					"principal.donald_duck.vdefault/acme.hr",
					"principal.donald_duck.vdefault/acme.sales",
					"principal.scrooge_mcduck.vdefault",
					"principal.terry_tibbs.vdefault",
					"resource.account.vdefault",
					"resource.album_object.vdefault",
					"resource.arn:aws:sns:us-east-1:123456789012:topic-a.vdefault",
					"resource.equipment_request.vdefault",
					"resource.equipment_request.vdefault/acme",
					"resource.example.vdefault",
					"resource.global.vdefault",
					"resource.import_derived_roles_that_import_variables.vdefault",
					"resource.import_variables.vdefault",
					"resource.leave_request.v20210210",
					"resource.leave_request.vdefault",
					"resource.leave_request.vdefault/acme",
					"resource.leave_request.vdefault/acme.hr",
					"resource.leave_request.vdefault/acme.hr.fr",
					"resource.leave_request.vdefault/acme.hr.uk",
					"resource.leave_request.vstaging",
					"resource.missing_attr.vdefault",
					"resource.output_now.vdefault",
					"resource.products.vdefault",
					"resource.purchase_order.vdefault",
					"resource.runtime_effective_derived_roles.vdefault",
					"resource.variables_referencing_variables.vdefault",
					"role.acme_assistant/acme.hr.de",
					"role.acme_creator/acme.hr.uk",
					"role.acme_jr_admin/acme.hr.uk",
					"role.acme_manager/acme.hr.uk",
					"role.acme_sr_admin/acme.hr.uk",
					"role.acme_travel_agent/acme.hr.de",
				}, listPolicies(t, clientCtx))
			})

			t.Run("put policies", func(t *testing.T) {
				put(t, clientCtx, globals, policyKind, ecPath)
				put(t, clientCtx, globals, policyKind, evPath)
				put(t, clientCtx, globals, policyKind, drPath)
				put(t, clientCtx, globals, policyKind, ppPath)
				put(t, clientCtx, globals, policyKind, rpPath)
				put(t, clientCtx, globals, policyKind, rlpPath)

				outEc := getPolicy(t, clientCtx, globals, policy.ExportConstantsKind, namer.PolicyKey(ec))
				outEv := getPolicy(t, clientCtx, globals, policy.ExportVariablesKind, namer.PolicyKey(ev))
				outDr := getPolicy(t, clientCtx, globals, policy.DerivedRolesKind, namer.PolicyKey(dr))
				outPp := getPolicy(t, clientCtx, globals, policy.PrincipalKind, namer.PolicyKey(pp))
				outRp := getPolicy(t, clientCtx, globals, policy.ResourceKind, namer.PolicyKey(rp))
				outRlp := getPolicy(t, clientCtx, globals, policy.RolePolicyKind, namer.PolicyKey(rlp))

				requirePolicyEq := func(t *testing.T, want *policyv1.Policy, haveJSON string) {
					t.Helper()

					var have policyv1.Policy
					require.NoError(t, protojson.Unmarshal([]byte(haveJSON), &have), "Failed to unmarshal policy")
					require.Empty(t, cmp.Diff(want, &have, protocmp.Transform(), protocmp.IgnoreFields(&policyv1.Metadata{}, "source_attributes")))
				}

				requirePolicyEq(t, ec, outEc)
				requirePolicyEq(t, ev, outEv)
				requirePolicyEq(t, dr, outDr)
				requirePolicyEq(t, pp, outPp)
				requirePolicyEq(t, rp, outRp)
				requirePolicyEq(t, rlp, outRlp)
			})

			t.Run("put schemas recursive", func(t *testing.T) {
				put(t, clientCtx, globals, schemaKind, "--recursive", test.PathToDir(t, "store/_schemas"))
				put(t, clientCtx, globals, schemaKind, "--recursive", pathToZip)
				require.Equal(t, []string{
					"principal.json",
					"principal_package.json",
					"resources/leave_request.json",
					"resources/purchase_order.json",
					"resources/salary_record.json",
				}, listSchemas(t, clientCtx))
			})

			t.Run("put schema", func(t *testing.T) {
				put(t, clientCtx, globals, schemaKind, pathToSchema)
				outSchema := getSchema(t, clientCtx, globals, schemaFileName)
				require.JSONEq(t, sch, outSchema)
			})
		})
	}
}

func put(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, args ...string) {
	t.Helper()

	p := mustNew(t, &root.Cli{})

	var out bytes.Buffer
	p.Stdout = &out

	ctx, err := p.Parse(append([]string{"put"}, args...))
	require.NoError(t, err)

	err = ctx.Run(clientCtx, globals)
	require.NoError(t, err)

	require.NotContains(t, out.String(), "Errors:")
}

func listPolicies(t *testing.T, clientCtx *cmdclient.Context) []string {
	t.Helper()
	policies, err := clientCtx.AdminClient.ListPolicies(context.Background())
	require.NoError(t, err, "failed to list policies")
	return policies
}

func listSchemas(t *testing.T, clientCtx *cmdclient.Context) []string {
	t.Helper()
	schemas, err := clientCtx.AdminClient.ListSchemas(context.Background())
	require.NoError(t, err, "failed to list schemas")
	return schemas
}

func get(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, args ...string) string {
	t.Helper()

	p := mustNew(t, &root.Cli{})

	var out bytes.Buffer
	p.Stdout = &out

	ctx, err := p.Parse(append([]string{"get"}, args...))
	require.NoError(t, err)

	err = ctx.Run(clientCtx, globals)
	require.NoError(t, err)

	return out.String()
}

func getPolicy(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, kind policy.Kind, policyID string) string {
	t.Helper()
	return get(t, clientCtx, globals, policyKindToGet(kind), policyID)
}

func policyKindToGet(kind policy.Kind) string {
	switch kind {
	case policy.DerivedRolesKind:
		return "dr"
	case policy.ExportConstantsKind:
		return "ec"
	case policy.ExportVariablesKind:
		return "ev"
	case policy.PrincipalKind:
		return "pp"
	case policy.ResourceKind:
		return "rp"
	case policy.RolePolicyKind:
		return "rlp"
	}
	panic(fmt.Errorf("unknown policy kind %d", kind))
}

func getSchema(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, schemaID string) string {
	t.Helper()
	return get(t, clientCtx, globals, "schema", schemaID)
}

func writeToTmpFile(t *testing.T, p *policyv1.Policy) string {
	t.Helper()

	f, err := os.CreateTemp("", "policy_*.yaml")
	require.NoError(t, err)

	pBytes, err := protojson.Marshal(p)
	require.NoError(t, err)

	_, err = f.Write(pBytes)
	require.NoError(t, err)

	return f.Name()
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

func withMeta(p *policyv1.Policy) *policyv1.Policy {
	return policy.WithMetadata(p, "", nil, namer.PolicyKey(p), policy.SourceDriver("sqlite3"))
}

const (
	policyKind = "policy"
	schemaKind = "schema"
)
