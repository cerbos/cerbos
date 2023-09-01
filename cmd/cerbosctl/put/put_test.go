// Copyright 2021-2023 Zenauth Ltd.
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
	"time"

	"github.com/alecthomas/kong"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client/testutil"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	adminUsername     = "cerbos"
	adminPassword     = "cerbosAdmin"
	schemaFileName    = "principal.json"
	readyTimeout      = 60 * time.Second
	readyPollInterval = 50 * time.Millisecond
)

func TestPutCmd(t *testing.T) {
	s := mkServer(t)
	defer s.Stop() //nolint:errcheck

	globals := mkGlobals(t, s.GRPCAddr())
	ctx := mkClients(t, globals)
	testPutCmd(ctx, globals)(t)
}

func testPutCmd(clientCtx *cmdclient.Context, globals *flagset.Globals) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		pathToSchema := test.PathToDir(t, filepath.Join("store", "_schemas", schemaFileName))
		sch := string(test.ReadSchemaFromFile(t, pathToSchema))

		ev := withMeta(test.GenExportVariables(test.Suffix(strconv.Itoa(1))))
		dr := withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(1))))
		pp := withMeta(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1))))
		rp := withMeta(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1))))

		evPath := writeToTmpFile(t, ev)
		drPath := writeToTmpFile(t, dr)
		ppPath := writeToTmpFile(t, pp)
		rpPath := writeToTmpFile(t, rp)

		expectedEv, err := protojson.Marshal(ev)
		require.NoError(t, err)
		expectedDr, err := protojson.Marshal(dr)
		require.NoError(t, err)
		expectedPp, err := protojson.Marshal(pp)
		require.NoError(t, err)
		expectedRp, err := protojson.Marshal(rp)
		require.NoError(t, err)

		pathToZip := filepath.Join("testdata", "store.zip")
		t.Run("cerbosctl put", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"put"})
				require.Error(t, err)
			})

			t.Run("put policies recursive", func(t *testing.T) {
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/export_variables"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/derived_roles"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/principal_policies"))
				put(t, clientCtx, globals, policyKind, "--recursive", test.PathToDir(t, "store/resource_policies"))
				put(t, clientCtx, globals, policyKind, "--recursive", pathToZip)

				require.Equal(t, []string{
					"derived_roles.alpha",
					"derived_roles.apatr_common_roles",
					"derived_roles.beta",
					"derived_roles.buyer_derived_roles",
					"derived_roles.import_variables",
					"derived_roles.package_roles",
					"derived_roles.principal_derived_roles",
					"export_variables.foobar",
					"principal.arn:aws:iam::123456789012:user/johndoe.vdefault",
					"principal.daisy_duck.vdefault",
					"principal.donald_duck.v20210210",
					"principal.donald_duck.vdefault",
					"principal.donald_duck.vdefault/acme",
					"principal.donald_duck.vdefault/acme.hr",
					"principal.scrooge_mcduck.vdefault",
					"principal.terry_tibbs.vdefault",
					"resource.account.vdefault",
					"resource.album_object.vdefault",
					"resource.arn:aws:sns:us-east-1:123456789012:topic-a.vdefault",
					"resource.equipment_request.vdefault",
					"resource.equipment_request.vdefault/acme",
					"resource.global.vdefault",
					"resource.import_derived_roles_that_import_variables.vdefault",
					"resource.import_variables.vdefault",
					"resource.leave_request.v20210210",
					"resource.leave_request.vdefault",
					"resource.leave_request.vdefault/acme",
					"resource.leave_request.vdefault/acme.hr",
					"resource.leave_request.vdefault/acme.hr.uk",
					"resource.leave_request.vstaging",
					"resource.missing_attr.vdefault",
					"resource.principal_derived_roles.vdefault",
					"resource.products.vdefault",
					"resource.purchase_order.vdefault",
					"resource.variables_referencing_variables.vdefault",
				}, listPolicies(t, clientCtx))
			})

			t.Run("put policies", func(t *testing.T) {
				put(t, clientCtx, globals, policyKind, evPath)
				put(t, clientCtx, globals, policyKind, drPath)
				put(t, clientCtx, globals, policyKind, ppPath)
				put(t, clientCtx, globals, policyKind, rpPath)

				outEv := getPolicy(t, clientCtx, globals, policy.ExportVariablesKind, namer.PolicyKey(ev))
				outDr := getPolicy(t, clientCtx, globals, policy.DerivedRolesKind, namer.PolicyKey(dr))
				outPp := getPolicy(t, clientCtx, globals, policy.PrincipalKind, namer.PolicyKey(pp))
				outRp := getPolicy(t, clientCtx, globals, policy.ResourceKind, namer.PolicyKey(rp))

				require.JSONEq(t, string(expectedEv), outEv)
				require.JSONEq(t, string(expectedDr), outDr)
				require.JSONEq(t, string(expectedPp), outPp)
				require.JSONEq(t, string(expectedRp), outRp)
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
	case policy.ExportVariablesKind:
		return "ev"
	case policy.PrincipalKind:
		return "pp"
	case policy.ResourceKind:
		return "rp"
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

func withMeta(p *policyv1.Policy) *policyv1.Policy {
	return policy.WithMetadata(p, "", nil, namer.PolicyKey(p))
}

const (
	policyKind = "policy"
	schemaKind = "schema"
)
