// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race
// +build !race

package main

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

		dr := withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(1))))
		pp := withMeta(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1))))
		rp := withMeta(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1))))

		drPath := writeToTmpFile(t, dr)
		ppPath := writeToTmpFile(t, pp)
		rpPath := writeToTmpFile(t, rp)

		expectedDr, err := protojson.Marshal(dr)
		require.NoError(t, err)
		expectedPp, err := protojson.Marshal(pp)
		require.NoError(t, err)
		expectedRp, err := protojson.Marshal(rp)
		require.NoError(t, err)

		t.Run("cerbosctl put", func(t *testing.T) {
			t.Run("no arguments provided", func(t *testing.T) {
				p := mustNew(t, &root.Cli{})
				_, err := p.Parse([]string{"put"})
				require.Error(t, err)
			})
			t.Run("put policies", func(t *testing.T) {
				put(t, clientCtx, globals, policyKind, drPath)
				put(t, clientCtx, globals, policyKind, ppPath)
				put(t, clientCtx, globals, policyKind, rpPath)

				outDr := getPolicy(t, clientCtx, globals, policy.DerivedRolesKind, namer.PolicyKey(dr))
				outPp := getPolicy(t, clientCtx, globals, policy.PrincipalKind, namer.PolicyKey(pp))
				outRp := getPolicy(t, clientCtx, globals, policy.ResourceKind, namer.PolicyKey(rp))

				require.JSONEq(t, string(expectedDr), outDr)
				require.JSONEq(t, string(expectedPp), outPp)
				require.JSONEq(t, string(expectedRp), outRp)
			})
			t.Run("put schema", func(t *testing.T) {
				put(t, clientCtx, globals, schemaKind, pathToSchema)
				outSchema := getSchema(t, clientCtx, globals, schemaFileName)
				require.JSONEq(t, sch, outSchema)
			})
		})
	}
}

func put(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, kind putKind, path string) {
	t.Helper()

	p := mustNew(t, &root.Cli{})

	ctx, err := p.Parse([]string{"put", string(kind), path})
	require.NoError(t, err)

	err = ctx.Run(clientCtx, globals)
	require.NoError(t, err)
}

func getPolicy(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, kind policy.Kind, policyID string) string {
	t.Helper()

	var k string
	switch kind {
	case policy.DerivedRolesKind:
		k = "dr"
	case policy.PrincipalKind:
		k = "pp"
	case policy.ResourceKind:
		k = "rp"
	}

	p := mustNew(t, &root.Cli{})
	out := bytes.NewBufferString("")
	p.Stdout = out

	ctx, err := p.Parse([]string{"get", k, policyID})
	require.NoError(t, err)

	err = ctx.Run(clientCtx, globals)
	require.NoError(t, err)

	return out.String()
}

func getSchema(t *testing.T, clientCtx *cmdclient.Context, globals *flagset.Globals, schemaID string) string {
	t.Helper()

	p := mustNew(t, &root.Cli{})
	out := bytes.NewBufferString("")
	p.Stdout = out

	ctx, err := p.Parse([]string{"get", "schema", schemaID})
	require.NoError(t, err)

	err = ctx.Run(clientCtx, globals)
	require.NoError(t, err)

	return out.String()
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

type putKind string

const (
	policyKind = "policy"
	schemaKind = "schema"
)
