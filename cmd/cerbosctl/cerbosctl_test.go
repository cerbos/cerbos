// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername   = "cerbos"
	adminPassword   = "cerbosAdmin"
	policiesPerType = 30
)

var (
	ac             client.AdminClient
	policyKeyRegex = regexp.MustCompile(`(derived_roles|principal|resource)\.(.+)(\.(.+))?`)
)

func TestCerbosctl(t *testing.T) {
	var s *testutil.ServerInfo
	s, ac = mkServer(t)
	defer s.Stop() //nolint:errcheck

	loadPolicies(t, ac)

	testGetCmd(withTestAdminClient)(t)
}

func testGetCmd(fn internal.WithClient) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		t.Run("cerbosctl get", func(t *testing.T) {
			t.Run("no arguments", func(t *testing.T) {
				cmd := get.NewGetCmd(fn)

				err := cmd.Execute()
				require.Error(t, err, "no arguments provided")
			})
			t.Run("arguments after get", func(t *testing.T) {
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
						cmd := get.NewGetCmd(fn)
						cmd.SetArgs([]string{arg})
						err := cmd.Execute()
						if tc.wantErr {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					}
				}
			})
			t.Run("number of policies", func(t *testing.T) {
				testCases := []struct {
					args []string
				}{
					{
						[]string{"principal_policy", "principal_policies", "pp"},
					},
					{
						[]string{"derived_role", "derived_roles", "dr"},
					},
					{
						[]string{"resource_policy", "resource_policies", "rp"},
					},
				}

				for _, tc := range testCases {
					for _, arg := range tc.args {
						out := bytes.NewBufferString("")
						cmd := get.NewGetCmd(fn)
						cmd.SetOut(out)
						cmd.SetArgs([]string{arg, "--no-headers"})
						err := cmd.Execute()
						require.NoError(t, err)
						require.Equal(t, policiesPerType, noOfPoliciesInCmdOutput(t, out.String()))
					}
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

	var ps *client.PolicySet
	for i := 0; i < policiesPerType; i++ {
		ps = client.NewPolicySet()
		pp := test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i)))
		rp := test.GenResourcePolicy(test.Suffix(strconv.Itoa(i)))
		dr := test.GenDerivedRoles(test.Suffix(strconv.Itoa(i)))
		ps.AddPolicy(pp)
		ps.AddPolicy(rp)
		ps.AddPolicy(dr)

		require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))
	}
}

func withTestAdminClient(fn func(c client.AdminClient, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		return fn(ac, cmd, args)
	}
}

func mkServerOpts(t *testing.T) []testutil.ServerOpt {
	t.Helper()

	serverOpts := []testutil.ServerOpt{
		testutil.WithPolicyRepositoryDatabase("sqlite3", fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))),
		testutil.WithAdminAPI(adminUsername, adminPassword),
	}

	return serverOpts
}

func mkServer(t *testing.T) (*testutil.ServerInfo, client.AdminClient) {
	t.Helper()

	s, err := testutil.StartCerbosServer(mkServerOpts(t)...)
	require.NoError(t, err)
	adminClient, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, client.WithPlaintext())
	require.NoError(t, err)
	return s, adminClient
}
