// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package main_test

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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/derivedroles"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/principalpolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/resourcepolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
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

var (
	ac             client.AdminClient
	policyKeyRegex = regexp.MustCompile(`(derived_roles|principal|resource)\.(.+)(\.(.+))?`)
)

func TestCerbosctl(t *testing.T) {
	var s *testutil.ServerInfo
	s, ac = mkServer(t)
	defer s.Stop() //nolint:errcheck

	loadPolicies(t, ac)
	t.Run("get", testGetCmd(withTestAdminClient))
}

func testGetCmd(fn internal.WithClient) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("no arguments provided", func(t *testing.T) {
			cmd := get.NewGetCmd(fn)

			err := cmd.Execute()
			require.Error(t, err)
		})
		t.Run("wrong flags in wrong commands", func(t *testing.T) {
			testCases := []struct {
				args    []string
				wantErr bool
			}{
				{strings.Split("schema --no-headers", " "), false},
				{strings.Split("derived_roles --name=a", " "), false},
				{strings.Split("principal_policies --name=a --version=default", " "), false},
				{strings.Split("resource_policies --name=a --version=default", " "), false},
				{strings.Split("derived_roles --version=abc", " "), true},
				{strings.Split("derived_roles a.b.c --no-headers", " "), true},
				{strings.Split("derived_roles a.b.c --sort-by policyId", " "), true},
				{strings.Split("derived_roles --sort-by policyId", " "), false},
				{strings.Split("derived_roles --sort-by version", " "), true},
			}
			for _, tc := range testCases {
				cmd := get.NewGetCmd(fn)
				cmd.SetArgs(tc.args)
				err := cmd.Execute()
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
					out := bytes.NewBufferString("")
					cmd := get.NewGetCmd(fn)
					cmd.SetOut(out)
					cmd.SetArgs([]string{arg, "--no-headers"})
					err := cmd.Execute()
					require.NoError(t, err)
					require.Equal(t, tc.wantCount, noOfPoliciesInCmdOutput(t, out.String()))
				}
			}
		})

		t.Run("compare output", func(t *testing.T) {
			testCases := []struct {
				policy *policyv1.Policy
				kind   string
				name   string
			}{
				{
					policy: withMeta(test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))),
					kind:   "dr",
					name:   "derived_roles.my_derived_roles_1",
				},
				{
					policy: withMeta(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1)))),
					kind:   "pp",
					name:   "principal.donald_duck_1.vdefault",
				},
				{
					policy: withMeta(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(1))), "acme.hr")),
					kind:   "pp",
					name:   "principal.donald_duck_1.vdefault/acme.hr",
				},
				{
					policy: withMeta(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1)))),
					kind:   "rp",
					name:   "resource.leave_request_1.vdefault",
				},
				{
					policy: withMeta(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(1))), "acme.hr.uk")),
					kind:   "rp",
					name:   "resource.leave_request_1.vdefault/acme.hr.uk",
				},
			}

			for _, tc := range testCases {
				var cmd *cobra.Command
				switch tc.kind {
				case "dr":
					cmd = derivedroles.NewDerivedRolesCmd(fn)
				case "pp":
					cmd = principalpolicy.NewPrincipalPolicyCmd(fn)
				case "rp":
					cmd = resourcepolicy.NewResourcePolicyCmd(fn)
				}
				cmd.SetArgs([]string{tc.name, "-ojson"})

				out := bytes.NewBufferString("")
				cmd.SetOut(out)
				err := cmd.Execute()
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
				{strings.Split("derived_roles principal.donald_duck_1.vdefault", " ")},
				{strings.Split("derived_roles resource.leave_request_1.vdefault", " ")},
				{strings.Split("principal_policies derived_roles.my_derived_roles_1", " ")},
				{strings.Split("principal_policies resource.leave_request_1.vdefault", " ")},
				{strings.Split("resource_policies derived_roles.my_derived_roles_1", " ")},
				{strings.Split("resource_policies principal.donald_duck_1.vdefault", " ")},
			}

			for _, tc := range testCases {
				out := bytes.NewBufferString("")
				cmd := get.NewGetCmd(fn)
				cmd.SetOut(out)
				cmd.SetArgs(tc.args)
				err := cmd.Execute()
				require.Error(t, err)
			}
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

	ps := client.NewPolicySet()
	for i := 0; i < policiesPerType; i++ {
		ps.AddPolicies(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i))))
		ps.AddPolicies(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme"))
		ps.AddPolicies(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr"))
		ps.AddPolicies(withScope(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), "acme.hr.uk"))
		ps.AddPolicies(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme"))
		ps.AddPolicies(withScope(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), "acme.hr"))
	}

	require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))
}

func withTestAdminClient(fn internal.AdminCommand) func(cmd *cobra.Command, args []string) error {
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
	require.Eventually(t, serverIsReady(s), readyTimeout, readyPollInterval)

	adminClient, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, client.WithPlaintext())
	require.NoError(t, err)
	return s, adminClient
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
