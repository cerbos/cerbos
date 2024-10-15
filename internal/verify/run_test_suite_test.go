// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"testing"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_testSuiteRun_getTests(t *testing.T) {
	tf := &TestFixture{
		Principals: &Principals{
			Fixtures: map[string]*enginev1.Principal{
				"employee":        {Id: "employee", Roles: []string{"user"}},
				"manager":         {Id: "manager", Roles: []string{"user"}},
				"department_head": {Id: "department_head", Roles: []string{"user"}},
			},
			Groups: map[string][]string{
				"management": {"manager", "department_head"},
			},
		},
		Resources: &Resources{
			Fixtures: map[string]*enginev1.Resource{
				"employee_leave_request":        {Kind: "leave_request", Id: "employee"},
				"manager_leave_request":         {Kind: "leave_request", Id: "manager"},
				"department_head_leave_request": {Kind: "leave_request", Id: "department_head"},
			},
			Groups: map[string][]string{
				"management_leave_requests": {"manager_leave_request", "department_head_leave_request"},
			},
		},
		AuxData: &AuxData{
			Fixtures: map[string]*enginev1.AuxData{
				"test_aux_data": {Jwt: map[string]*structpb.Value{"answer": structpb.NewNumberValue(42)}},
			},
		},
	}

	for _, tt := range test.LoadTestCases(t, "verify/test_suite_run_get_tests") {
		t.Run(tt.Name, func(t *testing.T) {
			tc := readTestCase(t, tt.Input)

			run := &testSuiteRun{
				Suite:   &policyv1.TestSuite{Tests: []*policyv1.TestTable{tc.Table}},
				Fixture: tf,
			}

			gotTests, gotErr := run.getTests()

			if tc.WantErr == "" {
				require.NoError(t, gotErr)
			} else {
				require.EqualError(t, gotErr, tc.WantErr)
			}

			if diff := cmp.Diff(tc.WantTests, gotTests, protocmp.Transform()); diff != "" {
				t.Errorf("didn't get expected tests: diff = %s", diff)
			}
		})
	}
}

func readTestCase(t *testing.T, data []byte) *privatev1.VerifyTestSuiteRunGetTestsTestCase {
	t.Helper()

	tc := &privatev1.VerifyTestSuiteRunGetTestsTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
