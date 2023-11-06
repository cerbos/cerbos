// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func Test_loadPrincipals(t *testing.T) {
	const principals = `
principals:
  harry:
    id: harry
    roles:
      - employee
    attr:
      department: marketing
      geography: GB
      team: design
`
	fsys := make(fstest.MapFS)
	expectedPath := "a/" + util.TestDataDirectory + "/principals.yaml"
	fsys[expectedPath] = newMapFile(principals)

	tests := []struct {
		want    *Principals
		name    string
		wantErr bool
	}{
		{
			name: "a/" + util.TestDataDirectory,
			want: &Principals{
				FilePath: expectedPath,
				Fixtures: map[string]*v1.Principal{
					"harry": {
						Id:    "harry",
						Roles: []string{"employee"},
						Attr: map[string]*structpb.Value{
							"department": structpb.NewStringValue("marketing"),
							"geography":  structpb.NewStringValue("GB"),
							"team":       structpb.NewStringValue("design"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := require.New(t)
			got, err := loadPrincipals(fsys, tt.name)
			if tt.wantErr {
				is.Error(err)
			} else {
				is.NoError(err)
			}
			if diff := cmp.Diff(got, tt.want, protocmp.Transform()); diff != "" {
				t.Errorf("loadPrincipals() diff = %s", diff)
			}
		})
	}
}

func Test_testFixture_getTests(t *testing.T) {
	tf := &TestFixture{
		Principals: &Principals{
			Fixtures: map[string]*v1.Principal{
				"employee":        {Id: "employee", Roles: []string{"user"}},
				"manager":         {Id: "manager", Roles: []string{"user"}},
				"department_head": {Id: "department_head", Roles: []string{"user"}},
			},
		},
		Resources: &Resources{
			Fixtures: map[string]*v1.Resource{
				"employee_leave_request":        {Kind: "leave_request", Id: "employee"},
				"manager_leave_request":         {Kind: "leave_request", Id: "manager"},
				"department_head_leave_request": {Kind: "leave_request", Id: "department_head"},
			},
		},
		AuxData: &AuxData{
			Fixtures: map[string]*v1.AuxData{
				"test_aux_data": {Jwt: map[string]*structpb.Value{"answer": structpb.NewNumberValue(42)}},
			},
		},
	}

	for _, tt := range test.LoadTestCases(t, "verify/test_fixture_get_tests") {
		t.Run(tt.Name, func(t *testing.T) {
			tc := readTestCase(t, tt.Input)
			ts := &policyv1.TestSuite{Tests: []*policyv1.TestTable{tc.Table}}

			gotTests, gotErr := tf.getTests(ts)

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

func readTestCase(t *testing.T, data []byte) *privatev1.VerifyTestFixtureGetTestsTestCase {
	t.Helper()

	tc := &privatev1.VerifyTestFixtureGetTestsTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
