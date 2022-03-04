// Copyright 2021-2022 Zenauth Ltd.
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
	fsys["a/"+util.TestDataDirectory+"/principals.yaml"] = newMapFile(principals)

	tests := []struct {
		want    map[string]*v1.Principal
		name    string
		wantErr bool
	}{
		{
			name: "a/" + util.TestDataDirectory,
			want: map[string]*v1.Principal{
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
	tf := &testFixture{
		principals: map[string]*v1.Principal{
			"employee":        {Id: "user:employee"},
			"manager":         {Id: "user:manager"},
			"department_head": {Id: "user:department_head"},
		},
		resources: map[string]*v1.Resource{
			"employee_leave_request":        {Id: "leave_request:employee"},
			"manager_leave_request":         {Id: "leave_request:manager"},
			"department_head_leave_request": {Id: "leave_request:department_head"},
		},
		auxData: map[string]*v1.AuxData{
			"test_aux_data": {Jwt: map[string]*structpb.Value{"answer": structpb.NewNumberValue(42)}},
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
