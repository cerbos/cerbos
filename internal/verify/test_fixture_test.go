// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
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
		name    string
		want    map[string]*v1.Principal
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
	harry := &v1.Principal{Id: "harry"}
	maggie := &v1.Principal{Id: "maggie"}
	harryLeaveRequest := &v1.Resource{Id: "harry_leave_request"}

	tf := &testFixture{
		principals: map[string]*v1.Principal{
			"harry":  harry,
			"maggie": maggie,
		},
		resources: map[string]*v1.Resource{
			"harry_leave_request": harryLeaveRequest,
		},
	}
	requestID := "requestID"
	name := "harry leave request"
	actions := []string{"view", "approve"}
	table := &policyv1.TestTable{
		Name: name,
		Input: &policyv1.TestTable_CheckInput{
			RequestId: requestID,
			Resource:  harryLeaveRequest.Id,
			Actions:   actions,
		},
		Expected: []*policyv1.TestTable_ExpectedItem{
			{
				Principal: "harry",
				Actions: map[string]effectv1.Effect{
					"view":    effectv1.Effect_EFFECT_ALLOW,
					"approve": effectv1.Effect_EFFECT_DENY,
				},
			},
			{
				Principal: "maggie",
				Actions: map[string]effectv1.Effect{
					"view":    effectv1.Effect_EFFECT_ALLOW,
					"approve": effectv1.Effect_EFFECT_ALLOW,
				},
			},
		},
	}
	ts := &policyv1.TestSuite{Tests: []*policyv1.TestTable{table}}
	expectedTests := []*policyv1.Test{
		{
			Name: &policyv1.Test_TestName{TestTableName: name, PrincipalKey: harry.Id},
			Input: &v1.CheckInput{
				RequestId: requestID,
				Resource:  harryLeaveRequest,
				Principal: harry,
				Actions:   actions,
			},
			Expected: table.Expected[0].Actions,
		},
		{
			Name: &policyv1.Test_TestName{TestTableName: name, PrincipalKey: maggie.Id},
			Input: &v1.CheckInput{
				RequestId: requestID,
				Resource:  harryLeaveRequest,
				Principal: maggie,
				Actions:   actions,
			},
			Expected: table.Expected[1].Actions,
		},
	}
	got, err := tf.getTests(ts)
	require.NoError(t, err)

	if diff := cmp.Diff(got, expectedTests, protocmp.Transform()); diff != "" {
		t.Errorf("getTests: diff = %s", diff)
	}
}
