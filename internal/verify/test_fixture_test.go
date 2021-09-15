package verify

import (
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"testing"
	"testing/fstest"
)

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

func Test_loadPrincipals(t *testing.T) {
	fsys := make(fstest.MapFS)
	fsys["a/testdata/principals.yaml"] = &fstest.MapFile{Data: []byte(principals)}

	tests := []struct {
		name    string
		want    map[string]*v1.Principal
		wantErr bool
	}{
		{
			name: "a/testdata",
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
	requestId := "requestId"
	name := "harry leave request"
	actions := []string{"view", "approve"}
	table := &policyv1.TestTable{
		Name: name,
		Input: &policyv1.TestTable_CheckInput{
			RequestId: requestId,
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
	expectedTests := []*policyv1.Test{{
		Name: name,
		Input: &v1.CheckInput{
			RequestId: requestId,
			Resource:  harryLeaveRequest,
			Principal: harry,
			Actions:   actions,
		},
		Expected: table.Expected[0].Actions,
	},
	{
		Name: name,
		Input: &v1.CheckInput{
			RequestId: requestId,
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
