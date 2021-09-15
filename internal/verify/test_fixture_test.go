package verify

import (
	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
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
