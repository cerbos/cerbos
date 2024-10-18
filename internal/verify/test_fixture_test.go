// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
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

principalGroups:
  designers:
    principals:
      - harry
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
				Fixtures: map[string]*enginev1.Principal{
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
				Groups: map[string][]string{
					"designers": {"harry"},
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
