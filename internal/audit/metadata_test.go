// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestMetadataExtractor(t *testing.T) {
	testCases := []struct {
		input       map[string]string
		want        map[string]*auditv1.MetaValues
		name        string
		includeKeys []string
		excludeKeys []string
	}{
		{
			name:  "NoIncludeOrExclude",
			input: map[string]string{"foo": "a", "bar": "b"},
		},
		{
			name:        "OnlyInclude",
			includeKeys: []string{"foo", "bar"},
			input:       map[string]string{"foo": "a", "bar": "b", "baz": "c"},
			want: map[string]*auditv1.MetaValues{
				"foo": {Values: []string{"a"}},
				"bar": {Values: []string{"b"}},
			},
		},
		{
			name:        "OnlyExclude",
			excludeKeys: []string{"foo", "bar"},
			input:       map[string]string{"foo": "a", "bar": "b", "baz": "c", "authorization": "d"},
			want: map[string]*auditv1.MetaValues{
				"baz": {Values: []string{"c"}},
			},
		},
		{
			name:        "BothIncludeAndExclude",
			includeKeys: []string{"foo"},
			excludeKeys: []string{"bar"},
			input:       map[string]string{"foo": "a", "bar": "b", "baz": "c", "authorization": "d"},
			want: map[string]*auditv1.MetaValues{
				"foo": {Values: []string{"a"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &Conf{
				confHolder: confHolder{
					IncludeMetadataKeys: tc.includeKeys,
					ExcludeMetadataKeys: tc.excludeKeys,
				},
			}
			me := NewMetadataExtractorFromConf(conf)
			ctx := metadata.NewIncomingContext(context.Background(), metadata.New(tc.input))

			have := me(ctx)
			require.Len(t, have, len(tc.want))
			require.True(t, cmp.Equal(tc.want, have, protocmp.Transform()))
		})
	}
}
