// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"cmp"
	"slices"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

func attributeList(in map[string]*responsev1.InspectPoliciesResponse_Attribute) []*responsev1.InspectPoliciesResponse_Attribute {
	out := make([]*responsev1.InspectPoliciesResponse_Attribute, 0, len(in))
	for _, attr := range in {
		out = append(out, &responsev1.InspectPoliciesResponse_Attribute{
			Name: attr.Name,
			Kind: attr.Kind,
		})
	}

	if len(out) > 1 {
		slices.SortFunc(out, func(a, b *responsev1.InspectPoliciesResponse_Attribute) int {
			if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
				return kind
			}

			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return out
}
