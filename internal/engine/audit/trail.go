// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"maps"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func MergeTrails(a, b *auditv1.AuditTrail) *auditv1.AuditTrail {
	switch {
	case a == nil || len(a.EffectivePolicies) == 0:
		return b
	case b == nil || len(b.EffectivePolicies) == 0:
		return a
	default:
		if a.EffectivePolicies == nil {
			a.EffectivePolicies = make(map[string]*policyv1.SourceAttributes, len(b.EffectivePolicies))
		}
		maps.Copy(a.EffectivePolicies, b.EffectivePolicies)
		return a
	}
}
