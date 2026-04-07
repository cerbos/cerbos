// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var routingRuleRowFields = map[protoreflect.Name]struct{}{
	"resource": {}, "role": {},
	"action": {}, "allow_actions": {},
	"scope": {}, "version": {},
	"principal": {},
}

var metadataOnlyFields = map[protoreflect.Name]struct{}{
	"origin_fqn":          {},
	"origin_derived_role": {},
	"evaluation_key":      {},
	"name":                {},
}

func TestAllRuleRowFieldsClassified(t *testing.T) {
	desc := (&runtimev1.RuleTable_RuleRow{}).ProtoReflect().Descriptor()
	fields := desc.Fields()
	for i := range fields.Len() {
		name := fields.Get(i).Name()
		_, isFunctional := functionalRuleRowFields[name]
		_, isRouting := routingRuleRowFields[name]
		_, isNonFunctional := metadataOnlyFields[name]
		require.Truef(t, isFunctional || isRouting || isNonFunctional,
			"RuleRow field %q is not classified: add it to functionalRuleRowFields, routingRuleRowFields, or metadataOnlyFields in checksum_test.go", name)

		n := 0
		if isFunctional {
			n++
		}
		if isRouting {
			n++
		}
		if isNonFunctional {
			n++
		}
		require.Equalf(t, 1, n, "RuleRow field %q appears in multiple classification sets", name)
	}
}

func TestFunctionalChecksumExcludesRoutingFields(t *testing.T) {
	base := &runtimev1.RuleTable_RuleRow{
		Effect:     effectv1.Effect_EFFECT_ALLOW,
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
	}

	t.Run("different scope same checksum", func(t *testing.T) {
		a := proto.Clone(base).(*runtimev1.RuleTable_RuleRow) //nolint:forcetypeassert
		a.Scope = "acme"

		b := proto.Clone(base).(*runtimev1.RuleTable_RuleRow) //nolint:forcetypeassert
		b.Scope = "acme.hr"

		require.Equal(t,
			util.HashPB(a, nonFunctionalChecksumFields),
			util.HashPB(b, nonFunctionalChecksumFields),
			"routing field scope should not affect functional checksum",
		)
	})

	t.Run("different effect different checksum", func(t *testing.T) {
		a := proto.Clone(base).(*runtimev1.RuleTable_RuleRow) //nolint:forcetypeassert
		a.Effect = effectv1.Effect_EFFECT_ALLOW

		b := proto.Clone(base).(*runtimev1.RuleTable_RuleRow) //nolint:forcetypeassert
		b.Effect = effectv1.Effect_EFFECT_DENY

		require.NotEqual(t,
			util.HashPB(a, nonFunctionalChecksumFields),
			util.HashPB(b, nonFunctionalChecksumFields),
			"functional field effect should affect functional checksum",
		)
	})
}
