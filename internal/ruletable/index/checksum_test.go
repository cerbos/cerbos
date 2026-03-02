// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/emptypb"
)

var knownNonFunctionalFields = map[protoreflect.Name]struct{}{
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
		_, isNonFunctional := knownNonFunctionalFields[name]
		require.Truef(t, isFunctional || isNonFunctional,
			"RuleRow field %q is not classified: add it to functionalRuleRowFields or knownNonFunctionalFields in checksum_test.go", name)
		require.Falsef(t, isFunctional && isNonFunctional,
			"RuleRow field %q is in both functionalRuleRowFields and knownNonFunctionalFields", name)
	}
}

func TestActionSetValuesAffectFunctionalChecksum(t *testing.T) {
	base := &runtimev1.RuleTable_RuleRow{
		Resource:   "resource",
		Role:       "role",
		Scope:      "scope",
		Version:    "v1",
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
	}

	t.Run("action", func(t *testing.T) {
		actionRowView := protoClone(base)
		actionRowView.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}

		actionRowEdit := protoClone(base)
		actionRowEdit.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "edit"}

		require.NotEqual(t,
			util.HashPB(actionRowView, ignoredNonFunctionalFields),
			util.HashPB(actionRowEdit, ignoredNonFunctionalFields),
			"different action values should produce different functional checksums",
		)
	})

	t.Run("allow_actions", func(t *testing.T) {
		allowActionsRowView := protoClone(base)
		allowActionsRowView.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
			AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
				Actions: map[string]*emptypb.Empty{"view": {}},
			},
		}

		allowActionsRowEdit := protoClone(base)
		allowActionsRowEdit.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
			AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
				Actions: map[string]*emptypb.Empty{"edit": {}},
			},
		}

		require.NotEqual(t,
			util.HashPB(allowActionsRowView, ignoredNonFunctionalFields),
			util.HashPB(allowActionsRowEdit, ignoredNonFunctionalFields),
			"different allow_actions values should produce different functional checksums",
		)
	})
}

func protoClone(r *runtimev1.RuleTable_RuleRow) *runtimev1.RuleTable_RuleRow {
	return proto.Clone(r).(*runtimev1.RuleTable_RuleRow) //nolint:forcetypeassert
}
