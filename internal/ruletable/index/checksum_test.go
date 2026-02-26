// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// knownNonFunctionalFields lists RuleRow fields that are intentionally excluded
// from the functional checksum because they do not affect evaluation outcome.
var knownNonFunctionalFields = map[protoreflect.Name]struct{}{
	"origin_fqn":          {}, // identifies contributing policy; not part of evaluation
	"origin_derived_role": {}, // identifies contributing derived role; not part of evaluation
	"evaluation_key":      {}, // condition cache key; identical rows produce identical results
	"name":                {}, // rule name used for tracing/audit only
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
