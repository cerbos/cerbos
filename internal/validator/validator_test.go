// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/validator"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestValidator(t *testing.T) {
	testCases := []struct {
		name    string
		message proto.Message
		wantErr string
	}{
		{
			name:    "enum.in scalar",
			message: &privatev1.Validation{EnumIn: effectv1.Effect_EFFECT_NO_MATCH},
			wantErr: "must be one of [EFFECT_ALLOW, EFFECT_DENY]",
		},
		{
			name: "enum.in map",
			message: &privatev1.Validation{
				EnumIn:    effectv1.Effect_EFFECT_ALLOW,
				EnumInMap: map[string]effectv1.Effect{"foo": effectv1.Effect_EFFECT_NO_MATCH},
			},
			wantErr: "must be one of [EFFECT_ALLOW, EFFECT_DENY]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorContains(t, validator.Validate(tc.message), tc.wantErr)
		})
	}
}
