// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package otel_test

import (
	"os"
	"testing"

	"github.com/cerbos/cerbos/internal/observability/otel"
	"github.com/stretchr/testify/require"
)

func TestEnv(t *testing.T) {
	t.Setenv(otel.TracesEndpointEV.Name, "https://traces.local")
	t.Setenv(otel.TracesEndpointEV.Alt, "https://traces-alt.local")
	t.Setenv(otel.TracesEndpointInsecureEV.Alt, "true")
	env := otel.Env(os.LookupEnv)

	testCases := []struct {
		name   string
		envVar otel.EnvVar
		want   string
	}{
		{
			name:   "first_choice_exists",
			envVar: otel.TracesEndpointEV,
			want:   "https://traces.local",
		},
		{
			name:   "alt_choice_exists",
			envVar: otel.TracesEndpointInsecureEV,
			want:   "true",
		},
		{
			name:   "not_exists",
			envVar: otel.ServiceNameEV,
			want:   "default",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := env.GetOrDefault(tc.envVar, "default")
			require.Equal(t, tc.want, have)
		})
	}
}
