// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing_test

import (
	"context"
	"testing"

	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/stretchr/testify/require"
)

func TestTracingInit(t *testing.T) {
	// This test is for detecting whether the imported semconv version clashes with the semconv version of Otel libraries
	conf := tracing.Conf{
		SampleProbability: 1.0,
		Jaeger: &tracing.JaegerConf{
			AgentEndpoint: "localhost:6900",
		},
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	t.Cleanup(cancelFn)

	require.NoError(t, tracing.InitFromConf(ctx, conf))
}
