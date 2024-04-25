// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka_test

import (
	"context"
	"testing"

	"github.com/cerbos/cerbos/internal/audit/kafka"
	"github.com/stretchr/testify/require"
)

func TestNewTLSConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// certPath or keyPath are required if either one are set
	_, err := kafka.NewTLSConfig(ctx, 0, false, "path/to/ca", "path/to/cert", "")
	require.EqualError(t, err, "certPath and keyPath must both be empty or both be non-empty")

	_, err = kafka.NewTLSConfig(ctx, 0, false, "path/to/ca", "", "path/to/key")
	require.EqualError(t, err, "certPath and keyPath must both be empty or both be non-empty")

	caCertPath := "testdata/valid/certs/ca.crt"
	_, err = kafka.NewTLSConfig(ctx, 0, false, caCertPath, "", "")
	require.NoError(t, err)

	_, err = kafka.NewTLSConfig(ctx, 0, false, caCertPath, "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
	require.NoError(t, err)
}
