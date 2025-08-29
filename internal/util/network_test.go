// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package util

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewTransportForAddress(t *testing.T) {
	testCases := []struct {
		name        string
		addr        string
		expectError bool
	}{
		{
			name: "TCP address",
			addr: ":3592",
		},
		{
			name: "Unix socket",
			addr: "unix:/tmp/test.sock",
		},
		{
			name:        "Invalid address",
			addr:        "invalid://test",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := NewTransportForAddress(tc.addr)

			if tc.expectError {
				require.Error(t, err)
				require.Nil(t, transport)
			} else {
				require.NoError(t, err)
				require.NotNil(t, transport)
				require.IsType(t, &http.Transport{}, transport)
			}
		})
	}
}
