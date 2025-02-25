// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http/httptest"
	"testing"

	"github.com/cerbos/cerbos/internal/audit"
	gateway "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestPeerFromContext(t *testing.T) {
	t.Run("gRPC", func(t *testing.T) {
		ctx := peer.NewContext(
			metadata.NewIncomingContext(t.Context(), metadata.Pairs(
				audit.HTTPRemoteAddrKey, "attempted spoof",
				audit.SetByGRPCGatewayKey, "attempted spoof",
				"User-Agent", "peer-from-context",
				"X-Forwarded-For", "1.1.1.1, 2.2.2.2",
				"X-Forwarded-For", "3.3.3.3",
			)),
			&peer.Peer{Addr: peerAddr("4.4.4.4:12345")},
		)

		p := audit.PeerFromContext(ctx)
		assert.Equal(t, "4.4.4.4:12345", p.Address)
		assert.Equal(t, "1.1.1.1, 2.2.2.2, 3.3.3.3", p.ForwardedFor)
		assert.Equal(t, "peer-from-context", p.UserAgent)
	})

	t.Run("HTTP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set(audit.HTTPRemoteAddrKey, "attempted spoof")
		req.Header.Set(audit.SetByGRPCGatewayKey, "attempted spoof")
		req.Header.Set("User-Agent", "peer-from-context")
		req.Header.Add("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
		req.Header.Add("X-Forwarded-For", "3.3.3.3")
		req.RemoteAddr = "4.4.4.4:12345"

		ctx, err := gateway.AnnotateIncomingContext(t.Context(), mkGatewayMux(nil), req, "example.Service/Method")
		require.NoError(t, err)

		peer := audit.PeerFromContext(ctx)
		assert.Equal(t, "4.4.4.4:12345", peer.Address)
		assert.Equal(t, "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4", peer.ForwardedFor)
		assert.Equal(t, "peer-from-context", peer.UserAgent)
	})
}

type peerAddr string

func (peerAddr) Network() string {
	return "tcp"
}

func (a peerAddr) String() string {
	return string(a)
}
