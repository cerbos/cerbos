// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	delimiter          = "|"
	grpcGWUserAgentKey = "grpcgateway-user-agent"
	userAgentKey       = "user-agent"
	xffKey             = "x-forwarded-for"
	callIDTagKey       = "call_id"

	HTTPRemoteAddrKey = "x-cerbos-http-remote-addr"
)

type callIDCtxKeyType struct{}

var callIDCtxKey = callIDCtxKeyType{}

func NewContextWithCallID(ctx context.Context, id ID) context.Context {
	tagCtx := logging.InjectLogField(ctx, util.AppName, map[string]any{callIDTagKey: id})
	return context.WithValue(tagCtx, callIDCtxKey, id)
}

func CallIDFromContext(ctx context.Context) (ID, bool) {
	idVal := ctx.Value(callIDCtxKey)
	if idVal == nil {
		return "", false
	}

	id, ok := idVal.(ID)
	if !ok {
		return "", false
	}

	return id, true
}

func PeerFromContext(ctx context.Context) *auditv1.Peer {
	p := peerFromContext(ctx)
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if addr := md.Get(HTTPRemoteAddrKey); len(addr) > 0 {
			p.Address = addr[0]
		}

		if ua, ok := md[grpcGWUserAgentKey]; ok {
			p.UserAgent = strings.Join(ua, delimiter)
		} else if ua, ok := md[userAgentKey]; ok {
			p.UserAgent = strings.Join(ua, delimiter)
		}

		if xff, ok := md[xffKey]; ok {
			p.ForwardedFor = strings.Join(xff, delimiter)
		}
	}

	return p
}

func peerFromContext(ctx context.Context) *auditv1.Peer {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return &auditv1.Peer{}
	}

	pp := &auditv1.Peer{Address: p.Addr.String()}
	if p.AuthInfo != nil {
		pp.AuthInfo = p.AuthInfo.AuthType()
	}

	return pp
}
