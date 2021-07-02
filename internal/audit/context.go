// Copyright 2021 Zenauth Ltd.

package audit

import (
	"context"
	"strings"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	auditv1 "github.com/cerbos/cerbos/internal/genpb/audit/v1"
)

const (
	delimiter          = "|"
	grpcGWUserAgentKey = "grpcgateway-user-agent"
	userAgentKey       = "user-agent"
	xffKey             = "x-forwarded-for"
)

type callIDCtxKeyType struct{}

var (
	callIDCtxKey = callIDCtxKeyType{}
	zeroID       = ID([16]byte{})
)

func NewContextWithCallID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, callIDCtxKey, id)
}

func CallIDFromContext(ctx context.Context) (ID, bool) {
	idVal := ctx.Value(callIDCtxKey)
	if idVal == nil {
		return zeroID, false
	}

	id, ok := idVal.(ID)
	if !ok {
		return zeroID, false
	}

	return id, true
}

func PeerFromContext(ctx context.Context) *auditv1.Peer {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}

	pp := &auditv1.Peer{Address: p.Addr.String()}
	if p.AuthInfo != nil {
		pp.AuthInfo = p.AuthInfo.AuthType()
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return pp
	}

	if ua, ok := md[grpcGWUserAgentKey]; ok {
		pp.UserAgent = strings.Join(ua, delimiter)
	} else if ua, ok := md[userAgentKey]; ok {
		pp.UserAgent = strings.Join(ua, delimiter)
	}

	if xff, ok := md[xffKey]; ok {
		pp.ForwardedFor = strings.Join(xff, delimiter)
	}

	return pp
}
