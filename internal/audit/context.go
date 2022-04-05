// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"

	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
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
)

type callIDCtxKeyType struct{}

var callIDCtxKey = callIDCtxKeyType{}

func NewContextWithCallID(ctx context.Context, id ID) context.Context {
	tags := grpc_ctxtags.Extract(ctx)
	tagCtx := grpc_ctxtags.SetInContext(ctx, tags.Set(util.AppName, map[string]any{callIDTagKey: id}))

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
