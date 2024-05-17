// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	grpcGWUserAgentKey = "grpcgateway-user-agent"
	userAgentKey       = "user-agent"
	xffKey             = "x-forwarded-for"
	callIDTagKey       = "call_id"

	SetByGRPCGatewayKey = "x-cerbos-set-by-grpc-gateway"
	HTTPRemoteAddrKey   = "x-cerbos-http-remote-addr"
)

var SetByGRPCGatewayVal string

func init() {
	SetByGRPCGatewayVal = generateSetByGRPCGatewayVal()
}

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
	if !ok {
		return p
	}

	setByGateway := checkSetByGRPCGateway(md)

	var ua []string
	xff := md[xffKey]
	if setByGateway {
		if addr := md[HTTPRemoteAddrKey]; len(addr) > 0 {
			p.Address = addr[len(addr)-1]
		}

		ua = md[grpcGWUserAgentKey]
	} else {
		ua = md[userAgentKey]
	}

	p.UserAgent = strings.Join(ua, "|")
	p.ForwardedFor = strings.Join(xff, ", ")

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

func generateSetByGRPCGatewayVal() string {
	const n = 32
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("failed to generate %s header value: %w", SetByGRPCGatewayKey, err))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func checkSetByGRPCGateway(md metadata.MD) bool {
	v := md[SetByGRPCGatewayKey]
	return len(v) > 0 && subtle.ConstantTimeCompare([]byte(v[len(v)-1]), []byte(SetByGRPCGatewayVal)) == 1
}
