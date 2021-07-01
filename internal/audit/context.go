// Copyright 2021 Zenauth Ltd.

package audit

import (
	"context"

	"google.golang.org/grpc/peer"

	auditv1 "github.com/cerbos/cerbos/internal/genpb/audit/v1"
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

	return pp
}
