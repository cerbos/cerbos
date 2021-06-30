// Copyright 2021 Zenauth Ltd.

package audit

import (
	"context"

	"google.golang.org/grpc"
)

func NewUnaryInterceptor(log Log) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}
}
