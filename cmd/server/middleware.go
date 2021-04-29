package server

import (
	"context"

	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func XForwardedHostUnaryServerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return handler(ctx, req)
	}

	xfh, ok := md["x-forwarded-host"]
	if !ok {
		return handler(ctx, req)
	}

	tags := grpc_ctxtags.Extract(ctx).Set("http.x_forwarded_host", xfh)

	return handler(grpc_ctxtags.SetInContext(ctx, tags), req)
}

// loggingDecider prevents healthcheck requests from being logged.
func loggingDecider(fullMethodName string, _ error) bool {
	return fullMethodName != "/grpc.health.v1.Health/Check"
}
