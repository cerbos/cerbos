package server

import (
	"context"
	"strings"

	grpc_logging "github.com/grpc-ecosystem/go-grpc-middleware/logging"
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

// payloadLoggingDecider decides whether to log request payloads.
func payloadLoggingDecider(conf *Conf) grpc_logging.ServerPayloadLoggingDecider {
	return func(ctx context.Context, fullMethodName string, servingObject interface{}) bool {
		return conf.LogRequestPayloads && strings.HasPrefix(fullMethodName, "/svc.v1")
	}
}
