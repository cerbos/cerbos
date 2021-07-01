// Copyright 2021 Zenauth Ltd.

package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/handlers"
	grpc_logging "github.com/grpc-ecosystem/go-grpc-middleware/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
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

// accessLogExclude decides which methods to exclude from being logged to the access log.
func accessLogExclude(method string) bool {
	return strings.HasPrefix(method, "/grpc.")
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

// messageProducer handles gRPC log messages.
func messageProducer(ctx context.Context, _ string, level zapcore.Level, code codes.Code, err error, duration zapcore.Field) {
	ctxzap.Extract(ctx).Check(level, "Handled request").Write(
		zap.Error(err),
		zap.String("grpc.code", code.String()),
		duration,
	)
}

// prettyJSON instructs grpc-gateway to output pretty JSON when the query parameter is present.
func prettyJSON(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["pretty"]; ok {
			r.Header.Set("Accept", "application/json+pretty")
		}
		h.ServeHTTP(w, r)
	})
}

func customHTTPResponseCode(ctx context.Context, w http.ResponseWriter, _ proto.Message) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	if vals := md.HeaderMD.Get("x-http-code"); len(vals) > 0 {
		code, err := strconv.Atoi(vals[0])
		if err != nil {
			return fmt.Errorf("invalid http code: %w", err)
		}

		delete(md.HeaderMD, "x-http-code")
		delete(w.Header(), "Grpc-Metadata-X-Http-Code")

		w.WriteHeader(code)
	}

	return nil
}

func withCORS(conf *Conf, handler http.Handler) http.Handler {
	if conf.CORS.Disabled {
		return handler
	}

	var opts []handlers.CORSOption
	if len(conf.CORS.AllowedOrigins) > 0 {
		opts = append(opts, handlers.AllowedOrigins(conf.CORS.AllowedOrigins))
	} else {
		opts = append(opts, handlers.AllowedOrigins([]string{"*"}))
	}

	if len(conf.CORS.AllowedHeaders) > 0 {
		opts = append(opts, handlers.AllowedHeaders(conf.CORS.AllowedHeaders))
	}

	return handlers.CORS(opts...)(handler)
}

func withRequestLogging(handler http.Handler) http.Handler {
	log := zap.NewStdLog(zap.L().Named("http"))
	return handlers.CombinedLoggingHandler(log.Writer(), handler)
}
