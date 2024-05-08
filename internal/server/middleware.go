// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	cerboslogging "github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/svc"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	adminSvcDisabled      = "Admin service is disabled by the configuration"
	playgroundSvcDisabled = "Playground service is disabled by the configuration"
	unknownSvc            = "Unknown service"
)

type methodNameCtxKeyType struct{}

var methodNameCtxKey = &methodNameCtxKeyType{}

func RequestMetadataUnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// New logging interceptor doesn't have access to method name so we save it to context for later use.
	newCtx := context.WithValue(ctx, methodNameCtxKey, info.FullMethod)

	reqMeta := svc.ExtractRequestFields(info.FullMethod, req)
	xffHeaders := make(map[string]any, 2) //nolint:mnd

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		xfh, ok := md["x-forwarded-host"]
		if ok {
			xffHeaders["x_forwarded_host"] = xfh
		}

		xff, ok := md["x-forwarded-for"]
		if ok {
			xffHeaders["x_forwarded_for"] = xff
		}
	}

	// Fields are key-value pairs. Because we are adding "meta" and "http", the expected length is 4.
	fields := make(logging.Fields, 0, 4) //nolint:mnd

	if len(xffHeaders) > 0 {
		fields = append(fields, "http", xffHeaders)
	}

	if len(reqMeta) > 0 {
		for k, v := range reqMeta {
			fields = append(fields, k, v)
		}
	}

	return handler(logging.InjectFields(newCtx, fields), req)
}

func RequestLogger(log *zap.Logger, msg string) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, level logging.Level, _ string, fields ...any) {
		if method, ok := ctx.Value(methodNameCtxKey).(string); ok {
			if method == "/grpc.health.v1.Health/Check" {
				return
			}
		}

		zapLvl := zap.InfoLevel
		switch level {
		case logging.LevelDebug:
			zapLvl = zap.DebugLevel
		case logging.LevelInfo:
			zapLvl = zap.InfoLevel
		case logging.LevelWarn:
			zapLvl = zap.WarnLevel
		case logging.LevelError:
			zapLvl = zap.ErrorLevel
		}

		log.Check(zapLvl, msg).Write(cerboslogging.GRPCLogFieldsToZap(fields)...)
	})
}

func PayloadLogger(conf *Conf) logging.Logger {
	if conf.LogRequestPayloads {
		log := RequestLogger(zap.L().Named("payload"), "server response payload logged as grpc.response.content field")
		return logging.LoggerFunc(func(ctx context.Context, level logging.Level, msg string, fields ...any) {
			if method, ok := ctx.Value(methodNameCtxKey).(string); ok {
				if strings.HasPrefix(method, "/cerbos.svc.v1") {
					log.Log(ctx, level, msg, fields...)
				}
			}
		})
	}

	return logging.LoggerFunc(func(_ context.Context, _ logging.Level, _ string, _ ...any) {})
}

// accessLogExclude decides which methods to exclude from being logged to the access log.
func accessLogExclude(method string) bool {
	return strings.HasPrefix(method, "/grpc.")
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

	opts := cors.Options{
		AllowedOrigins: conf.CORS.AllowedOrigins,
		AllowedHeaders: conf.CORS.AllowedHeaders,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
	}

	var logger cors.Logger
	if enabled, err := strconv.ParseBool(os.Getenv("CERBOS_DEBUG_CORS")); err == nil && enabled {
		l, err := zap.NewStdLogAt(zap.L().Named("cors"), zap.DebugLevel)
		if err != nil {
			l = zap.NewStdLog(zap.L().Named("cors"))
		}

		opts.Debug = true
		logger = l
	}

	c := cors.New(opts)
	c.Log = logger

	return c.Handler(handler)
}

func handleUnknownServices(_ any, stream grpc.ServerStream) error {
	errFn := func(msg string) error {
		return status.Errorf(codes.Unimplemented, msg)
	}

	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return errFn(unknownSvc)
	}

	parts := strings.Split(method, "/")
	if len(parts) < 2 { //nolint:mnd
		return errFn(unknownSvc)
	}

	switch parts[1] {
	case svcv1.CerbosAdminService_ServiceDesc.ServiceName:
		return errFn(adminSvcDisabled)
	case svcv1.CerbosPlaygroundService_ServiceDesc.ServiceName:
		return errFn(playgroundSvcDisabled)
	}

	return errFn(unknownSvc)
}

func handleRoutingError(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, httpStatus int) {
	if httpStatus == http.StatusNotFound && r != nil && r.URL != nil {
		errHandler := func(msg string) {
			err := &runtime.HTTPStatusError{
				HTTPStatus: httpStatus,
				Err:        status.Errorf(codes.Unimplemented, msg),
			}
			runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
		}

		switch {
		case strings.HasPrefix(r.URL.Path, adminEndpoint):
			errHandler(adminSvcDisabled)
			return
		case strings.HasPrefix(r.URL.Path, playgroundEndpoint):
			errHandler(playgroundSvcDisabled)
			return
		}
	}

	runtime.DefaultRoutingErrorHandler(ctx, mux, marshaler, w, r, httpStatus)
}

func cerbosVersionUnaryServerInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cerbos-version", util.Version))
	return handler(ctx, req)
}
