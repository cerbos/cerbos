module github.com/cerbos/cerbos/api/genpb

go 1.21

toolchain go1.22.6

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.34.2-20240717164558-a6c49f84cc0f.2
	connectrpc.com/connect v1.16.2
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.21.0
	github.com/planetscale/vtprotobuf v0.6.0
	google.golang.org/genproto/googleapis/api v0.0.0-20240808171019-573a1156607a
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
)

require (
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240730163845-b1a4ccb954bf // indirect
)
