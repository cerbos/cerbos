module github.com/cerbos/cerbos/api/genpb

go 1.21

toolchain go1.23.2

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.35.1-20240920164238-5a7b106cbb87.1
	connectrpc.com/connect v1.17.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0
	github.com/planetscale/vtprotobuf v0.6.1-0.20241011083415-71c992bc3c87
	google.golang.org/genproto/googleapis/api v0.0.0-20241007155032-5fefd90f89a9
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.1
)

require (
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240930140551-af27646dc61f // indirect
)
