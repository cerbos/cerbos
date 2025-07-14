module github.com/cerbos/cerbos/api/genpb

go 1.23.4

toolchain go1.24.5

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.6-20250625184727-c923a0c2a132.1
	connectrpc.com/connect v1.18.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.1
	github.com/planetscale/vtprotobuf v0.6.1-0.20250313105119-ba97887b0a25
	google.golang.org/genproto/googleapis/api v0.0.0-20250707201910-8d1bb00bc6a7
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
)

require (
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
)
