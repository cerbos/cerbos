module github.com/cerbos/cerbos/api/genpb

go 1.21

toolchain go1.23.2

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.34.2-20240920164238-5a7b106cbb87.2
	connectrpc.com/connect v1.17.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0
	github.com/planetscale/vtprotobuf v0.6.1-0.20240917153116-6f2963f01587
	google.golang.org/genproto/googleapis/api v0.0.0-20240930140551-af27646dc61f
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.34.2
)

require (
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240924160255-9d4c2d233b61 // indirect
)
