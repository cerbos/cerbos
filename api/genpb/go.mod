module github.com/cerbos/cerbos/api/genpb

go 1.22.7

toolchain go1.23.3

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.35.2-20240920164238-5a7b106cbb87.1
	connectrpc.com/connect v1.17.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.24.0
	github.com/planetscale/vtprotobuf v0.6.1-0.20241121165744-79df5c4772f2
	google.golang.org/genproto/googleapis/api v0.0.0-20241118233622-e639e219e697
	google.golang.org/grpc v1.68.0
	google.golang.org/protobuf v1.35.2
)

require (
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241118233622-e639e219e697 // indirect
)
