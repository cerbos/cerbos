module github.com/cerbos/cerbos/api/genpb

go 1.22.7

toolchain go1.23.4

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.2-20241127180247-a33202765966.1
	connectrpc.com/connect v1.18.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.25.1
	github.com/planetscale/vtprotobuf v0.6.1-0.20241121165744-79df5c4772f2
	google.golang.org/genproto/googleapis/api v0.0.0-20250106144421-5f5ef82da422
	google.golang.org/grpc v1.69.2
	google.golang.org/protobuf v1.36.2
)

require (
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250102185135-69823020774d // indirect
)
