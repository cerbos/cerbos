module github.com/cerbos/cerbos/api/genpb

go 1.23.4

toolchain go1.24.2

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.6-20250307204501-0409229c3780.1
	connectrpc.com/connect v1.18.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3
	github.com/planetscale/vtprotobuf v0.6.1-0.20250313105119-ba97887b0a25
	google.golang.org/genproto/googleapis/api v0.0.0-20250409194420-de1ac958c67a
	google.golang.org/grpc v1.71.1
	google.golang.org/protobuf v1.36.6
)

require (
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250404141209-ee84b53bf3d0 // indirect
)
