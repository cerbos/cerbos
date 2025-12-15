module github.com/cerbos/cerbos/api/genpb

go 1.24.0

toolchain go1.25.5

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20251209175733-2a1774d88802.1
	connectrpc.com/connect v1.19.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.3
	github.com/planetscale/vtprotobuf v0.6.1-0.20250313105119-ba97887b0a25
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.46.1-0.20251013234738-63d1a5100f82 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251124214823-79d6a2a48846 // indirect
)
