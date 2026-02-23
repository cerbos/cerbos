module github.com/cerbos/cerbos/api/genpb

go 1.25.0

toolchain go1.26.0

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20260209202127-80ab13bee0bf.1
	connectrpc.com/connect v1.19.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0
	github.com/planetscale/vtprotobuf v0.6.1-0.20250313105119-ba97887b0a25
	google.golang.org/genproto/googleapis/api v0.0.0-20260217215200-42d3e9bedb6d
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
)

require (
	go.opentelemetry.io/otel v1.40.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.40.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260209200024-4cfbd4190f57 // indirect
)
