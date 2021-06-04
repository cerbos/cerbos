module github.com/cerbos/cerbos

go 1.16

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	contrib.go.opencensus.io/exporter/prometheus v0.3.0
	github.com/ProtonMail/gopenpgp/v2 v2.1.9 // indirect
	github.com/bufbuild/buf v0.42.1
	github.com/cespare/xxhash v1.1.0
	github.com/doug-martin/goqu/v9 v9.13.0
	github.com/envoyproxy/protoc-gen-validate v0.6.1
	github.com/fatih/color v1.12.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/fullstorydev/grpcurl v1.8.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-git/v5 v5.4.0
	github.com/golangci/golangci-lint v1.40.1
	github.com/google/cel-go v0.7.3
	github.com/google/go-cmp v0.5.6
	github.com/google/go-licenses v0.0.0-20210329231322-ce1d9163b77d
	github.com/google/gops v0.3.18
	github.com/google/uuid v1.2.0
	github.com/goreleaser/goreleaser v0.166.2
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.4.0
	github.com/iancoleman/strcase v0.1.3 // indirect
	github.com/jmoiron/sqlx v1.3.4
	github.com/kavu/go_reuseport v1.5.0
	github.com/lyft/protoc-gen-star v0.5.3 // indirect
	github.com/mattn/go-isatty v0.0.12
	github.com/mattn/go-runewidth v0.0.12 // indirect
	github.com/mattn/go-sqlite3 v1.14.7
	github.com/open-policy-agent/opa v0.28.0
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/common v0.20.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rjeczalik/notify v0.9.3-0.20201210012515-e2a77dcc14cf
	github.com/spf13/afero v1.6.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/sjson v1.1.6
	go.elastic.co/ecszap v1.0.0
	go.opencensus.io v0.23.0
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/config v1.4.0
	go.uber.org/multierr v1.7.0
	go.uber.org/zap v1.16.0
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	google.golang.org/genproto v0.0.0-20210524142926-3e3a6030be83
	google.golang.org/grpc v1.38.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.26.0
	gotest.tools/gotestsum v1.6.4
	helm.sh/helm/v3 v3.5.4
)

replace github.com/docker/distribution => github.com/docker/distribution v0.0.0-20191216044856-a8371794149d

replace github.com/docker/docker => github.com/docker/docker v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible
