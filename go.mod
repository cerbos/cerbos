module github.com/cerbos/cerbos

go 1.16

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	contrib.go.opencensus.io/exporter/prometheus v0.3.0
	github.com/ProtonMail/gopenpgp/v2 v2.2.0 // indirect
	github.com/alecthomas/chroma v0.9.2
	github.com/bluele/gcache v0.0.2
	github.com/bufbuild/buf v0.43.2
	github.com/cespare/xxhash v1.1.0
	github.com/dgraph-io/badger/v3 v3.2103.0
	github.com/doug-martin/goqu/v9 v9.13.0
	github.com/envoyproxy/protoc-gen-validate v0.6.1
	github.com/fatih/color v1.12.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/fullstorydev/grpcurl v1.8.1
	github.com/gdamore/tcell/v2 v2.3.3
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-git/v5 v5.4.2
	github.com/golangci/golangci-lint v1.41.1
	github.com/google/cel-go v0.7.3
	github.com/google/go-cmp v0.5.6
	github.com/google/go-licenses v0.0.0-20210329231322-ce1d9163b77d
	github.com/google/gops v0.3.18
	github.com/google/uuid v1.2.0
	github.com/goreleaser/goreleaser v0.172.1
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.4.0
	github.com/iancoleman/strcase v0.1.3 // indirect
	github.com/jdxcode/netrc v0.0.0-20210204082910-926c7f70242a
	github.com/jmoiron/sqlx v1.3.4
	github.com/jwalton/gchalk v1.0.3
	github.com/kavu/go_reuseport v1.5.0
	github.com/lyft/protoc-gen-star v0.5.3 // indirect
	github.com/mattn/go-isatty v0.0.13
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/oklog/ulid/v2 v2.0.2
	github.com/open-policy-agent/opa v0.30.1
	github.com/planetscale/vtprotobuf v0.0.0-20210616093554-9236f7c7b8ca
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.29.0 // indirect
	github.com/prometheus/procfs v0.7.0 // indirect
	github.com/prometheus/statsd_exporter v0.21.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/tview v0.0.0-20210624165335-29d673af0ce2
	github.com/rjeczalik/notify v0.9.3-0.20201210012515-e2a77dcc14cf
	github.com/spf13/afero v1.6.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/sjson v1.1.7
	github.com/vektra/mockery/v2 v2.9.0
	go.elastic.co/ecszap v1.0.0
	go.opencensus.io v0.23.0
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/config v1.4.0
	go.uber.org/multierr v1.7.0
	go.uber.org/zap v1.18.1
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/time v0.0.0-20210611083556-38a9dc6acbc6 // indirect
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c
	google.golang.org/grpc v1.39.0-dev.0.20210519181852-3dd75a6888ce
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.27.1
	gotest.tools/gotestsum v1.6.4
	helm.sh/helm/v3 v3.6.2
	modernc.org/sqlite v1.11.2
)

replace github.com/docker/distribution => github.com/docker/distribution v0.0.0-20191216044856-a8371794149d

replace github.com/docker/docker => github.com/docker/docker v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible
