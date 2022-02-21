module github.com/cerbos/cerbos

go 1.17

require (
	contrib.go.opencensus.io/exporter/prometheus v0.4.0
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/alecthomas/chroma v0.10.0
	github.com/alecthomas/kong v0.4.0
	github.com/aws/aws-sdk-go v1.43.2
	github.com/bluele/gcache v0.0.2
	github.com/cespare/xxhash v1.1.0
	github.com/cespare/xxhash/v2 v2.1.2
	github.com/denisenkom/go-mssqldb v0.12.0
	github.com/dgraph-io/badger/v3 v3.2103.2
	github.com/doug-martin/goqu/v9 v9.18.0
	github.com/envoyproxy/protoc-gen-validate v0.6.3
	github.com/fatih/color v1.13.0
	github.com/fatih/structtag v1.2.0
	github.com/fergusstrange/embedded-postgres v1.14.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/gdamore/tcell/v2 v2.4.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-cmd/cmd v1.4.0
	github.com/go-git/go-git/v5 v5.4.2
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gobwas/glob v0.2.3
	github.com/golang-migrate/migrate/v4 v4.15.1
	github.com/google/cel-go v0.9.0
	github.com/google/go-cmp v0.5.7
	github.com/google/gops v0.3.22
	github.com/google/uuid v1.3.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.3
	github.com/iancoleman/strcase v0.2.0
	github.com/jackc/pgtype v1.10.0
	github.com/jackc/pgx/v4 v4.15.0
	github.com/jdxcode/netrc v0.0.0-20210204082910-926c7f70242a
	github.com/jmoiron/sqlx v1.3.4
	github.com/jwalton/gchalk v1.2.1
	github.com/kavu/go_reuseport v1.5.0
	github.com/lestrrat-go/jwx v1.2.18
	github.com/mattn/go-isatty v0.0.14
	github.com/minio/minio-go/v7 v7.0.22
	github.com/oklog/ulid/v2 v2.0.2
	github.com/olekukonko/tablewriter v0.0.5
	github.com/ory/dockertest/v3 v3.8.1
	github.com/planetscale/vtprotobuf v0.0.0-20210616093554-9236f7c7b8ca
	github.com/prometheus/client_golang v1.12.1
	github.com/rivo/tview v0.0.0-20210624165335-29d673af0ce2
	github.com/rjeczalik/notify v0.9.3-0.20201210012515-e2a77dcc14cf
	github.com/santhosh-tekuri/jsonschema/v5 v5.0.0
	github.com/spf13/afero v1.8.1
	github.com/spf13/cobra v1.3.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/gjson v1.14.0
	github.com/tidwall/sjson v1.2.4
	go.elastic.co/ecszap v1.0.1
	go.opencensus.io v0.23.0
	go.opentelemetry.io/otel v1.4.1
	go.opentelemetry.io/otel/bridge/opencensus v0.27.1
	go.opentelemetry.io/otel/exporters/jaeger v1.4.1
	go.opentelemetry.io/otel/sdk v1.4.1
	go.opentelemetry.io/otel/trace v1.4.1
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/config v1.4.0
	go.uber.org/multierr v1.7.0
	go.uber.org/zap v1.21.0
	gocloud.dev v0.24.0
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871
	golang.org/x/net v0.0.0-20220107192237-5cfca573fb4d
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/tools v0.1.9
	google.golang.org/genproto v0.0.0-20220118154757-00ab72f36ad5
	google.golang.org/grpc v1.44.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0
	helm.sh/helm/v3 v3.8.0
	modernc.org/sqlite v1.14.6
)

require (
	cloud.google.com/go v0.99.0 // indirect
	cloud.google.com/go/storage v1.18.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20210512092938-c05353c2d58c // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
	github.com/antlr/antlr4 v0.0.0-20200503195918-621b933c7a7f // indirect
	github.com/aws/aws-sdk-go-v2 v1.9.2 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.4.3 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.2.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.3.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.4.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.7.2 // indirect
	github.com/aws/smithy-go v1.8.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.2 // indirect
	github.com/census-instrumentation/opencensus-proto v0.3.0 // indirect
	github.com/cncf/udpa/go v0.0.0-20210930031921-04548b0d99d4 // indirect
	github.com/cncf/xds/go v0.0.0-20211130200136-a8f946100490 // indirect
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.0-20210816181553-5444fa50b93d // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/docker/cli v20.10.11+incompatible // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/envoyproxy/go-control-plane v0.10.1 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.3.1 // indirect
	github.com/go-kit/log v0.1.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/go-logr/logr v1.2.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/goccy/go-json v0.9.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.0.0-20170517235910-f1bb20e5a188 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/flatbuffers v2.0.0+incompatible // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/wire v0.5.0 // indirect
	github.com/googleapis/gax-go/v2 v2.1.1 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.11.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.2.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jwalton/go-supportscolor v1.1.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kevinburke/ssh_config v1.1.0 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.0 // indirect
	github.com/lestrrat-go/iter v1.0.1 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/lib/pq v1.10.4 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magefile/mage v1.9.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mattn/go-sqlite3 v1.14.10 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/minio/md5-simd v1.1.0 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/prometheus/statsd_exporter v0.21.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rs/xid v1.2.1 // indirect
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/xanzy/ssh-agent v0.3.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.opentelemetry.io/otel/metric v0.27.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v0.27.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/api v0.62.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	modernc.org/cc/v3 v3.35.22 // indirect
	modernc.org/ccgo/v3 v3.15.13 // indirect
	modernc.org/libc v1.14.5 // indirect
	modernc.org/mathutil v1.4.1 // indirect
	modernc.org/memory v1.0.5 // indirect
	modernc.org/opt v0.1.1 // indirect
	modernc.org/strutil v1.1.1 // indirect
	modernc.org/token v1.0.0 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
