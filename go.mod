module github.com/cerbos/cerbos

go 1.17

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	contrib.go.opencensus.io/exporter/prometheus v0.4.0
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/ProtonMail/go-crypto v0.0.0-20210512092938-c05353c2d58c // indirect
	github.com/alecthomas/chroma v0.9.2
	github.com/bluele/gcache v0.0.2
	github.com/census-instrumentation/opencensus-proto v0.3.0 // indirect
	github.com/cespare/xxhash v1.1.0
	github.com/dgraph-io/badger/v3 v3.2103.1
	github.com/doug-martin/goqu/v9 v9.16.0
	github.com/envoyproxy/protoc-gen-validate v0.6.1
	github.com/fatih/color v1.13.0
	github.com/fergusstrange/embedded-postgres v1.11.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/gdamore/tcell/v2 v2.4.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-git/v5 v5.4.2
	github.com/go-sql-driver/mysql v1.6.0
	github.com/google/cel-go v0.8.0
	github.com/google/go-cmp v0.5.6
	github.com/google/gops v0.3.20
	github.com/google/uuid v1.3.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.6.0
	github.com/jackc/pgx/v4 v4.13.0
	github.com/jdxcode/netrc v0.0.0-20210204082910-926c7f70242a
	github.com/jmoiron/sqlx v1.3.4
	github.com/jwalton/gchalk v1.1.0
	github.com/kavu/go_reuseport v1.5.0
	github.com/kevinburke/ssh_config v1.1.0 // indirect
	github.com/klauspost/compress v1.13.5 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/matryer/is v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.14
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/oklog/ulid/v2 v2.0.2
	github.com/open-policy-agent/opa v0.32.1
	github.com/ory/dockertest/v3 v3.8.0
	github.com/planetscale/vtprotobuf v0.0.0-20210616093554-9236f7c7b8ca
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/procfs v0.7.0 // indirect
	github.com/prometheus/statsd_exporter v0.21.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/tview v0.0.0-20210624165335-29d673af0ce2
	github.com/rjeczalik/notify v0.9.3-0.20201210012515-e2a77dcc14cf
	github.com/rodaine/table v1.0.1
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/spf13/afero v1.6.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/sjson v1.2.2
	github.com/ulikunitz/xz v0.5.10 // indirect
	go.elastic.co/ecszap v1.0.0
	go.opencensus.io v0.23.0
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/config v1.4.0
	go.uber.org/multierr v1.7.0
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/net v0.0.0-20210825183410-e898025ed96a
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/api v0.46.0 // indirect
	google.golang.org/genproto v0.0.0-20210903162649-d08c68adba83
	google.golang.org/grpc v1.41.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0
	helm.sh/helm/v3 v3.7.0
	modernc.org/sqlite v1.13.1
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/PaesslerAG/gval v1.0.0 // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
	github.com/andybalholm/brotli v1.0.0 // indirect
	github.com/antlr/antlr4 v0.0.0-20200503195918-621b933c7a7f // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/containerd v1.5.5 // indirect
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/danwakefield/fnmatch v0.0.0-20160403171240-cbb64ac3d964 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/docker/cli v20.10.8+incompatible // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.7+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.3.1 // indirect
	github.com/go-kit/log v0.1.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/flatbuffers v2.0.0+incompatible // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.10.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.1.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.8.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jwalton/go-supportscolor v1.0.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/lib/pq v1.10.2 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magefile/mage v1.9.0 // indirect
	github.com/mattn/go-colorable v0.1.9 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mholt/archiver/v3 v3.5.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/moby/term v0.0.0-20210610120745-9d4ed1856297 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/pierrec/lz4/v4 v4.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.29.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/tidwall/gjson v1.9.1 // indirect
	github.com/tidwall/match v1.0.3 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/uber/jaeger-client-go v2.25.0+incompatible // indirect
	github.com/xanzy/ssh-agent v0.3.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/yashtewari/glob-intersection v0.0.0-20180916065949-5c77d914dd0b // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/sys v0.0.0-20210902050250-f475640dd07b // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.5 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	modernc.org/cc/v3 v3.34.0 // indirect
	modernc.org/ccgo/v3 v3.11.2 // indirect
	modernc.org/libc v1.11.3 // indirect
	modernc.org/mathutil v1.4.1 // indirect
	modernc.org/memory v1.0.5 // indirect
	modernc.org/opt v0.1.1 // indirect
	modernc.org/strutil v1.1.1 // indirect
	modernc.org/token v1.0.0 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace github.com/docker/distribution => github.com/docker/distribution v0.0.0-20191216044856-a8371794149d

replace github.com/docker/docker => github.com/docker/docker v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible
