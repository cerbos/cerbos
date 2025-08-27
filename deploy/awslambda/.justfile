publish: function-package
    #!/usr/bin/env bash
    arch=$(uname -m)
    if [[ "$arch" == "aarch64" ]]; then
        arch=arm64
    fi
    if [[ "$arch" == "x86_64" ]]; then
        arch=amd64
    fi
    [ "$arch" != "x86_64" ] && [ "$arch" != "arm64" ] && { echo "${arch} - unsupported architecture, supported: x86_64, arm64" >&2; exit 1; } 
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset  --no-fail-on-empty-changeset --parameter-overrides ArchitectureParameter=$arch

function-package: 
	@ mkdir -p dist
	@ CGO_ENABLED=0 GOOS=linux go build -o dist/bootstrap main.go
	@ cp .cerbos.yaml dist/.cerbos.yaml
