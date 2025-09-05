publish: function-package
    #!/usr/bin/env bash
    arch=$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset --parameter-overrides ArchitectureParameter=$arch

function-package: 
	@ mkdir -p dist
	@ CGO_ENABLED=0 GOOS=linux go build -o dist/bootstrap main.go
	@ cp .cerbos.yaml dist/.cerbos.yaml
