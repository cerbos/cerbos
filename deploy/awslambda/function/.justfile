publish: function-package
    #!/usr/bin/env bash
    arch=$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset --parameter-overrides ArchitectureParameter=$arch

function-package:
    #!/usr/bin/env bash
    arch=$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
    mkdir -p dist
    if [[ "$arch" == "arm64" ]] then
     ln -f "../../../dist/cerbosfunc_linux_arm64_v8.0/cerbosfunc" dist/bootstrap 
    else
     ln -f "../../../dist/cerbosfunc_linux_amd64_v1/cerbosfunc" dist/bootstrap 
    fi
