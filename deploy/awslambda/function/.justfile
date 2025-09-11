publish: function-package
    #!/usr/bin/env bash
    arch=$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset --parameter-overrides ArchitectureParameter=$arch

publish-to-sar: function-package
    #!/usr/bin/env bash
    if [[ -z "${CERBOS_SAM_PACKAGING_BUCKET}" ]]; then
        echo "Error: CERBOS_SAM_PACKAGING_BUCKET environment variable is required for SAR publication"
        exit 1
    fi
    
    version=${CERBOS_VERSION:-1.0.0}
    
    echo "Packaging Lambda function for SAR..."
    sam package \
        --template-file sam.yml \
        --s3-bucket "${CERBOS_SAM_PACKAGING_BUCKET}" \
        --output-template-file packaged-template.yml
    
    echo "Publishing to AWS Serverless Application Repository..."
    sam publish \
        --template packaged-template.yml \
        --semantic-version "$version"

function-package:
    #!/usr/bin/env bash
    arch=$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
    mkdir -p dist config-layer
    
    cp .cerbos.yaml config-layer/
    
    if [[ "$arch" == "arm64" ]] then
     ln -f "../../../dist/cerbosfunc_linux_arm64_v8.0/cerbosfunc" dist/bootstrap 
    else
     ln -f "../../../dist/cerbosfunc_linux_amd64_v1/cerbosfunc" dist/bootstrap 
    fi
