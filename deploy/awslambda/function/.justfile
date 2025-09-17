publish: (function-package 'arm64')
    #!/usr/bin/env bash
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset

publish-to-sar VERSION='' ARCH=arch(): (function-package ARCH)
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ -z "${CERBOS_SAM_PACKAGING_BUCKET}" ]]; then
        echo "Error: CERBOS_SAM_PACKAGING_BUCKET environment variable is required for SAR publication"
        exit 1
    fi
    if [[ -z "{{ VERSION }}" ]]; then
        echo "Error: version is required"
        exit 1
    fi
    
    arch=$(sed -e 's/aarch64/arm64/' -e 's/amd64/x86_64/' <<< "{{ ARCH }}")
    app_name="cerbos-lambda-function-${arch/_/-}" # _ isn't valid character in the name
    
    # Create template with architecture-specific name, replace arch (noop if arch is arm64)
    sed -e "s/\"cerbos-lambda-function\"/\"${app_name}\"/" -e "s/- arm64/- ${arch}/" sam.yml > .sam.tmp.yml

    version=${version#v}
    echo "Detected version: $version"
    echo "Detected architecture: $arch"
    echo "Publishing as: $app_name"
    echo "Packaging Lambda function for SAR..."
    sam package \
        --template-file .sam.tmp.yml \
        --s3-bucket "${CERBOS_SAM_PACKAGING_BUCKET}" \
        --output-template-file packaged-template.yml > /dev/null
    
    echo "Publishing to AWS Serverless Application Repository..."
    sam publish \
        --template packaged-template.yml \
        --semantic-version "$version"
    
    # Clean up temporary files
    rm -f .sam.tmp.yml packaged-template.yml

function-package ARCH=arch():
    #!/usr/bin/env bash
    arch=$(sed -e 's/aarch64/arm64/' <<< "{{ ARCH }}")
    mkdir -p dist config-layer
    
    cp .cerbos.yaml config-layer/
    
    if [[ "$arch" == "arm64" ]] then
     ln -f "../../../dist/cerbosfunc_linux_arm64_v8.0/cerbosfunc" dist/bootstrap 
    else
     ln -f "../../../dist/cerbosfunc_linux_amd64_v1/cerbosfunc" dist/bootstrap 
    fi
