publish: function-package
    #!/usr/bin/env bash
    arch=$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset --parameter-overrides ArchitectureParameter=$arch

publish-to-sar ARCH=arch() VERSION='': (function-package ARCH)
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ -z "${CERBOS_SAM_PACKAGING_BUCKET}" ]]; then
        echo "Error: CERBOS_SAM_PACKAGING_BUCKET environment variable is required for SAR publication"
        exit 1
    fi
    
    arch=$(sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/' <<< "{{ ARCH }}")
    app_name="cerbos-lambda-function-${arch}"
    
    # Create template with architecture-specific name
    sed "s/\"cerbos-lambda-function\"/\"${app_name}\"/" sam.yml > sam-sar.yml

    if [[ -z "{{ VERSION }}" ]]; then
        version=$(./dist/bootstrap --version 2>/dev/null | head -n1 | awk '{print $2}')
        # Remove 'v' prefix if present for SAR semantic versioning
        version=${version#v}
    else
        version="{{ VERSION }}"
    fi
    echo "Detected version: $version"
    echo "Detected architecture: $arch"
    echo "Publishing as: $app_name"
    echo "Packaging Lambda function for SAR..."
    sam package \
        --template-file sam-sar.yml \
        --s3-bucket "${CERBOS_SAM_PACKAGING_BUCKET}" \
        --output-template-file packaged-template.yml
    
    echo "Publishing to AWS Serverless Application Repository..."
    sam publish \
        --template packaged-template.yml \
        --semantic-version "$version"
    
    # Clean up temporary files
    rm -f sam-sar.yml packaged-template.yml

function-package ARCH=arch():
    #!/usr/bin/env bash
    arch=$(sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/' <<< "{{ ARCH }}")
    mkdir -p dist config-layer
    
    cp .cerbos.yaml config-layer/
    
    if [[ "$arch" == "arm64" ]] then
     ln -f "../../../dist/cerbosfunc_linux_arm64_v8.0/cerbosfunc" dist/bootstrap 
    else
     ln -f "../../../dist/cerbosfunc_linux_amd64_v1/cerbosfunc" dist/bootstrap 
    fi
