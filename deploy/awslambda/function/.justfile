publish: (function-package 'arm64')
    #!/usr/bin/env bash
    sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-Cerbos} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset

export POLICY := '''
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: "20210210"
  resource: leave_request
  rules:
  - actions: ["condone"]
    roles:
        - employee
    effect: EFFECT_ALLOW
    condition:
      match:
        expr: R.attr.team == "design"
'''
export CONFIG := '''
auxData:
  jwt:
    disableVerification: true

storage:
  driver: "disk"
  disk:
    directory: /opt/policies
'''
# Build and publish AWS Lambda layer with Cerbos config and policies
publish-test-layer LAYER_NAME="cerbos-config-policies":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p test-layer-content/policies
    printf "%s" "$POLICY" > test-layer-content/policies/leave_request.yaml
    printf "%s" "$CONFIG" > test-layer-content/conf.yml

    cd test-layer-content
    zip -r ../{{ LAYER_NAME }}.zip .
    cd ..
    
    # Publish layer using AWS CLI
    aws lambda publish-layer-version \
        --layer-name "{{ LAYER_NAME }}" \
        --description "Cerbos configuration and policies layer" \
        --zip-file fileb://{{ LAYER_NAME }}.zip \
        --compatible-architectures arm64 x86_64
    
    # Cleanup
    rm -rf test-layer-content {{ LAYER_NAME }}.zip
    
    echo "Layer {{ LAYER_NAME }} published successfully"

publish-to-sar ARCH=arch() $VERSION $CERBOS_SAM_PACKAGING_BUCKET: (function-package ARCH)
    #!/usr/bin/env bash
    set -euo pipefail

    arch=$(sed -e 's/aarch64/arm64/' -e 's/amd64/x86_64/' <<< "{{ ARCH }}")
    app_name="cerbos-lambda-function-${arch/_/-}" # _ isn't valid character in the name
    
    # Create template with architecture-specific name, replace arch (noop if arch is arm64)
    sed -e "s/\"cerbos-lambda-function\"/\"${app_name}\"/" -e "s/- arm64/- ${arch}/" sam.yml > .sam.tmp.yml

    VERSION=${VERSION#v}

    echo "Detected version: $VERSION"
    echo "Detected architecture: $arch"
    echo "Publishing as: $app_name"
    echo "Packaging Lambda function for SAR..."
    sam package \
        --template-file .sam.tmp.yml \
        --s3-bucket "$CERBOS_SAM_PACKAGING_BUCKET" \
        --output-template-file packaged-template.yml > /dev/null
    
    echo "Publishing to AWS Serverless Application Repository..."
    sam publish \
        --template packaged-template.yml \
        --semantic-version "$VERSION"
    
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
