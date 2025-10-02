publish: (function-package 'arm64')
    @ sam deploy --template sam.yml --stack-name ${CERBOS_STACK_NAME:-CerbosExt} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset 

publish-to-sar $VERSION $CERBOS_SAM_PACKAGING_BUCKET ARCH=arch() : (function-package ARCH)
    #!/usr/bin/env bash
    set -euo pipefail

    arch=$(sed -e 's/aarch64/arm64/' -e 's/amd64/x86_64/' <<< "{{ ARCH }}")
    app_name="cerbos-lambda-extension-${arch/_/-}" # _ isn't valid character in the name
    
    # Create template with architecture-specific name, replace arch (noop if arch is arm64)
    sed -e "s/\"cerbos-lambda-extension\"/\"${app_name}\"/" -e "s/- arm64/- ${arch}/" sam.yml > .sam.tmp.yml

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
    arch=$(sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/' <<< "{{ ARCH }}")
    rm -rf dist layer/extensions
    mkdir -p dist layer/extensions
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o dist/bootstrap main.go
    cp .cerbos.yaml dist/.cerbos.yaml
    cp -r ../policies dist

    if [[ "$arch" == "arm64" ]] then
     ln -f "../../../dist/cerbosext_linux_arm64_v8.0/cerbosext" layer/extensions/cerbosext
    else
     ln -f "../../../dist/cerbosext_linux_amd64_v1/cerbosext" layer/extensions/cerbosext
    fi

publish-test-function:
    rm -rf dist
    mkdir -p dist
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/bootstrap main.go
    cp .cerbos.yaml dist/.cerbos.yaml
    cp -r ../policies dist
    sam deploy --template sam.test.yml --stack-name ${CERBOS_STACK_NAME:-TestCerbosExtension} --resolve-s3 \
    --capabilities CAPABILITY_IAM --no-confirm-changeset --no-fail-on-empty-changeset --profile test-sar-cerbos
