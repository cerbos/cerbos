FROM gcr.io/distroless/base
#FROM alpine:latest
COPY internal/test/testdata/store /policies
COPY hack/docker/lambda/conf.yaml /conf.yaml
COPY lambda /lambda
ENTRYPOINT ["/lambda"]
