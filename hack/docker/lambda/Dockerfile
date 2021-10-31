FROM gcr.io/distroless/base
COPY internal/test/testdata/store /policies
COPY lambda /lambda
ENTRYPOINT ["/lambda"]
