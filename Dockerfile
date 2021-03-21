FROM golang:1.16-alpine as builder
ARG SRC_DIR=/go/src/github.com/cerbos/cerbos
RUN apk --no-cache add --update make build-base git
ADD . $SRC_DIR
WORKDIR $SRC_DIR
RUN mkdir -p hack/tools/bin
RUN make build 

FROM scratch
COPY --from=builder /go/src/github.com/cerbos/cerbos/cerbos /cerbos
ENTRYPOINT ["/cerbos"]

