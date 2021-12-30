FROM alpine:3.15 AS base
RUN apk add -U --no-cache ca-certificates && update-ca-certificates

FROM scratch
EXPOSE 3592 3593
VOLUME ["/policies"]
ENTRYPOINT ["/cerbos"]
CMD ["server", "--config=/conf.default.yaml"]
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY cerbos /cerbos
COPY conf.default.yaml /conf.default.yaml

