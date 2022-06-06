FROM alpine:3.15 AS base
RUN apk add -U --no-cache ca-certificates && update-ca-certificates

FROM scratch
EXPOSE 3592 3593
ENV CERBOS_CONFIG="/conf.default.yaml"
VOLUME ["/policies"]
ENTRYPOINT ["/cerbos"]
CMD ["server"]
HEALTHCHECK --interval=1m --timeout=3s CMD ["/cerbos", "healthcheck"]
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY cerbos /cerbos
COPY conf.default.yaml /conf.default.yaml

