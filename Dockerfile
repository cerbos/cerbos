FROM gcr.io/distroless/base
EXPOSE 3592 3593
VOLUME ["/policies"]
ENTRYPOINT ["/cerbos"]
CMD ["server", "--config=/conf.default.yaml"]
COPY cerbos /cerbos
COPY conf.default.yaml /conf.default.yaml

