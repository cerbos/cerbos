FROM public.ecr.aws/lambda/provided:al2
VOLUME ["/policies"]
ENTRYPOINT ["/lambda"]
COPY lambda /lambda
COPY hack/docker/lambda/conf.yaml /conf.yaml

