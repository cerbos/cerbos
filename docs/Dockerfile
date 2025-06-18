ARG ANTORA_VERSION=3.1.6
FROM antora/antora:${ANTORA_VERSION}
WORKDIR /antora
COPY ./antora-llm-generator /antora-llm-generator
RUN yarn global add /antora-llm-generator
