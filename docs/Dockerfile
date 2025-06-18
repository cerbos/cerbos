ARG ANTORA_VERSION=3.1.6
FROM antora/antora:${ANTORA_VERSION}
WORKDIR /antora
COPY ./antora-llm-generator /antora/docs/antora-llm-generator
COPY package.json package-lock.json* ./
RUN cd /antora/docs/antora-llm-generator && npm install
RUN cd /antora/docs
RUN npm install

