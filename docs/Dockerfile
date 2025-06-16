# Use the official Antora image as a base
# We use an ARG to make the version easily updatable
ARG ANTORA_VERSION=3.1.6
FROM antora/antora:${ANTORA_VERSION}

# Set the working directory inside the container
WORKDIR /antora

# --- Install Dependencies ---
# Copy the plugin source and package manifests first for better Docker layer caching.
# The build will only re-run `npm install` if these files change.

# Copy the source code of our custom plugin
COPY ./antora-llm-generator /antora/docs/antora-llm-generator

# Copy the main package files that define our dependencies
COPY package.json package-lock.json* ./

# Install all dependencies, including Antora and our local plugin
# This makes them available to the `antora` command.
RUN npm install

# The base image already has an ENTRYPOINT of ["antora"].
# We will provide the command to run in the `docker run` command,
# so no CMD is needed here.
