# Path: docker/standard_validator/Dockerfile
# Change: Switched to a smaller 'slim' variant of the Rust base image to conserve disk space.

# --- Builder Stage ---
# Use the 'slim' variant of the Rust image to reduce disk footprint during build.
FROM rust:1.78-slim-bullseye as builder

# Set the working directory.
WORKDIR /usr/src/app

# The slim image is Debian-based and has apt-get.
# Install protobuf compiler for libp2p dependencies
RUN apt-get update && apt-get install -y protobuf-compiler

# Copy the entire workspace (respecting .dockerignore)
COPY . .

# Build the node binary in release mode with the required features.
RUN cargo build --release \
    -p depin-sdk-node \
    --no-default-features \
    --features "build-bins,consensus-poa,vm-wasm"

# --- Final Stage ---
# Use a minimal base image for a smaller footprint.
FROM debian:bullseye-slim

# Set the working directory.
WORKDIR /usr/local/bin

# Copy the compiled node binary from the builder stage.
COPY --from=builder /usr/src/app/target/release/depin-sdk-node .

# The CMD is specified in the docker-compose.yml to select the container role.
ENTRYPOINT ["/usr/local/bin/depin-sdk-node"]