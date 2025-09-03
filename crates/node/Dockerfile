# Path: crates/node/Dockerfile

# Stage 1: Build the binary
FROM rust:1.78-slim-bullseye as builder

WORKDIR /usr/src/depin-sdk
# FIX: Add pkg-config and libssl-dev to the list of installed packages.
RUN apt-get update && apt-get install -y protobuf-compiler build-essential pkg-config libssl-dev

# Add a build argument to accept features from the command line.
# The default value ensures that if no arg is provided, it still builds the base bins.
ARG FEATURES="validator-bins"

COPY . .

# Build the node package with the specified features.
# This allows building specialized images for different test configurations.
# Example: docker build --build-arg FEATURES="build-bins,consensus-poa,tree-file" ...
RUN cargo build --release --package depin-sdk-node --features "$FEATURES"

# Stage 2: Create the final, smaller image
FROM debian:bullseye-slim

# Copy all the binaries from the builder stage
COPY --from=builder /usr/src/depin-sdk/target/release/orchestration /usr/local/bin/orchestration
COPY --from=builder /usr/src/depin-sdk/target/release/workload /usr/local/bin/workload
COPY --from=builder /usr/src/depin-sdk/target/release/guardian /usr/local/bin/guardian

# Remove the default ENTRYPOINT. The specific binary to run will be
# provided as the command when starting the container (e.g., CMD ["orchestration", ...]).