# crates/node/Dockerfile

# Stage 1: Build the binary
# FIX: Use the 'slim' variant of the Rust image to match the final runtime environment.
FROM rust:1.78-slim-bullseye as builder

WORKDIR /usr/src/depin-sdk

# FIX: The slim image needs the protobuf compiler to be installed manually.
RUN apt-get update && apt-get install -y protobuf-compiler

COPY . .

# Build the node with the `build-bins` feature, which enables the CLI and all necessary components.
RUN cargo build --release --package depin-sdk-node --features build-bins

# Stage 2: Create the final, smaller image
FROM debian:bullseye-slim

# Copy the binary from the builder stage
COPY --from=builder /usr/src/depin-sdk/target/release/depin-sdk-node /usr/local/bin/depin-sdk-node

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/depin-sdk-node"]