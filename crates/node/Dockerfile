# Path: crates/node/Dockerfile

# Stage 1: Build the binary
FROM rust:1.78-slim-bullseye as builder

WORKDIR /usr/src/depin-sdk
RUN apt-get update && apt-get install -y protobuf-compiler build-essential

COPY . .

# Build the node package, which now produces multiple binaries
RUN cargo build --release --package depin-sdk-node --features build-bins

# Stage 2: Create the final, smaller image
FROM debian:bullseye-slim

# Copy all the binaries from the builder stage
COPY --from=builder /usr/src/depin-sdk/target/release/orchestration /usr/local/bin/orchestration
COPY --from=builder /usr/src/depin-sdk/target/release/workload /usr/local/bin/workload
COPY --from=builder /usr/src/depin-sdk/target/release/guardian /usr/local/bin/guardian

# Remove the default ENTRYPOINT. The specific binary to run will be
# provided as the command when starting the container (e.g., CMD ["orchestration", ...]).