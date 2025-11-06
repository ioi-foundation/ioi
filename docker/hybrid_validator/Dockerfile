FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/ioi-validator-hybrid /usr/local/bin/

# Copy configuration files
COPY docker/hybrid_validator/config/* /app/config/

ENTRYPOINT ["ioi-validator-hybrid"]
