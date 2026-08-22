# AFT paper-benchmark runner image (RES-P4.3, Stage 1: Akash console deploy).
#
# Builds the ioi workspace at a pinned commit and runs the AFT paper-benchmark
# matrix. Canonical results are served through the authenticated result endpoint;
# managed Console control-plane logs are not a result channel.
#
# PROPRIETARY: this image contains the full ioi source at the pinned commit.
# It MUST be pushed to a PRIVATE registry only. The reviewed SDL contains a
# credential sentinel and connector reference; the daemon resolves the sealed
# registry credential only after the C2 intent commit and does not retain the
# expanded SDL. Never put registry plaintext in source, SDL, or artifacts, and
# never push this image to a public registry.
#
# Reproducibility: pin the toolchain (rust-toolchain.toml → 1.93.1) and the
# source commit. The host KERNEL is the Akash provider's, not ours — a
# documented caveat. An exact-provider campaign remains measured-container or
# variance-caveated unless tenant-specific placement evidence passes the
# provider-key-bound attestation verifier (see README.md).

FROM rust:1.93.1-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31

LABEL org.opencontainers.image.source="https://github.com/ioi-foundation/ioi"
LABEL org.opencontainers.image.description="Private IOI AFT RES-P4.3 benchmark runner"

# Native deps — mirrors the "Install native deps for kernel build" CI step.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        cmake \
        libdbus-1-dev \
        libprotobuf-dev \
        protobuf-compiler \
        libxcb1-dev \
        libxdo-dev \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ioi

# Build context MUST be a clean checkout of the pinned commit:
#   git archive <full-commit> | tar -x -C <empty-build-directory>
#   docker build --build-arg IOI_COMMIT=<full-commit> -f <this-file> -t <private-image> <empty-build-directory>
COPY . .

# Record the source commit into the image for the manifest (best-effort;
# overridable via --build-arg so an archive build without .git still stamps it).
ARG IOI_COMMIT
RUN test -n "${IOI_COMMIT}" && test "${IOI_COMMIT}" != "unknown"
ENV IOI_BENCH_COMMIT=${IOI_COMMIT}

# Pre-compile the benchmark test binary (release) at build time so the paid
# Akash lease pays for EXECUTION, not compilation.
RUN cargo test --locked --release --no-run \
        -p ioi-cli \
        --features consensus-aft,vm-wasm,state-jellyfish \
        --test benchmark_throughput

# The harness starts three node roles under two state-tree feature sets. Build
# those exact feature-keyed target directories after the test executable so a
# paid lease can execute immediately. Runtime rebuilding is disabled: a stale
# or absent binary must fail the campaign rather than consume provider time
# compiling software that was supposed to be immutable.
RUN CARGO_TARGET_DIR=/ioi/target/test-node-builds/release-0b7414797d7f2187 \
      cargo build --locked --release -p ioi-node --no-default-features \
        --features validator-bins,consensus-aft,state-iavl,commitment-hash,vm-wasm \
        --bin orchestration --bin workload --bin guardian \
    && CARGO_TARGET_DIR=/ioi/target/test-node-builds/release-6bdc4f43f691ae57 \
      cargo build --locked --release -p ioi-node --no-default-features \
        --features validator-bins,consensus-aft,state-jellyfish,commitment-hash,vm-wasm \
        --bin orchestration --bin workload --bin guardian

COPY internal-docs/architecture/protocols/aft/bench/akash/run-bench.sh /usr/local/bin/run-bench.sh
COPY internal-docs/architecture/protocols/aft/bench/akash/result-tools.py /usr/local/bin/aft-result-tools.py
RUN chmod +x /usr/local/bin/run-bench.sh /usr/local/bin/aft-result-tools.py

# Generate a unique workload-transport identity inside this immutable private
# image. The public certificate fingerprint is extracted by the build workflow
# and bound into the owner-reviewed challenge. The private key is not a user or
# provider credential; it only terminates the raw Akash TCP forwarding inside
# this exact image and is never emitted as an artifact.
RUN install -d -m 0700 /etc/ioi-aft-result \
    && openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
      -keyout /etc/ioi-aft-result/tls.key \
      -out /etc/ioi-aft-result/tls.crt \
      -subj '/CN=ioi-aft-result' \
      -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
      -addext 'subjectAltName=DNS:ioi-aft-result' \
    && chmod 0600 /etc/ioi-aft-result/tls.key \
    && chmod 0644 /etc/ioi-aft-result/tls.crt

# Repetition + warmup knobs (override in the SDL env).
ENV AFT_BENCH_WARMUPS=1 \
    AFT_BENCH_REPEATS=5 \
    AFT_BENCH_PROTOCOL_VERSION=res-p4.3.v2 \
    IOI_AFT_BENCH_SCENARIO= \
    IOI_TEST_BUILD_PROFILE=release \
    IOI_TEST_FORBID_NODE_BUILD=1 \
    IOI_AFT_BENCH_REBUILD_NODE=0

ENTRYPOINT ["/usr/local/bin/run-bench.sh"]
