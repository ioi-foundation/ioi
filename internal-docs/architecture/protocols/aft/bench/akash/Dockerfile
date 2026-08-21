# AFT paper-benchmark runner image (RES-P4.3, Stage 1: Akash console deploy).
#
# Builds the ioi workspace at a pinned commit and runs the AFT paper-benchmark
# matrix. Output is a Markdown table on stdout (retrieve via `akash ... lease-logs`).
#
# PROPRIETARY: this image contains the full ioi source at the pinned commit.
# It MUST be pushed to a PRIVATE registry only, and the Akash SDL must pull it
# with `credentials` (see deploy.sdl). Never push to a public registry.
#
# Reproducibility: pin the toolchain (rust-toolchain.toml → 1.93.1) and the
# source commit. The host KERNEL is the Akash provider's, not ours — a
# documented caveat; this run is a NON-GATING reference until a reserved
# bare-metal / pinned runner exists (see README.md and the RES-P4.3 residual).

FROM rust:1.93.1-bookworm

# Native deps — mirrors the "Install native deps for kernel build" CI step.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        cmake \
        libdbus-1-dev \
        protobuf-compiler \
        libxcb1-dev \
        libxdo-dev \
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
RUN cargo test --release --no-run \
        -p ioi-cli \
        --features consensus-aft,vm-wasm,state-jellyfish \
        -- test_aft_paper_benchmark_matrix

COPY internal-docs/architecture/protocols/aft/bench/akash/run-bench.sh /usr/local/bin/run-bench.sh
COPY internal-docs/architecture/protocols/aft/bench/akash/result-tools.py /usr/local/bin/aft-result-tools.py
RUN chmod +x /usr/local/bin/run-bench.sh /usr/local/bin/aft-result-tools.py

# Repetition + warmup knobs (override in the SDL env).
ENV AFT_BENCH_WARMUPS=1 \
    AFT_BENCH_REPEATS=5 \
    IOI_AFT_BENCH_SCENARIO= \
    IOI_TEST_BUILD_PROFILE=release

ENTRYPOINT ["/usr/local/bin/run-bench.sh"]
