#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

TEST_FILTER="${IOI_AFT_BENCH_TEST_FILTER:-benchmark_throughput::aft::test_aft_base_final_benchmark_matrix}"

latest_benchmark_exe=""
latest_benchmark_mtime=0

shopt -s nullglob
for candidate in target/release/deps/benchmark_throughput-*; do
  if [[ ! -x "${candidate}" || "${candidate}" == *.d ]]; then
    continue
  fi
  candidate_mtime="$(stat -c '%Y' "${candidate}")"
  if (( candidate_mtime > latest_benchmark_mtime )); then
    latest_benchmark_exe="${candidate}"
    latest_benchmark_mtime="${candidate_mtime}"
  fi
done
shopt -u nullglob

if [[ -z "${latest_benchmark_exe}" ]]; then
  echo "missing release benchmark executable under target/release/deps/benchmark_throughput-*; build it first with:" >&2
  echo "  cargo test -p ioi-cli --test benchmark_throughput --release --no-run" >&2
  exit 1
fi

node_binaries=(
  target/release/orchestration
  target/release/workload
  target/release/guardian
)

stale_nodes=()
for node_binary in "${node_binaries[@]}"; do
  if [[ ! -x "${node_binary}" ]]; then
    echo "missing release node binary: ${node_binary}" >&2
    echo "build them first with:" >&2
    echo "  cargo build -p ioi-node --no-default-features --features validator-bins,consensus-aft,state-jellyfish,commitment-hash,vm-wasm --release" >&2
    exit 1
  fi

  node_mtime="$(stat -c '%Y' "${node_binary}")"
  if (( node_mtime < latest_benchmark_mtime )); then
    stale_nodes+=("${node_binary}")
  fi
done

if (( ${#stale_nodes[@]} > 0 )); then
  echo "refusing to run with stale release node binaries." >&2
  echo "benchmark executable: ${latest_benchmark_exe}" >&2
  stat -c '  %y %n' "${latest_benchmark_exe}" >&2
  for stale_node in "${stale_nodes[@]}"; do
    stat -c '  %y %n' "${stale_node}" >&2
  done
  echo "refresh the node binaries first with:" >&2
  echo "  cargo build -p ioi-node --no-default-features --features validator-bins,consensus-aft,state-jellyfish,commitment-hash,vm-wasm --release" >&2
  exit 2
fi

echo "using benchmark executable: ${latest_benchmark_exe}"
for node_binary in "${node_binaries[@]}"; do
  stat -c '  %y %n' "${node_binary}"
done

export IOI_TEST_BUILD_PROFILE="${IOI_TEST_BUILD_PROFILE:-release}"
export IOI_AFT_BENCH_SKIP_ARTIFACT_BUILD="${IOI_AFT_BENCH_SKIP_ARTIFACT_BUILD:-1}"
export IOI_AFT_BENCH_REBUILD_NODE="${IOI_AFT_BENCH_REBUILD_NODE:-0}"

exec "${latest_benchmark_exe}" "${TEST_FILTER}" --ignored --exact --nocapture "$@"
