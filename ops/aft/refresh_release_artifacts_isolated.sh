#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

BUILD_PROFILE="${IOI_TEST_BUILD_PROFILE:-release}"
STATE_TREE="${IOI_AFT_BENCH_STATE_TREE:-Jellyfish}"
REFRESH_JOBS="${IOI_AFT_REFRESH_JOBS:-4}"
REFRESH_ONLY="${IOI_AFT_REFRESH_ONLY:-all}"
DRY_RUN="${IOI_AFT_REFRESH_DRY_RUN:-0}"

case "${STATE_TREE}" in
  IAVL)
    state_feature="state-iavl"
    ;;
  Jellyfish)
    state_feature="state-jellyfish"
    ;;
  *)
    echo "unsupported IOI_AFT_BENCH_STATE_TREE: ${STATE_TREE}" >&2
    exit 1
    ;;
esac

case "${REFRESH_ONLY}" in
  all|benchmark|node)
    ;;
  *)
    echo "unsupported IOI_AFT_REFRESH_ONLY: ${REFRESH_ONLY} (expected all|benchmark|node)" >&2
    exit 1
    ;;
esac

timestamp="$(date +%s)"
bench_unit="${IOI_AFT_REFRESH_BENCH_UNIT_NAME:-ioi-aft-refresh-bench-${timestamp}}"
node_unit="${IOI_AFT_REFRESH_NODE_UNIT_NAME:-ioi-aft-refresh-node-${timestamp}}"
bench_log="${IOI_AFT_REFRESH_BENCH_LOG:-/tmp/${bench_unit}.log}"
node_log="${IOI_AFT_REFRESH_NODE_LOG:-/tmp/${node_unit}.log}"

if command -v ionice >/dev/null 2>&1; then
  throttle_prefix=(ionice -c3 nice -n 15)
else
  throttle_prefix=(nice -n 15)
fi

printf -v throttle_shell '%q ' "${throttle_prefix[@]}"
printf -v workspace_shell '%q' "${ROOT_DIR}"
printf -v bench_log_shell '%q' "${bench_log}"
printf -v node_log_shell '%q' "${node_log}"
printf -v jobs_shell '%q' "${REFRESH_JOBS}"
printf -v build_profile_shell '%q' "${BUILD_PROFILE}"
printf -v state_feature_shell '%q' "${state_feature}"

bench_cmd="cd ${workspace_shell} && export CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=${jobs_shell} IOI_TEST_BUILD_PROFILE=${build_profile_shell}; ${throttle_shell}cargo test -p ioi-cli --test benchmark_throughput --release --no-run > ${bench_log_shell} 2>&1"
node_cmd="cd ${workspace_shell} && export CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=${jobs_shell} IOI_TEST_BUILD_PROFILE=${build_profile_shell}; ${throttle_shell}cargo build -p ioi-node --no-default-features --features validator-bins,consensus-aft,${state_feature_shell},commitment-hash,vm-wasm --release > ${node_log_shell} 2>&1 && touch target/${build_profile_shell}/orchestration target/${build_profile_shell}/workload target/${build_profile_shell}/guardian"

echo "build_profile: ${BUILD_PROFILE}"
echo "state_tree: ${STATE_TREE}"
echo "refresh_jobs: ${REFRESH_JOBS}"
echo "refresh_only: ${REFRESH_ONLY}"
echo "dry_run: ${DRY_RUN}"

if [[ "${REFRESH_ONLY}" == "all" || "${REFRESH_ONLY}" == "benchmark" ]]; then
  echo "bench_unit: ${bench_unit}"
  echo "bench_log: ${bench_log}"
  echo "bench_cmd: ${bench_cmd}"
fi

if [[ "${REFRESH_ONLY}" == "all" || "${REFRESH_ONLY}" == "node" ]]; then
  echo "node_unit: ${node_unit}"
  echo "node_log: ${node_log}"
  echo "node_cmd: ${node_cmd}"
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  exit 0
fi

run_unit() {
  local unit_name="$1"
  local command="$2"
  systemd-run \
    --user \
    --collect \
    --same-dir \
    --wait \
    --unit="${unit_name}" \
    bash -lc "${command}"
}

if [[ "${REFRESH_ONLY}" == "all" || "${REFRESH_ONLY}" == "benchmark" ]]; then
  run_unit "${bench_unit}" "${bench_cmd}"
fi

if [[ "${REFRESH_ONLY}" == "all" || "${REFRESH_ONLY}" == "node" ]]; then
  run_unit "${node_unit}" "${node_cmd}"
fi

echo "artifact refresh complete"
stat -c '%y %n' \
  "target/${BUILD_PROFILE}/deps/benchmark_throughput-"* \
  "target/${BUILD_PROFILE}/orchestration" \
  "target/${BUILD_PROFILE}/workload" \
  "target/${BUILD_PROFILE}/guardian"
