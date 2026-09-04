#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE_ROOT="${ROOT_DIR}/internal-docs/architecture/protocols/aft/evidence/m16q-runs"
ALLOW_DIRTY=0
QUICK=0
OUTPUT_DIR=""

usage() {
  echo "usage: $0 [--quick] [--allow-dirty] [--output DIR]" >&2
}

while (($#)); do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    --output)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    *) usage; exit 2 ;;
  esac
done

cd "${ROOT_DIR}"
COMMIT="$(git rev-parse HEAD)"
TREE_STATUS="$(git status --porcelain=v1)"
if [[ -n "${TREE_STATUS}" && "${ALLOW_DIRTY}" -ne 1 ]]; then
  echo "M16Q qualification requires a clean worktree; use --allow-dirty only for development." >&2
  exit 1
fi
if [[ -z "${OUTPUT_DIR}" ]]; then
  RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  OUTPUT_DIR="${EVIDENCE_ROOT}/${RUN_STAMP}-${COMMIT:0:12}"
fi
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
SUMMARY="${OUTPUT_DIR}/phase-results.tsv"
printf 'phase\tresult\telapsed_seconds\tcommand\n' >"${SUMMARY}"

record_metadata() {
  {
    echo "schema=ioi.aft.m16q.qualification-run.v1"
    echo "commit=${COMMIT}"
    echo "tree_dirty=$([[ -n "${TREE_STATUS}" ]] && echo true || echo false)"
    echo "quick=$([[ "${QUICK}" -eq 1 ]] && echo true || echo false)"
    echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "uname=$(uname -a)"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "python=$(python3 --version 2>&1)"
    echo "node=$(node --version 2>/dev/null || echo unavailable)"
    echo "npm=$(npm --version 2>/dev/null || echo unavailable)"
    echo "cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
  } >"${OUTPUT_DIR}/environment.txt"
  git status --porcelain=v1 >"${OUTPUT_DIR}/worktree-status.txt"
  git show --no-patch --format=fuller "${COMMIT}" >"${OUTPUT_DIR}/commit.txt"
  sha256sum \
    .github/scripts/run_aft_m16q_qualification.sh \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_model_r4.py \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_results_r4.json \
    internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md \
    internal-docs/architecture/protocols/aft/specs/query_unanimity_theorems.md \
    internal-docs/architecture/protocols/aft/specs/query_unanimity_end_to_end_theorems.md \
    crates/consensus/src/aft/query_unanimity.rs \
    crates/validator/src/standard/orchestration/quv.rs \
    crates/networking/src/libp2p/pq_channel.rs \
    crates/networking/src/libp2p/swarm.rs \
    crates/agentgres/src/consequence.rs \
    crates/cli/tests/aft_e2e.rs >"${OUTPUT_DIR}/source-sha256.txt"
}

run_phase() {
  local phase="$1"
  shift
  local started ended elapsed rendered status
  rendered="$(printf '%q ' "$@")"
  started="$(date +%s)"
  echo "[M16Q] START ${phase}: ${rendered}" | tee "${OUTPUT_DIR}/${phase}.command.txt"
  set +e
  "$@" > >(tee "${OUTPUT_DIR}/${phase}.log") 2>&1
  status=$?
  set -e
  ended="$(date +%s)"
  elapsed=$((ended - started))
  if [[ ${status} -eq 0 ]]; then
    printf '%s\tPASS\t%s\t%s\n' "${phase}" "${elapsed}" "${rendered}" >>"${SUMMARY}"
    echo "[M16Q] PASS ${phase} (${elapsed}s)"
  else
    printf '%s\tFAIL(%s)\t%s\t%s\n' "${phase}" "${status}" "${elapsed}" "${rendered}" >>"${SUMMARY}"
    echo "[M16Q] FAIL ${phase} status=${status} (${elapsed}s)" >&2
    return "${status}"
  fi
}

require_tests_ran() {
  local phase="$1"
  local log="${OUTPUT_DIR}/${phase}.log"
  if ! grep -Eq 'running [1-9][0-9]* tests?' "${log}"; then
    printf '%s\tFAIL(no-tests-selected)\t0\tqualification harness assertion\n' "${phase}" >>"${SUMMARY}"
    echo "[M16Q] FAIL ${phase}: cargo selected zero tests" >&2
    return 1
  fi
}

record_metadata

run_phase formal_r4 bash .github/scripts/run_aft_formal_checks.sh --quv-only
run_phase quv_core cargo test -p ioi-consensus --features aft --lib aft::query_unanimity::tests
require_tests_ran quv_core
run_phase pq_transport cargo test -p ioi-networking --lib pq_channel
require_tests_ran pq_transport
run_phase pq_swarm_admission cargo test -p ioi-networking --lib protected_payload_routes_only_after_aead_and_type_agreement
require_tests_ran pq_swarm_admission
run_phase consequence_t10 cargo test -p agentgres consequence::tests
require_tests_ran consequence_t10
run_phase terminal_seal_sim cargo test -p ioi-consensus --features aft --lib adversarial_campaigns
require_tests_ran terminal_seal_sim
run_phase terminal_seal_receipts cargo test -p ioi-finality --features portable-assurance --lib portable_assurance::tests
require_tests_ran terminal_seal_receipts
run_phase quv_component_timing cargo test --release -p ioi-consensus --features aft --lib m16q_profiles_mldsa_signing_and_durable_write_before_reply -- --ignored --nocapture
require_tests_ran quv_component_timing

if [[ "${QUICK}" -ne 1 ]]; then
  run_phase quv_single_correct_process \
    cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation -- --nocapture
  require_tests_ran quv_single_correct_process
  run_phase quv_disjoint_reconfiguration \
    cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_disjoint_successors_install_live_handoff_before_activation -- --nocapture
  require_tests_ran quv_disjoint_reconfiguration
  run_phase quv_overlap_reconfiguration \
    cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff -- --nocapture
  require_tests_ran quv_overlap_reconfiguration
  run_phase pq_hash_async_process \
    cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
  require_tests_ran pq_hash_async_process
  run_phase pq_ordering_restart \
    cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_pq_four_validator_timeout_quorum_and_restart -- --nocapture
  require_tests_ran pq_ordering_restart
  run_phase hypervisor_web npm run build --workspace=@ioi/hypervisor-app
  run_phase hypervisor_daemon cargo build --locked -p ioi-node --bin hypervisor-daemon
fi

{
  echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit=${COMMIT}"
  echo "result=PASS"
} >"${OUTPUT_DIR}/result.txt"
find "${OUTPUT_DIR}" -maxdepth 1 -type f ! -name artifact-sha256.txt -print0 \
  | sort -z \
  | xargs -0 sha256sum >"${OUTPUT_DIR}/artifact-sha256.txt"
echo "M16Q qualification PASS: ${OUTPUT_DIR}"
