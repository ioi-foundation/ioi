#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FORMAL_DIR="internal-docs/architecture/protocols/aft/formal"
MANIFEST_PATH="${ROOT_DIR}/${FORMAL_DIR}/manual-discharge.json"
FORMAL_CACHE_DIR="${ROOT_DIR}/.internal/formal-cache"
JAR_PATH="${FORMAL_CACHE_DIR}/tools/tla/tla2tools.jar"
JAR_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
TLAPS_DIR="${FORMAL_CACHE_DIR}/tools/tlaps-pre"
TLAPS_INSTALL_DIR="${TLAPS_DIR}/install"
TLAPS_ARCHIVE="${TLAPS_DIR}/tlapm.tar.gz"
TLAPM_BIN="${TLAPS_INSTALL_DIR}/bin/tlapm"
TLAPS_STDLIB="${TLAPS_INSTALL_DIR}/lib/tlapm/stdlib/TLAPS.tla"

# Every TLAPS proof the harness discharges, relative to FORMAL_DIR.
PROOFS=(
  "guardian_majority/GuardianMajorityProof.tla"
  "nested_guardian/NestedGuardianProof.tla"
  "AsymptoteProof.tla"
  "canonical_ordering/CanonicalOrderingProof.tla"
  "common_boundary/BoundaryRingProof.tla"
  "common_boundary/CustodyObligationProof.tla"
  "common_boundary/MembershipTransitionProof.tla"
  "common_boundary/ForensicAccountabilityProof.tla"
  "common_boundary/SuccessionClockProof.tla"
)

# Every TLC model the harness checks, as "cfg|tla", relative to FORMAL_DIR.
MODELS=(
  "guardian_majority/GuardianMajority.cfg|guardian_majority/GuardianMajority.tla"
  "nested_guardian/NestedGuardian.cfg|nested_guardian/NestedGuardian.tla"
  "Asymptote.cfg|Asymptote.tla"
  "canonical_ordering/CanonicalOrdering.cfg|canonical_ordering/CanonicalOrdering.tla"
  "canonical_ordering/CanonicalOrderingRetrievability.cfg|canonical_ordering/CanonicalOrderingRetrievability.tla"
  "canonical_ordering/CanonicalCollapseRecursiveContinuity.cfg|canonical_ordering/CanonicalCollapseRecursiveContinuity.tla"
  "common_boundary/BoundaryRing.cfg|common_boundary/BoundaryRing.tla"
  "common_boundary/BoundaryRing4.cfg|common_boundary/BoundaryRing.tla"
  "common_boundary/CustodyObligation.cfg|common_boundary/CustodyObligation.tla"
  "common_boundary/BoundaryLiveness.cfg|common_boundary/BoundaryLiveness.tla"
  "common_boundary/BoundaryLivenessHandover.cfg|common_boundary/BoundaryLiveness.tla"
  "common_boundary/MembershipTransition.cfg|common_boundary/MembershipTransition.tla"
  "common_boundary/ForensicAccountability.cfg|common_boundary/ForensicAccountability.tla"
  "common_boundary/ForensicAccountabilityAllByz.cfg|common_boundary/ForensicAccountability.tla"
  "common_boundary/SuccessionClock.cfg|common_boundary/SuccessionClock.tla"
)

# Every trace-conformance replay (AFT-CB R13 / C4a), as
# "trace|base-module|generated-module-name", relative to FORMAL_DIR.
# The committed trace is emitted by the Rust reference driver
# (crates/consensus/src/aft/boundary_ring_trace.rs) and byte-pinned by
# the cargo test boundary_ring_reference_trace_matches_committed_golden;
# this harness replays it against the TLA kernel, closing
# code <-> committed trace <-> model.
TRACES=(
  "common_boundary/traces/boundary_ring_reference.trace.jsonl|common_boundary/BoundaryRing.tla|BoundaryRingTraceReference"
)

# Census: every .tla module under FORMAL_DIR (excluding symlinks and
# .tlacache) must be either executed by this harness or carried in
# manual-discharge.json with a reason. An unlisted module fails the build:
# the formal corpus admits no silent orphans.
census() {
  local executed=()
  local p m
  for p in "${PROOFS[@]}"; do executed+=("${p}"); done
  for m in "${MODELS[@]}"; do executed+=("${m##*|}"); done

  EXECUTED_MODULES="$(printf '%s\n' "${executed[@]}")" \
  FORMAL_DIR_ABS="${ROOT_DIR}/${FORMAL_DIR}" \
  MANIFEST_PATH="${MANIFEST_PATH}" \
  python3 <<'PY'
import json
import os
import sys

formal = os.environ["FORMAL_DIR_ABS"]
executed = set(filter(None, os.environ["EXECUTED_MODULES"].split("\n")))
manifest_path = os.environ["MANIFEST_PATH"]

discovered = set()
for root, dirs, files in os.walk(formal):
    dirs[:] = [d for d in dirs if d != ".tlacache"]
    for name in files:
        if not name.endswith(".tla"):
            continue
        full = os.path.join(root, name)
        if os.path.islink(full):
            continue
        discovered.add(os.path.relpath(full, formal))

errors = []

for module in sorted(executed):
    if module not in discovered:
        errors.append(f"executed module missing on disk: {module}")

try:
    with open(manifest_path) as fh:
        manifest = json.load(fh)
except FileNotFoundError:
    errors.append(f"manual-discharge manifest missing: {manifest_path}")
    manifest = {"modules": []}
except json.JSONDecodeError as exc:
    print(f"CENSUS FAIL: manifest is not valid JSON: {exc}", file=sys.stderr)
    sys.exit(1)

required_fields = ("module", "reason", "last_discharged", "discharged_by")
manual = set()
for entry in manifest.get("modules", []):
    missing = [k for k in required_fields if not str(entry.get(k, "")).strip()]
    if missing:
        errors.append(
            f"manifest entry {entry.get('module', '<unnamed>')} missing fields: {missing}"
        )
        continue
    module = entry["module"]
    if module in manual:
        errors.append(f"manifest lists module twice: {module}")
    manual.add(module)
    if module not in discovered:
        errors.append(f"manifest lists module not on disk: {module}")
    if module in executed:
        errors.append(f"manifest lists module the harness already executes: {module}")

for module in sorted(discovered - executed - manual):
    errors.append(f"module neither executed by the harness nor manifest-marked: {module}")

if errors:
    print("CENSUS FAIL:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)

print(
    f"census OK: {len(discovered)} modules = "
    f"{len(executed)} executed + {len(manual)} manifest-marked (manual)"
)
PY
}

census

if [[ "${1:-}" == "--census-only" ]]; then
  exit 0
fi

platform() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}:${arch}" in
    Linux:x86_64)
      echo "x86_64-linux-gnu"
      ;;
    Darwin:arm64)
      echo "arm64-darwin"
      ;;
    *)
      echo "unsupported:${os}:${arch}"
      return 1
      ;;
  esac
}

TLAPS_PLATFORM="$(platform)"
TLAPS_URL="https://github.com/tlaplus/tlapm/releases/download/1.6.0-pre/tlapm-1.6.0-pre-${TLAPS_PLATFORM}.tar.gz"

mkdir -p "$(dirname "${JAR_PATH}")"
mkdir -p "${TLAPS_DIR}"

if [[ ! -f "${JAR_PATH}" ]]; then
  curl -L --fail --retry 3 -o "${JAR_PATH}" "${JAR_URL}"
fi

if [[ ! -x "${TLAPM_BIN}" ]]; then
  rm -rf "${TLAPS_INSTALL_DIR}"
  mkdir -p "${TLAPS_INSTALL_DIR}"
  if [[ ! -f "${TLAPS_ARCHIVE}" ]]; then
    curl -L --fail --retry 3 -o "${TLAPS_ARCHIVE}" "${TLAPS_URL}"
  fi
  tar -xzf "${TLAPS_ARCHIVE}" -C "${TLAPS_INSTALL_DIR}" --strip-components=1
fi

run_proof() {
  local model_dir="$1"
  local tla_file="$2"

  pushd "${ROOT_DIR}/${model_dir}" >/dev/null
  ln -sf "${TLAPS_STDLIB}" TLAPS.tla
  "${TLAPM_BIN}" --cleanfp "${tla_file}"
  popd >/dev/null
}

run_model() {
  local model_dir="$1"
  local config_file="$2"
  local tla_file="$3"

  pushd "${ROOT_DIR}/${model_dir}" >/dev/null
  ln -sf "${TLAPS_STDLIB}" TLAPS.tla
  java -cp "${JAR_PATH}" tlc2.TLC -cleanup -deadlock -config "${config_file}" "${tla_file}"
  popd >/dev/null
}

run_trace() {
  local trace_rel="$1"
  local base_rel="$2"
  local module="$3"
  local workdir

  workdir="$(mktemp -d)"
  python3 "${ROOT_DIR}/.github/scripts/gen_aft_trace_module.py" \
    "${ROOT_DIR}/${FORMAL_DIR}/${trace_rel}" "${module}" "${workdir}"
  cp "${ROOT_DIR}/${FORMAL_DIR}/${base_rel}" "${workdir}/"
  pushd "${workdir}" >/dev/null
  # Deadlock checking stays ON here (NO -deadlock flag, unlike run_model):
  # a mid-trace disabled action — a step the code took that the model
  # refuses — deadlocks, and that deadlock IS the divergence signal the
  # trace-conformance lane exists for.  The generated terminal state
  # self-loops, so a fully-replayed trace never deadlocks.
  java -cp "${JAR_PATH}" tlc2.TLC -cleanup -config "${module}.cfg" "${module}.tla"
  popd >/dev/null
  rm -rf "${workdir}"
}

for proof in "${PROOFS[@]}"; do
  run_proof "${FORMAL_DIR}/$(dirname "${proof}")" "$(basename "${proof}")"
done

for model in "${MODELS[@]}"; do
  cfg="${model%%|*}"
  tla="${model##*|}"
  run_model "${FORMAL_DIR}/$(dirname "${tla}")" "$(basename "${cfg}")" "$(basename "${tla}")"
done

for trace in "${TRACES[@]}"; do
  rest="${trace#*|}"
  run_trace "${trace%%|*}" "${rest%%|*}" "${rest##*|}"
done
