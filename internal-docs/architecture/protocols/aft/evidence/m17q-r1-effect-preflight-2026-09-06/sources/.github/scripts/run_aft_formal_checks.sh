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
  "consequence/QuvEffectPreparationProof.tla"
  "consequence/QuvManifestLocatorProof.tla"
  "consequence/ConsequenceTraceLifetimeProof.tla"
  "consequence/QuvInstallContinuationProof.tla"
  "outbox/QuvByteReserveProof.tla"
  "outbox/PqOutboxIndexCommitProof.tla"
  "outbox/PqReservedIndexProof.tla"
  "outbox/QuvPayloadArenaCapacityProof.tla"
  "resource_profile/QuvLifetimeBudgetProof.tla"
  "resource_profile/QuvRecordReservationProof.tla"
  "resource_profile/QuvAnchoredReservationProof.tla"
  "resource_profile/QuvConflictSummaryProof.tla"
  "maximal_visibility/QuvReadinessBoundProof.tla"
  "consequence/ReconciliationBudgetProof.tla"
  "guardian_majority/GuardianMajorityProof.tla"
  "nested_guardian/NestedGuardianProof.tla"
  "AsymptoteProof.tla"
  "canonical_ordering/CanonicalOrderingProof.tla"
  "common_boundary/BoundaryRingProof.tla"
  "common_boundary/CustodyObligationProof.tla"
  "common_boundary/MembershipTransitionProof.tla"
  "common_boundary/ForensicAccountabilityProof.tla"
  "common_boundary/SuccessionClockProof.tla"
  "maximal_visibility/QueryUnanimityProof.tla"
  "maximal_visibility/QueryUnanimityCompositionProof.tla"
)

# Every TLC model the harness checks, as "cfg|tla", relative to FORMAL_DIR.
MODELS=(
  "consequence/QuvEffectPreparation.cfg|consequence/QuvEffectPreparation.tla"
  "consequence/QuvManifestLocator.cfg|consequence/QuvManifestLocator.tla"
  "consequence/ConsequenceTraceLifetime.cfg|consequence/ConsequenceTraceLifetime.tla"
  "consequence/QuvInstallContinuation.cfg|consequence/QuvInstallContinuation.tla"
  "outbox/QuvByteReserve.cfg|outbox/QuvByteReserve.tla"
  "outbox/PqOutboxIndexCommit.cfg|outbox/PqOutboxIndexCommit.tla"
  "outbox/PqReservedIndex.cfg|outbox/PqReservedIndex.tla"
  "resource_profile/QuvRecordReservation.cfg|resource_profile/QuvRecordReservation.tla"
  "resource_profile/QuvAnchoredReservation.cfg|resource_profile/QuvAnchoredReservation.tla"
  "outbox/QuvPayloadArena.cfg|outbox/QuvPayloadArena.tla"
  "resource_profile/QuvLifetimeBudget.cfg|resource_profile/QuvLifetimeBudget.tla"
  "concurrency/QuvAdmissionOrderOne.cfg|concurrency/QuvAdmissionOrder.tla"
  "concurrency/QuvAdmissionOrderTwo.cfg|concurrency/QuvAdmissionOrder.tla"
  "concurrency/PostCommitLockOrderReleased.cfg|concurrency/PostCommitLockOrder.tla"
  "maximal_visibility/QuvReadinessBound.cfg|maximal_visibility/QuvReadinessBound.tla"
  "maximal_visibility/QuvReadinessCompositionImmediatePreparation.cfg|maximal_visibility/QuvReadinessComposition.tla"
  "maximal_visibility/QuvReadinessCompositionEqual.cfg|maximal_visibility/QuvReadinessComposition.tla"
  "maximal_visibility/QuvHeadPreparationTimingWait.cfg|maximal_visibility/QuvHeadPreparationTiming.tla"
  "maximal_visibility/QuvHeadTriggeredPreparationOwned.cfg|maximal_visibility/QuvHeadTriggeredPreparation.tla"
  "maximal_visibility/QuvHeadTriggeredPreparationUnowned.cfg|maximal_visibility/QuvHeadTriggeredPreparation.tla"
  "maximal_visibility/QuvHeadProgressOwned.cfg|maximal_visibility/QuvHeadProgress.tla"
  "maximal_visibility/QuvHeadProgressUnowned.cfg|maximal_visibility/QuvHeadProgress.tla"
  "maximal_visibility/QuvHeadInterleavingUnowned.cfg|maximal_visibility/QuvHeadInterleaving.tla"
  "maximal_visibility/QuvHeadInterleavingUnownedSolo.cfg|maximal_visibility/QuvHeadInterleaving.tla"
  "maximal_visibility/QuvHeadInterleaving.cfg|maximal_visibility/QuvHeadInterleaving.tla"
  "maximal_visibility/QuvHeadInterleavingTwoSlot.cfg|maximal_visibility/QuvHeadInterleaving.tla"
  "maximal_visibility/QuvHeadPreparation.cfg|maximal_visibility/QuvHeadPreparation.tla"
  "maximal_visibility/QuvHeadPreparationSolo.cfg|maximal_visibility/QuvHeadPreparation.tla"
  "maximal_visibility/OwnedParentReverification.cfg|maximal_visibility/OwnedParentReverification.tla"
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
  "common_boundary/SuccessionSchedule.cfg|common_boundary/SuccessionSchedule.tla"
  "hash_async/OptimisticFallbackComposition.cfg|hash_async/OptimisticFallbackComposition.tla"
  "no_laundering/GuaranteeMeet.cfg|no_laundering/GuaranteeMeet.tla"
  "consequence/AtMostOnceExternalization.cfg|consequence/AtMostOnceExternalization.tla"
  "consequence/ReconciliationBudget.cfg|consequence/ReconciliationBudget.tla"
  "economic_assurance/DistinctCollateralFloor.cfg|economic_assurance/DistinctCollateralFloor.tla"
  "cross_domain/CrossDomainNonInterference.cfg|cross_domain/CrossDomainNonInterference.tla"
  "maximal_visibility/MaximalVisibilityDilemma2.cfg|maximal_visibility/MaximalVisibilityDilemma.tla"
  "maximal_visibility/MaximalVisibilityDilemma3.cfg|maximal_visibility/MaximalVisibilityDilemma.tla"
  "maximal_visibility/ConflictQualifiedLiveness.cfg|maximal_visibility/ConflictQualifiedLiveness.tla"
)

# Negative-property and reachability probes that MUST produce the named counterexample. A surprising
# pass means the lower-bound witness no longer exercises its claimed failure.
COUNTERMODELS=(
  "consequence/QuvEffectPreparationBinding.cfg|consequence/QuvEffectPreparation.tla|Invariant PreparationChecked is violated"
  "consequence/QuvEffectPreparationPreflight.cfg|consequence/QuvEffectPreparation.tla|Invariant PreparationChecked is violated"
  "consequence/QuvEffectPreparationBearer.cfg|consequence/QuvEffectPreparation.tla|Invariant GrantIsOwn is violated"
  "consequence/QuvManifestLocatorOverwrite.cfg|consequence/QuvManifestLocator.tla|Invariant IndexCorrect is violated"
  "consequence/QuvManifestLocatorEarlyRecovery.cfg|consequence/QuvManifestLocator.tla|Invariant ReadyComplete is violated"
  "consequence/ConsequenceTraceLifetimeReuse.cfg|consequence/ConsequenceTraceLifetime.tla|Invariant TraceBound is violated"
  "consequence/QuvInstallContinuationNoFence.cfg|consequence/QuvInstallContinuation.tla|Invariant LiveAtClaim is violated"
  "consequence/QuvInstallContinuationRehydrate.cfg|consequence/QuvInstallContinuation.tla|Invariant ProcessLocal is violated"
  "outbox/QuvByteReserveShared.cfg|outbox/QuvByteReserve.tla|Invariant EmptyLaneHasCapacity is violated"
  "outbox/PqOutboxEarlyDelete.cfg|outbox/PqOutboxIndexCommit.tla|Invariant RecoverableIndex is violated"
  "outbox/PqReservedIndexEarly.cfg|outbox/PqReservedIndex.tla|Invariant ActiveRecoverable is violated"
  "resource_profile/QuvRecordReservationTruncate.cfg|resource_profile/QuvRecordReservation.tla|Invariant CapacityRetained is violated"
  "resource_profile/QuvAnchoredReservationEarlyAnchor.cfg|resource_profile/QuvAnchoredReservation.tla|Invariant AnchorBacked is violated"
  "resource_profile/QuvAnchoredReservationEarlyReply.cfg|resource_profile/QuvAnchoredReservation.tla|Invariant ReplyBacked is violated"
  "resource_profile/QuvRecordReservationForget.cfg|resource_profile/QuvRecordReservation.tla|Invariant AcknowledgedRetained is violated"
  "outbox/QuvPayloadArenaSmall.cfg|outbox/QuvPayloadArena.tla|Invariant StagingHasCapacity is violated"
  "outbox/QuvPayloadArenaOverwrite.cfg|outbox/QuvPayloadArena.tla|Invariant OldIndexPreserved is violated"
  "outbox/PqReservedIndexTruncate.cfg|outbox/PqReservedIndex.tla|Invariant CapacityRetained is violated"
  "outbox/PqOutboxEarlyPublish.cfg|outbox/PqOutboxIndexCommit.tla|Invariant RecoverableIndex is violated"
  "resource_profile/QuvLifetimeBudgetReuse.cfg|resource_profile/QuvLifetimeBudget.tla|Invariant ChargedRecordBytes is violated"
  "concurrency/QuvAdmissionOrderNoFifo.cfg|concurrency/QuvAdmissionOrder.tla|Invariant BoundedPredecessors is violated"
  "concurrency/PostCommitLockOrderRetained.cfg|concurrency/PostCommitLockOrder.tla|Invariant NoCircularWait is violated"
  "maximal_visibility/QuvReadinessBoundNoQueueBudget.cfg|maximal_visibility/QuvReadinessBound.tla|Invariant ReadyForNext is violated"
  "maximal_visibility/QuvReadinessCompositionUnequal.cfg|maximal_visibility/QuvReadinessComposition.tla|Invariant EveryIntroducedChildAdmissible is violated"
  "maximal_visibility/QuvReadinessCompositionReachable.cfg|maximal_visibility/QuvReadinessComposition.tla|Invariant NoCompletedSequence is violated"
  "maximal_visibility/QuvHeadPreparationTimingNoWait.cfg|maximal_visibility/QuvHeadPreparationTiming.tla|Invariant CompleteCorrectProcessing is violated"
  "maximal_visibility/QuvHeadPreparationTimingReachable.cfg|maximal_visibility/QuvHeadPreparationTiming.tla|Invariant NoCompletedChild is violated"
  "maximal_visibility/QuvHeadTriggeredPreparationDisabled.cfg|maximal_visibility/QuvHeadTriggeredPreparation.tla|Temporal property AllTriggeredHistoriesAdvance was violated"
  "maximal_visibility/QuvHeadProgressDiscardGrant.cfg|maximal_visibility/QuvHeadProgress.tla|Temporal property AllHistoriesAdvance was violated"
  "maximal_visibility/QuvHeadInterleavingUnownedReachable.cfg|maximal_visibility/QuvHeadInterleaving.tla|Invariant NoCompletedConfiguredHistory is violated"
  "maximal_visibility/QuvHeadInterleavingReachable.cfg|maximal_visibility/QuvHeadInterleaving.tla|Invariant NoCompletedConfiguredHistory is violated"
  "maximal_visibility/QuvHeadPreparationReachable.cfg|maximal_visibility/QuvHeadPreparation.tla|Invariant NoCompletedTwoSlotHistory is violated"
  "maximal_visibility/OwnedParentReverificationPersistence.cfg|maximal_visibility/OwnedParentReverification.tla|Invariant PriorAcceptancePersists is violated"
  "consequence/ReconciliationBudgetVolatile.cfg|consequence/ReconciliationBudgetVolatile.tla|Invariant ReservedBeforeLookup is violated"
  "maximal_visibility/RoleSwitchConflict.cfg|maximal_visibility/RoleSwitchConflict.tla|Invariant ExternalNonConflict is violated"
  "maximal_visibility/ExternalSelectorMutation.cfg|maximal_visibility/ExternalSelectorMutation.tla|Invariant ParticipantOnlyVerifier is violated"
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
  local p m c rest
  for p in "${PROOFS[@]}"; do executed+=("${p}"); done
  for m in "${MODELS[@]}"; do executed+=("${m##*|}"); done
  for c in "${COUNTERMODELS[@]}"; do
    rest="${c#*|}"
    executed+=("${rest%%|*}")
  done

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

run_quv_model() {
  local workdir model expected generated

  workdir="$(mktemp -d)"
  model="${ROOT_DIR}/${FORMAL_DIR}/maximal_visibility/quv_timed_model_r4.py"
  expected="${ROOT_DIR}/${FORMAL_DIR}/maximal_visibility/quv_timed_results_r4.json"
  pushd "${workdir}" >/dev/null
  python3 "${model}" | tee quv_timed_run_r4.txt
  generated="${workdir}/quv_timed_results_r4.json"
  python3 - "${expected}" "${generated}" <<'PY'
import json
import sys

expected_path, generated_path = sys.argv[1:]
with open(expected_path, encoding="utf-8") as source:
    expected = json.load(source)
with open(generated_path, encoding="utf-8") as source:
    generated = json.load(source)
if expected != generated:
    print("QUV R4 FAIL: generated JSON differs from committed expectation", file=sys.stderr)
    sys.exit(1)
print("QUV R4 OK: generated JSON matches committed expectation")
PY
  popd >/dev/null
  rm -rf "${workdir}"
}

if [[ "${1:-}" == "--quv-only" ]]; then
  run_quv_model
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
  local link_path original_link="" had_link=0 status

  pushd "${ROOT_DIR}/${model_dir}" >/dev/null
  link_path="${PWD}/TLAPS.tla"
  if [[ -L "${link_path}" ]]; then
    had_link=1
    original_link="$(readlink "${link_path}")"
  elif [[ -e "${link_path}" ]]; then
    echo "refusing to replace non-symlink ${link_path}" >&2
    popd >/dev/null
    return 1
  fi
  ln -sfn "${TLAPS_STDLIB}" "${link_path}"
  set +e
  "${TLAPM_BIN}" --cleanfp "${tla_file}"
  status=$?
  set -e
  if [[ ${had_link} -eq 1 ]]; then
    ln -sfn "${original_link}" "${link_path}"
  else
    unlink "${link_path}"
  fi
  popd >/dev/null
  return "${status}"
}

run_model() {
  local model_dir="$1"
  local config_file="$2"
  local tla_file="$3"
  local link_path original_link="" had_link=0 status

  pushd "${ROOT_DIR}/${model_dir}" >/dev/null
  link_path="${PWD}/TLAPS.tla"
  if [[ -L "${link_path}" ]]; then
    had_link=1
    original_link="$(readlink "${link_path}")"
  elif [[ -e "${link_path}" ]]; then
    echo "refusing to replace non-symlink ${link_path}" >&2
    popd >/dev/null
    return 1
  fi
  ln -sfn "${TLAPS_STDLIB}" "${link_path}"
  set +e
  java -cp "${JAR_PATH}" tlc2.TLC -cleanup -deadlock -config "${config_file}" "${tla_file}"
  status=$?
  set -e
  if [[ ${had_link} -eq 1 ]]; then
    ln -sfn "${original_link}" "${link_path}"
  else
    unlink "${link_path}"
  fi
  popd >/dev/null
  return "${status}"
}

run_countermodel() {
  local model_dir="$1"
  local config_file="$2"
  local tla_file="$3"
  local expected="$4"
  local output status workdir

  workdir="$(mktemp -d)"
  cp "${ROOT_DIR}/${model_dir}/${config_file}" "${workdir}/"
  cp "${ROOT_DIR}/${model_dir}/${tla_file}" "${workdir}/"
  # This transition model extends the checked frontier model. Keep its local
  # dependency explicit; do not resolve imports from an unrelated checkout.
  if [[ "${tla_file}" == "QuvHeadInterleaving.tla" ]]; then
    cp "${ROOT_DIR}/${model_dir}/QuvHeadPreparation.tla" "${workdir}/"
  fi
  if [[ "${tla_file}" == "QuvHeadProgress.tla" || "${tla_file}" == "QuvHeadTriggeredPreparation.tla" ]]; then
    cp "${ROOT_DIR}/${model_dir}/QuvHeadPreparation.tla" "${workdir}/"
    cp "${ROOT_DIR}/${model_dir}/QuvHeadInterleaving.tla" "${workdir}/"
  fi
  pushd "${workdir}" >/dev/null
  set +e
  output="$(java -cp "${JAR_PATH}" tlc2.TLC -cleanup -deadlock \
    -config "${config_file}" "${tla_file}" 2>&1)"
  status=$?
  set -e
  popd >/dev/null
  rm -rf "${workdir}"
  if [[ ${status} -eq 0 ]]; then
    printf '%s\n' "${output}" >&2
    echo "countermodel unexpectedly passed: ${tla_file}" >&2
    return 1
  fi
  if ! grep -Fq "${expected}" <<<"${output}"; then
    printf '%s\n' "${output}" >&2
    echo "countermodel failed without expected witness: ${expected}" >&2
    return 1
  fi
  printf '%s\n' "${output}"
  echo "expected counterexample observed: ${tla_file}: ${expected}"
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

if [[ "${1:-}" == "--quv-byte-reserve-only" ]]; then
  run_proof "${FORMAL_DIR}/outbox" "QuvByteReserveProof.tla"
  run_model "${FORMAL_DIR}/outbox" "QuvByteReserve.cfg" "QuvByteReserve.tla"
  run_countermodel "${FORMAL_DIR}/outbox" "QuvByteReserveShared.cfg" "QuvByteReserve.tla" "Invariant EmptyLaneHasCapacity is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-effect-preparation-only" ]]; then
  run_proof "${FORMAL_DIR}/consequence" "QuvEffectPreparationProof.tla"
  run_model "${FORMAL_DIR}/consequence" "QuvEffectPreparation.cfg" "QuvEffectPreparation.tla"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvEffectPreparationBinding.cfg" "QuvEffectPreparation.tla" "Invariant PreparationChecked is violated"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvEffectPreparationPreflight.cfg" "QuvEffectPreparation.tla" "Invariant PreparationChecked is violated"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvEffectPreparationBearer.cfg" "QuvEffectPreparation.tla" "Invariant GrantIsOwn is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-manifest-locator-only" ]]; then
  run_proof "${FORMAL_DIR}/consequence" "QuvManifestLocatorProof.tla"
  run_model "${FORMAL_DIR}/consequence" "QuvManifestLocator.cfg" "QuvManifestLocator.tla"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvManifestLocatorOverwrite.cfg" "QuvManifestLocator.tla" "Invariant IndexCorrect is violated"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvManifestLocatorEarlyRecovery.cfg" "QuvManifestLocator.tla" "Invariant ReadyComplete is violated"
  exit 0
fi

if [[ "${1:-}" == "--consequence-trace-lifetime-only" ]]; then
  run_proof "${FORMAL_DIR}/consequence" "ConsequenceTraceLifetimeProof.tla"
  run_model "${FORMAL_DIR}/consequence" "ConsequenceTraceLifetime.cfg" "ConsequenceTraceLifetime.tla"
  run_countermodel "${FORMAL_DIR}/consequence" "ConsequenceTraceLifetimeReuse.cfg" "ConsequenceTraceLifetime.tla" "Invariant TraceBound is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-install-continuation-only" ]]; then
  run_proof "${FORMAL_DIR}/consequence" "QuvInstallContinuationProof.tla"
  run_model "${FORMAL_DIR}/consequence" "QuvInstallContinuation.cfg" "QuvInstallContinuation.tla"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvInstallContinuationNoFence.cfg" "QuvInstallContinuation.tla" "Invariant LiveAtClaim is violated"
  run_countermodel "${FORMAL_DIR}/consequence" "QuvInstallContinuationRehydrate.cfg" "QuvInstallContinuation.tla" "Invariant ProcessLocal is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-anchor-reservation-only" ]]; then
  run_proof "${FORMAL_DIR}/resource_profile" "QuvAnchoredReservationProof.tla"
  run_model "${FORMAL_DIR}/resource_profile" "QuvAnchoredReservation.cfg" "QuvAnchoredReservation.tla"
  run_countermodel "${FORMAL_DIR}/resource_profile" "QuvAnchoredReservationEarlyAnchor.cfg" "QuvAnchoredReservation.tla" "Invariant AnchorBacked is violated"
  run_countermodel "${FORMAL_DIR}/resource_profile" "QuvAnchoredReservationEarlyReply.cfg" "QuvAnchoredReservation.tla" "Invariant ReplyBacked is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-record-reservation-only" ]]; then
  run_proof "${FORMAL_DIR}/resource_profile" "QuvRecordReservationProof.tla"
  run_model "${FORMAL_DIR}/resource_profile" "QuvRecordReservation.cfg" "QuvRecordReservation.tla"
  run_countermodel "${FORMAL_DIR}/resource_profile" "QuvRecordReservationTruncate.cfg" "QuvRecordReservation.tla" "Invariant CapacityRetained is violated"
  run_countermodel "${FORMAL_DIR}/resource_profile" "QuvRecordReservationForget.cfg" "QuvRecordReservation.tla" "Invariant AcknowledgedRetained is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-payload-arena-only" ]]; then
  run_proof "${FORMAL_DIR}/outbox" "QuvPayloadArenaCapacityProof.tla"
  run_model "${FORMAL_DIR}/outbox" "QuvPayloadArena.cfg" "QuvPayloadArena.tla"
  run_countermodel "${FORMAL_DIR}/outbox" "QuvPayloadArenaSmall.cfg" "QuvPayloadArena.tla" "Invariant StagingHasCapacity is violated"
  run_countermodel "${FORMAL_DIR}/outbox" "QuvPayloadArenaOverwrite.cfg" "QuvPayloadArena.tla" "Invariant OldIndexPreserved is violated"
  exit 0
fi

if [[ "${1:-}" == "--pq-reserved-index-only" ]]; then
  run_proof "${FORMAL_DIR}/outbox" "PqReservedIndexProof.tla"
  run_model "${FORMAL_DIR}/outbox" "PqReservedIndex.cfg" "PqReservedIndex.tla"
  run_countermodel "${FORMAL_DIR}/outbox" "PqReservedIndexEarly.cfg" "PqReservedIndex.tla" "Invariant ActiveRecoverable is violated"
  run_countermodel "${FORMAL_DIR}/outbox" "PqReservedIndexTruncate.cfg" "PqReservedIndex.tla" "Invariant CapacityRetained is violated"
  exit 0
fi

if [[ "${1:-}" == "--pq-outbox-index-only" ]]; then
  run_proof "${FORMAL_DIR}/outbox" "PqOutboxIndexCommitProof.tla"
  run_model "${FORMAL_DIR}/outbox" "PqOutboxIndexCommit.cfg" "PqOutboxIndexCommit.tla"
  run_countermodel "${FORMAL_DIR}/outbox" "PqOutboxEarlyDelete.cfg" "PqOutboxIndexCommit.tla" "Invariant RecoverableIndex is violated"
  run_countermodel "${FORMAL_DIR}/outbox" "PqOutboxEarlyPublish.cfg" "PqOutboxIndexCommit.tla" "Invariant RecoverableIndex is violated"
  exit 0
fi

if [[ "${1:-}" == "--smoke" ]]; then
  run_proof "${FORMAL_DIR}" "AsymptoteProof.tla"
  run_model "${FORMAL_DIR}" "Asymptote.cfg" "Asymptote.tla"
  exit 0
fi

if [[ "${1:-}" == "--quv-admission-order-only" ]]; then
  run_model "${FORMAL_DIR}/concurrency" "QuvAdmissionOrderOne.cfg" "QuvAdmissionOrder.tla"
  run_model "${FORMAL_DIR}/concurrency" "QuvAdmissionOrderTwo.cfg" "QuvAdmissionOrder.tla"
  run_countermodel "${FORMAL_DIR}/concurrency" "QuvAdmissionOrderNoFifo.cfg" "QuvAdmissionOrder.tla" "Invariant BoundedPredecessors is violated"
  exit 0
fi

if [[ "${1:-}" == "--post-commit-lock-order-only" ]]; then
  run_model "${FORMAL_DIR}/concurrency" "PostCommitLockOrderReleased.cfg" "PostCommitLockOrder.tla"
  run_countermodel "${FORMAL_DIR}/concurrency" "PostCommitLockOrderRetained.cfg" "PostCommitLockOrder.tla" "Invariant NoCircularWait is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-lifetime-budget-only" ]]; then
  run_proof "${FORMAL_DIR}/resource_profile" "QuvLifetimeBudgetProof.tla"
  run_model "${FORMAL_DIR}/resource_profile" "QuvLifetimeBudget.cfg" "QuvLifetimeBudget.tla"
  run_countermodel "${FORMAL_DIR}/resource_profile" "QuvLifetimeBudgetReuse.cfg" "QuvLifetimeBudget.tla" "Invariant ChargedRecordBytes is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-conflict-summary-only" ]]; then
  run_proof "${FORMAL_DIR}/resource_profile" "QuvConflictSummaryProof.tla"
  exit 0
fi

if [[ "${1:-}" == "--quv-readiness-bound-only" ]]; then
  run_proof "${FORMAL_DIR}/maximal_visibility" "QuvReadinessBoundProof.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" "QuvReadinessBound.cfg" "QuvReadinessBound.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" "QuvReadinessBoundNoQueueBudget.cfg" "QuvReadinessBound.tla" "Invariant ReadyForNext is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-readiness-composition-only" || "${1:-}" == "--quv-parent-boundary-only" ]]; then
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvReadinessCompositionEqual.cfg" "QuvReadinessComposition.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvReadinessCompositionImmediatePreparation.cfg" "QuvReadinessComposition.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvReadinessCompositionUnequal.cfg" "QuvReadinessComposition.tla" \
    "Invariant EveryIntroducedChildAdmissible is violated"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvReadinessCompositionReachable.cfg" "QuvReadinessComposition.tla" \
    "Invariant NoCompletedSequence is violated"
  if [[ "${1:-}" == "--quv-readiness-composition-only" ]]; then
    exit 0
  fi
fi

if [[ "${1:-}" == "--quv-preparation-timing-only" || "${1:-}" == "--quv-parent-boundary-only" ]]; then
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadPreparationTimingWait.cfg" "QuvHeadPreparationTiming.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadPreparationTimingNoWait.cfg" "QuvHeadPreparationTiming.tla" \
    "Invariant CompleteCorrectProcessing is violated"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadPreparationTimingReachable.cfg" "QuvHeadPreparationTiming.tla" \
    "Invariant NoCompletedChild is violated"
  if [[ "${1:-}" == "--quv-preparation-timing-only" ]]; then
    exit 0
  fi
fi

if [[ "${1:-}" == "--quv-triggered-preparation-only" || "${1:-}" == "--quv-parent-boundary-only" ]]; then
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadTriggeredPreparationOwned.cfg" "QuvHeadTriggeredPreparation.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadTriggeredPreparationUnowned.cfg" "QuvHeadTriggeredPreparation.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadTriggeredPreparationDisabled.cfg" "QuvHeadTriggeredPreparation.tla" \
    "Temporal property AllTriggeredHistoriesAdvance was violated"
  if [[ "${1:-}" == "--quv-triggered-preparation-only" ]]; then
    exit 0
  fi
fi

if [[ "${1:-}" == "--quv-parent-boundary-only" ]]; then
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadProgressOwned.cfg" "QuvHeadProgress.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadProgressUnowned.cfg" "QuvHeadProgress.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadProgressDiscardGrant.cfg" "QuvHeadProgress.tla" \
    "Temporal property AllHistoriesAdvance was violated"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadInterleavingUnowned.cfg" "QuvHeadInterleaving.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadInterleavingUnownedSolo.cfg" "QuvHeadInterleaving.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadInterleavingUnownedReachable.cfg" "QuvHeadInterleaving.tla" \
    "Invariant NoCompletedConfiguredHistory is violated"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadInterleaving.cfg" "QuvHeadInterleaving.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadInterleavingTwoSlot.cfg" "QuvHeadInterleaving.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadInterleavingReachable.cfg" "QuvHeadInterleaving.tla" \
    "Invariant NoCompletedConfiguredHistory is violated"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadPreparation.cfg" "QuvHeadPreparation.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadPreparationSolo.cfg" "QuvHeadPreparation.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "QuvHeadPreparationReachable.cfg" "QuvHeadPreparation.tla" \
    "Invariant NoCompletedTwoSlotHistory is violated"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "OwnedParentReverification.cfg" "OwnedParentReverification.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "OwnedParentReverificationPersistence.cfg" "OwnedParentReverification.tla" \
    "Invariant PriorAcceptancePersists is violated"
  exit 0
fi

if [[ "${1:-}" == "--quv-theorem-only" ]]; then
  run_proof "${FORMAL_DIR}/maximal_visibility" "QueryUnanimityProof.tla"
  run_proof "${FORMAL_DIR}/maximal_visibility" "QueryUnanimityCompositionProof.tla"
  exit 0
fi

if [[ "${1:-}" == "--consequence-t10-only" ]]; then
  run_model "${FORMAL_DIR}/consequence" \
    "AtMostOnceExternalization.cfg" "AtMostOnceExternalization.tla"
  run_model "${FORMAL_DIR}/consequence" \
    "ReconciliationBudget.cfg" "ReconciliationBudget.tla"
  run_proof "${FORMAL_DIR}/consequence" "ReconciliationBudgetProof.tla"
  run_countermodel "${FORMAL_DIR}/consequence" \
    "ReconciliationBudgetVolatile.cfg" "ReconciliationBudgetVolatile.tla" \
    "Invariant ReservedBeforeLookup is violated"
  exit 0
fi

if [[ "${1:-}" == "--maximal-visibility-only" ]]; then
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "MaximalVisibilityDilemma2.cfg" "MaximalVisibilityDilemma.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "MaximalVisibilityDilemma3.cfg" "MaximalVisibilityDilemma.tla"
  run_model "${FORMAL_DIR}/maximal_visibility" \
    "ConflictQualifiedLiveness.cfg" "ConflictQualifiedLiveness.tla"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "RoleSwitchConflict.cfg" "RoleSwitchConflict.tla" \
    "Invariant ExternalNonConflict is violated"
  run_countermodel "${FORMAL_DIR}/maximal_visibility" \
    "ExternalSelectorMutation.cfg" "ExternalSelectorMutation.tla" \
    "Invariant ParticipantOnlyVerifier is violated"
  exit 0
fi

for proof in "${PROOFS[@]}"; do
  run_proof "${FORMAL_DIR}/$(dirname "${proof}")" "$(basename "${proof}")"
done

for model in "${MODELS[@]}"; do
  cfg="${model%%|*}"
  tla="${model##*|}"
  run_model "${FORMAL_DIR}/$(dirname "${tla}")" "$(basename "${cfg}")" "$(basename "${tla}")"
done

for countermodel in "${COUNTERMODELS[@]}"; do
  cfg="${countermodel%%|*}"
  rest="${countermodel#*|}"
  tla="${rest%%|*}"
  expected="${rest##*|}"
  run_countermodel "${FORMAL_DIR}/$(dirname "${tla}")" \
    "$(basename "${cfg}")" "$(basename "${tla}")" "${expected}"
done

for trace in "${TRACES[@]}"; do
  rest="${trace#*|}"
  run_trace "${trace%%|*}" "${rest%%|*}" "${rest##*|}"
done

run_quv_model
