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
    .github/scripts/run_aft_formal_checks.sh \
    .github/scripts/check_aft_quv_journal_sync.py \
    .github/scripts/check_aft_quv_record_reservation.py \
    .github/scripts/check_aft_quv_handoff_reservation.py \
    .github/scripts/check_aft_m16q_process_evidence.py \
    .github/scripts/check_aft_quv_handoff_evidence.py \
    .github/scripts/check_aft_quv_readiness_evidence.py \
    internal-docs/architecture/protocols/aft/formal/consequence/ReconciliationBudget.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/ReconciliationBudget.cfg \
    internal-docs/architecture/protocols/aft/formal/consequence/ReconciliationBudgetProof.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/ReconciliationBudgetVolatile.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/ReconciliationBudgetVolatile.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_model_r4.py \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/OwnedParentReverification.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparation.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessBound.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessBound.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessBoundNoQueueBudget.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessBoundProof.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessComposition.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessCompositionEqual.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessCompositionImmediatePreparation.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessCompositionUnequal.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvReadinessCompositionReachable.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparationTiming.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparationTimingWait.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparationTimingNoWait.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparationTimingReachable.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadTriggeredPreparation.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadTriggeredPreparationOwned.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadTriggeredPreparationUnowned.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadTriggeredPreparationDisabled.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadProgress.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadProgressOwned.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadProgressUnowned.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadProgressDiscardGrant.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleaving.tla \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleavingUnowned.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleavingUnownedSolo.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleavingUnownedReachable.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleaving.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleavingTwoSlot.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadInterleavingReachable.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparation.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparationSolo.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/QuvHeadPreparationReachable.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/OwnedParentReverification.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/OwnedParentReverificationPersistence.cfg \
    internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_results_r4.json \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvConflictSummaryProof.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvLifetimeBudget.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvLifetimeBudgetProof.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvLifetimeBudget.cfg \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvLifetimeBudgetReuse.cfg \
    internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md \
    internal-docs/architecture/protocols/aft/specs/query_unanimity_theorems.md \
    internal-docs/architecture/protocols/aft/specs/query_unanimity_end_to_end_theorems.md \
    crates/consensus/src/aft/query_unanimity.rs \
    crates/consensus/src/aft/query_unanimity/head.rs \
    crates/consensus/src/aft/query_unanimity/member_delta.rs \
    crates/consensus/src/aft/query_unanimity/member_delta_tests.rs \
    crates/consensus/src/aft/query_unanimity/journal.rs \
    crates/consensus/src/aft/query_unanimity/journal/member_store.rs \
    crates/consensus/src/aft/query_unanimity/journal/reservation.rs \
    crates/consensus/src/aft/query_unanimity/journal/anchor_reservation.rs \
    crates/consensus/src/aft/query_unanimity/handoff_reservation.rs \
    crates/consensus/src/aft/query_unanimity/journal/fixture.rs \
    crates/consensus/src/aft/query_unanimity/store_fixture_io.rs \
    crates/consensus/src/aft/query_unanimity/journal/tests.rs \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvRecordReservation.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvRecordReservationProof.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvRecordReservation.cfg \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvRecordReservationTruncate.cfg \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvRecordReservationForget.cfg \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvAnchoredReservation.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvAnchoredReservationProof.tla \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvAnchoredReservation.cfg \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvAnchoredReservationEarlyAnchor.cfg \
    internal-docs/architecture/protocols/aft/formal/resource_profile/QuvAnchoredReservationEarlyReply.cfg \
    internal-docs/architecture/protocols/aft/formal/consequence/QuvInstallContinuation.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/QuvInstallContinuationProof.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/QuvInstallContinuation.cfg \
    internal-docs/architecture/protocols/aft/formal/consequence/QuvInstallContinuationNoFence.cfg \
    internal-docs/architecture/protocols/aft/formal/consequence/QuvInstallContinuationRehydrate.cfg \
    crates/validator/src/standard/orchestration/quv.rs \
    crates/validator/src/standard/orchestration/quv/admission.rs \
    crates/validator/src/standard/orchestration/finalize/post_commit.rs \
    internal-docs/architecture/protocols/aft/formal/concurrency/QuvAdmissionOrder.tla \
    internal-docs/architecture/protocols/aft/formal/concurrency/QuvAdmissionOrderOne.cfg \
    internal-docs/architecture/protocols/aft/formal/concurrency/QuvAdmissionOrderTwo.cfg \
    internal-docs/architecture/protocols/aft/formal/concurrency/QuvAdmissionOrderNoFifo.cfg \
    internal-docs/architecture/protocols/aft/formal/concurrency/PostCommitLockOrder.tla \
    internal-docs/architecture/protocols/aft/formal/concurrency/PostCommitLockOrderReleased.cfg \
    internal-docs/architecture/protocols/aft/formal/concurrency/PostCommitLockOrderRetained.cfg \
    crates/validator/src/standard/orchestration/finalize/tests_parts/node_state_lock_order.rs \
    crates/validator/src/standard/orchestration/quv/dispatch.rs \
    crates/validator/src/standard/orchestration/quv/member_completion.rs \
    crates/validator/src/standard/orchestration/quv/event_dispatch.rs \
    crates/validator/src/standard/orchestration/context.rs \
    crates/validator/src/standard/orchestration/lifecycle.rs \
    crates/validator/src/standard/orchestration/consensus.rs \
    crates/networking/src/libp2p/pq_channel.rs \
    crates/networking/src/libp2p/pq_channel/outbox_decode.rs \
    crates/networking/src/libp2p/pq_channel/outbox_index.rs \
    crates/networking/src/libp2p/pq_channel/outbox_arena.rs \
    crates/networking/src/libp2p/pq_channel/outbox_reservation.rs \
    .github/scripts/check_aft_pq_outbox_ancestry.py \
    .github/scripts/check_aft_pq_outbox_reservation.py \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvByteReserve.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvByteReserveProof.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvByteReserve.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvByteReserveShared.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqOutboxIndexCommit.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/PqReservedIndex.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvPayloadArena.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvPayloadArenaCapacityProof.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvPayloadArena.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvPayloadArenaSmall.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/QuvPayloadArenaOverwrite.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqReservedIndexProof.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/PqReservedIndex.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqReservedIndexEarly.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqReservedIndexTruncate.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqOutboxIndexCommitProof.tla \
    internal-docs/architecture/protocols/aft/formal/outbox/PqOutboxIndexCommit.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqOutboxEarlyDelete.cfg \
    internal-docs/architecture/protocols/aft/formal/outbox/PqOutboxEarlyPublish.cfg \
    crates/crypto/src/transport/pq_authenticated_channel.rs \
    crates/networking/src/libp2p/swarm.rs \
    crates/agentgres/src/consequence.rs \
    crates/agentgres/src/consequence/tests.rs \
    internal-docs/architecture/protocols/aft/formal/consequence/ConsequenceTraceLifetime.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/ConsequenceTraceLifetimeProof.tla \
    internal-docs/architecture/protocols/aft/formal/consequence/ConsequenceTraceLifetime.cfg \
    internal-docs/architecture/protocols/aft/formal/consequence/ConsequenceTraceLifetimeReuse.cfg \
    crates/types/src/app/consequence.rs \
    crates/types/src/app/query_unanimity.rs \
    crates/types/src/config/mod.rs \
    crates/types/src/config/tests.rs \
    crates/services/src/aft_effect_registry.rs \
    crates/validator/src/standard/orchestration/grpc_public.rs \
    crates/cli/src/testing/backend.rs \
    crates/cli/src/testing/validator.rs \
    crates/cli/src/testing/rpc.rs \
    crates/cli/tests/aft_e2e_parts/quv_readiness.rs \
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

run_process_phase() {
  local phase="$1"
  shift
  local component_logs="${OUTPUT_DIR}/${phase}-components"
  mkdir -p "${component_logs}"
  run_phase "${phase}" env "IOI_AFT_BENCH_TRACE_DIR=${component_logs}" "$@"
  if grep -qF 'HARNESS_DIAGNOSTIC_WRITE_FAILURE' "${OUTPUT_DIR}/${phase}.log" \
    || [[ -z "$(find "${component_logs}" -type f -name '*-orch.log' -size +0c -print -quit)" ]]; then
    printf '%s\tFAIL(component-log-capture)\t0\tqualification harness assertion\n' "${phase}" >>"${SUMMARY}"
    echo "[M16Q] FAIL ${phase}: component logs were not retained" >&2
    return 1
  fi
}

record_metadata

run_phase readiness_evidence_checker python3 .github/scripts/check_aft_quv_readiness_evidence.py --self-test
run_phase process_evidence_checker python3 .github/scripts/check_aft_m16q_process_evidence.py --self-test
run_phase formal_r4 bash .github/scripts/run_aft_formal_checks.sh --quv-only
run_phase formal_quv_theorems bash .github/scripts/run_aft_formal_checks.sh --quv-theorem-only
run_phase formal_quv_readiness_bound bash .github/scripts/run_aft_formal_checks.sh --quv-readiness-bound-only
run_phase formal_quv_head_preparation bash .github/scripts/run_aft_formal_checks.sh --quv-parent-boundary-only
run_phase formal_consequence_t10 bash .github/scripts/run_aft_formal_checks.sh --consequence-t10-only
run_phase quv_core cargo test -p ioi-consensus --features aft --lib aft::query_unanimity::tests
require_tests_ran quv_core
# Provisioning and history regressions must run explicitly; another passing test is insufficient.
for required_case in handoff_reserved_capacity_precedes_live_consumption_and_reuses_inode handoff_recovery_rejects_authenticated_unreachable_generations handoff_final_continuation_deadline_edges_preserve_uninstalled_state rooted_slot_horizon_survives_reopen_and_keeps_historical_queries candidate_byte_cap_precedes_validation_and_store_mutation unconfigured_reply_identities_cannot_consume_verifier_capacity saturated_summary_replies_remain_valid_bounded_and_preserve_first_winner summary_validation_refuses_omitted_singleton_and_duplicate_conflict_entries readiness_observes_durable_head_and_reopen_without_retry_reset journal_format_refuses_authenticated_schema_six_without_migration policy_root_binds_operation_service_and_refuses_invalid_limits provisioning_root_commits_complete_scope_and_canonical_policy_set changed_provisioning_refuses_without_writing_even_during_pending_recovery accepted_history_derives_scope_and_preserves_historical_predecessors accepted_history_refuses_conflicting_or_expired_grants_without_mutation accepted_history_supports_unowned_grants_and_rejects_invalid_bootstrap accepted_history_terminal_slot_does_not_wrap_or_erase_history durable_history_requires_live_advance_and_retains_historical_queries recovery_requires_snapshot_for_every_accepted_history_entry durable_history_headroom_and_persistence_errors_preserve_recovery authenticated_advanced_history_covers_every_byte_in_pending_recovery preparation_selection_recovers_and_rotates_without_advancing_history preparation_selection_preserves_mode_rules_and_excludes_handoffs policy_root_binds_preparation_limits_and_rejects_invalid_budgets preparation_attempts_are_rooted_durable_and_retire_only_on_advance preparation_attempts_preflight_authenticate_and_recover_uncertain_write authorization_expiry_cap_never_extends_or_revives_a_grant; do
  if ! rg -q "^test aft::query_unanimity::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_core.log"; then
    echo "[M16Q] FAIL quv_core: missing passing core regression ${required_case}" >&2
    exit 1
  fi
done
# Shared production staging and journal replay must both execute their exact regressions.
for required_case in startup_reserves_complete_rooted_lifetime_before_creating_a_journal preparation_policy_is_rechecked_on_replay_and_exhaustion_survives_reopen rooted_preparation_format_refuses_schema_seven_without_mutation typed_journal_replay_matches_live_member_across_three_slots_and_reopens journal_member_commit_refusal_and_anchor_failure_do_not_publish_memory journal_member_cached_size_matches_compact_history_boundaries typed_replay_refuses_invalid_order_scope_and_counters_without_mutation typed_replay_refuses_owned_conflict_reservation_but_retains_both_candidates authenticated_pending_record_cannot_advance_anchor_if_typed_replay_refuses; do
  if ! rg -q "^test aft::query_unanimity::tests::journal_replay_tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_core.log"; then
    echo "[M16Q] FAIL quv_core: missing passing typed transition regression ${required_case}" >&2
    exit 1
  fi
done
run_phase quv_journal_component cargo test --locked -p ioi-consensus --features aft --lib aft::query_unanimity::journal::tests
require_tests_ran quv_journal_component
for required_case in reserved_anchor_boundaries_never_publish_memory_before_durability anchor_capacity_failure_precedes_continuation_and_record_mutation corrupt_active_anchor_cannot_fall_back_to_valid_reserved_copy overallocated_reserved_record_quarantines_before_continuation reserved_records_preserve_allocation_and_inode_through_complete_lifetime partial_or_unallocated_reserved_records_require_authenticated_restart reserved_record_anchor_failure_requires_semantic_replay_before_recovery corrupt_reservation_root_preserves_pending_bytes_and_anchor streaming_recovery_reauthenticates_records_and_preserves_pending_anchor streaming_recovery_refuses_missing_or_noncanonical_record_indices append_retains_prior_records_and_replays_in_order pending_record_requires_successful_semantic_replay_before_anchor_advance bootstrap_interruption_recovers_only_the_provisioned_initial_record capacity_refusal_preserves_disk_and_keeps_store_usable exclusive_open_and_complete_chain_validation_precede_replay recovery_cleans_only_unacknowledged_next_temporary_record total_byte_limit_is_checked_before_disk_mutation final_continuation_refusal_is_nonmutating_and_precedes_any_write capacity_admission_precedes_the_final_continuation_check interrupted_record_write_quarantines_until_authenticated_reopen interrupted_anchor_write_recovers_the_durable_pending_record semantic_refusal_preserves_partial_next_record_for_inspection; do
  if ! rg -q "^test aft::query_unanimity::journal::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_journal_component.log"; then
    echo "[M16Q] FAIL quv_journal_component: missing passing journal regression ${required_case}" >&2
    exit 1
  fi
done
for required_case in fixed_anchor_updates_reuse_both_inodes_and_keep_raw_authentication fixed_anchor_interruption_selects_only_the_active_name fixed_anchor_lost_spare_and_alias_refuse_before_writing; do
  if ! rg -q "^test aft::query_unanimity::journal::anchor_reservation::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_core.log"; then
    echo "[M16Q] FAIL quv_core: missing passing reserved anchor regression ${required_case}" >&2
    exit 1
  fi
done
run_phase quv_record_reservation python3 .github/scripts/check_aft_quv_record_reservation.py --output "${OUTPUT_DIR}/quv-record-reservation"
run_phase quv_handoff_reservation python3 .github/scripts/check_aft_quv_handoff_reservation.py --output "${OUTPUT_DIR}/quv-handoff-reservation"
run_phase quv_journal_sync_checker python3 .github/scripts/check_aft_quv_journal_sync.py --self-test
run_phase quv_journal_trace_tool strace --version
run_phase quv_journal_ancestry strace -f -yy -e trace=fsync,rename,openat,mkdir -o "${OUTPUT_DIR}/quv_journal_ancestry.strace" \
  cargo test --locked -p ioi-consensus --features aft --lib aft::query_unanimity::journal::tests::bootstrap_interruption_recovers_only_the_provisioned_initial_record -- --exact --nocapture
require_tests_ran quv_journal_ancestry
run_phase quv_journal_sync_evidence python3 .github/scripts/check_aft_quv_journal_sync.py --trace "${OUTPUT_DIR}/quv_journal_ancestry.strace" --result "${OUTPUT_DIR}/quv_journal_ancestry.log"
run_phase manifest_types cargo test --locked -p ioi-types --lib app::consequence::tests
run_phase quv_bootstrap_policy cargo test --locked -p ioi-types --lib quv_policy_requires_exact_authority_and_durable_roots
require_tests_ran quv_bootstrap_policy
run_phase formal_quv_admission_order bash .github/scripts/run_aft_formal_checks.sh --quv-admission-order-only
run_phase formal_post_commit_lock_order bash .github/scripts/run_aft_formal_checks.sh --post-commit-lock-order-only
run_phase post_commit_lock_order cargo test --locked -p ioi-validator --features consensus-aft --lib standard::orchestration::finalize::tests::finalization_releases_node_state_before_waiting_for_context -- --exact
require_tests_ran post_commit_lock_order
run_phase quv_consequence_wait_lock cargo test --locked -p ioi-validator --features consensus-aft --lib standard::orchestration::grpc_public::quv_refusal_status_tests::quv_wait_releases_consequence_lock_and_reopen_restores_exclusion -- --exact
require_tests_ran quv_consequence_wait_lock
run_phase quv_runtime_policy cargo test --locked -p ioi-validator --features consensus-aft --lib standard::orchestration::quv::
require_tests_ran quv_runtime_policy
for required_case in preparation_waiter_is_bounded_and_cancellation_preserves_fifo readiness_wait_keeps_domain_capacity_and_leaves_preparation_lane_free pending_removal_keeps_admission_until_dispatch_returns_or_is_canceled admission_release_is_observed_after_semaphore_release canceled_durable_waiter_retains_admission_until_work_finishes admission_serializes_and_preserves_queued_worker_order admission_cancellation_releases_domain_and_queue_capacity; do
  if ! rg -q "^test standard::orchestration::quv::admission::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_runtime_policy.log"; then
    echo "[M16Q] FAIL quv_runtime_policy: missing passing admission regression ${required_case}" >&2
    exit 1
  fi
done
for required_case in dispatch_requires_every_exact_member_before_decision canceled_dispatch_never_runs_the_live_decision dispatch_completion_obeys_before_equal_after_deadline; do
  if ! rg -q "^test standard::orchestration::quv::dispatch::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_runtime_policy.log"; then
    echo "[M16Q] FAIL quv_runtime_policy: missing passing dispatch regression ${required_case}" >&2
    exit 1
  fi
done
if ! rg -q '^test standard::orchestration::quv::tests::readiness_revalidation_rejects_before_and_accepts_equal_or_after \.\.\. ok$' "${OUTPUT_DIR}/quv_runtime_policy.log"; then
  echo '[M16Q] FAIL quv_runtime_policy: missing current-head readiness revalidation regression' >&2
  exit 1
fi
if ! rg -q '^test standard::orchestration::quv::tests::every_operation_role_has_a_rooted_active_service_budget \.\.\. ok$' "${OUTPUT_DIR}/quv_runtime_policy.log"; then
  echo "[M16Q] FAIL quv_runtime_policy: missing all-operation service regression" >&2
  exit 1
fi
if ! rg -q '^test standard::orchestration::quv::tests::active_service_completion_never_reports_late_success \.\.\. ok$' "${OUTPUT_DIR}/quv_runtime_policy.log"; then
  echo '[M16Q] FAIL quv_runtime_policy: missing active-service completion regression' >&2
  exit 1
fi
for required_case in captured_completion_notifies_and_forwards_exact_reply_under_backpressure refused_completion_notifies_without_reply_and_closed_lane_returns_error; do
  if ! rg -q "^test standard::orchestration::quv::member_completion::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/quv_runtime_policy.log"; then
    echo "[M16Q] FAIL quv_runtime_policy: missing member-completion regression ${required_case}" >&2
    exit 1
  fi
done
if ! rg -q '^test standard::orchestration::quv::tests::reply_handler_uses_captured_table_and_preserves_transport_binding \.\.\. ok$' "${OUTPUT_DIR}/quv_runtime_policy.log"; then
  echo '[M16Q] FAIL quv_runtime_policy: missing captured-table reply routing regression' >&2
  exit 1
fi
if ! rg -q '^test standard::orchestration::quv::event_dispatch::tests::blocked_push_admission_does_not_block_reply_or_hide_overflow \.\.\. ok$' "${OUTPUT_DIR}/quv_runtime_policy.log"; then
  echo '[M16Q] FAIL quv_runtime_policy: missing bounded admission/reply isolation regression' >&2
  exit 1
fi
if ! rg -q '^test standard::orchestration::quv::event_dispatch::tests::aborting_event_drain_cancels_blocked_admission_worker \.\.\. ok$' "${OUTPUT_DIR}/quv_runtime_policy.log"; then
  echo '[M16Q] FAIL quv_runtime_policy: missing forced-abort admission-worker regression' >&2
  exit 1
fi
run_phase quv_handoff_evidence_self_test python3 .github/scripts/check_aft_quv_handoff_evidence.py --self-test
require_tests_ran manifest_types
run_phase manifest_admission cargo test --locked -p ioi-services --lib aft_effect_registry
require_tests_ran manifest_admission
run_phase pq_online_record_limit cargo test --locked -p ioi-crypto --lib online_record_byte_limit_refuses_before_sequence_consumption
require_tests_ran pq_online_record_limit
run_phase pq_transport cargo test -p ioi-networking --lib pq_channel
require_tests_ran pq_transport
if ! rg -q '^test libp2p::pq_channel::tests::durable_outbox_enforces_record_plaintext_boundary_before_mutation \.\.\. ok$' "${OUTPUT_DIR}/pq_transport.log"; then
  echo '[M16Q] FAIL pq_transport: missing durable plaintext-boundary regression' >&2
  exit 1
fi
if ! rg -q '^test libp2p::pq_channel::tests::outbox_streaming_preserves_v2_bytes_and_returns_write_errors \.\.\. ok$' "${OUTPUT_DIR}/pq_transport.log"; then
  echo '[M16Q] FAIL pq_transport: missing streaming format/error regression' >&2
  exit 1
fi
for required_case in tests::normal_storage_capacity_refusal_preserves_live_quv_queue tests::quv_payload_arena_retains_both_lanes_across_atomic_replacement_and_restart tests::quv_payload_arena_refuses_corruption_without_retired_file_fallback tests::reserved_outbox_index_quarantines_exchange_before_directory_sync tests::reserved_outbox_index_reuses_allocated_inodes_across_commits tests::reserved_outbox_index_refuses_lost_capacity_and_recovers_incomplete_spare tests::reserved_outbox_index_rejects_aliases_and_corrupt_active_image tests::outbox_byte_budgets_preserve_quv_lanes_and_unrelated_recipients tests::bounded_quv_wire_shapes_fit_reserved_frame_budget tests::legacy_outbox_upgrade_recovers_interrupted_payload_staging tests::indexed_outbox_recovers_commit_boundaries_without_resurrecting_retirements tests::indexed_outbox_preserves_unrelated_payload_files_and_refuses_corrupt_recovery tests::rooted_outbox_scope_precedes_discovery_and_rejects_foreign_recovery tests::outbox_streaming_recovery_refuses_truncation_and_trailing_bytes outbox_decode::tests::entry_budget_rejects_declared_vector_before_reading_body; do
  if ! rg -q "^test libp2p::pq_channel::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/pq_transport.log"; then
    echo "[M16Q] FAIL pq_transport: missing strict recovery regression ${required_case}" >&2
    exit 1
  fi
done
run_phase pq_outbox_ancestry python3 .github/scripts/check_aft_pq_outbox_ancestry.py --output "${OUTPUT_DIR}/pq-outbox-ancestry"
run_phase pq_outbox_reservation python3 .github/scripts/check_aft_pq_outbox_reservation.py --output "${OUTPUT_DIR}/pq-outbox-reservation"
run_phase pq_swarm_admission cargo test -p ioi-networking --lib protected_payload_routes_only_after_aead_and_type_agreement
require_tests_ran pq_swarm_admission
run_phase consequence_t10 cargo test -p agentgres consequence::tests
require_tests_ran consequence_t10
for required_case in online_receipt_bound_covers_named_resource_execution_and_complete_budget receipt_hash_view_preserves_canonical_bytes_and_optional_fields receipt_trace_bound_refuses_extra_ambiguity_without_mutating_state pq_resource_format_bounds_cover_maximum_tokens_and_refuse_noncanonical_evidence; do
  if ! rg -q "^test consequence::tests::${required_case} \.\.\. ok$" "${OUTPUT_DIR}/consequence_t10.log"; then
    echo "[M16Q] FAIL consequence_t10: missing passing resource-bound regression ${required_case}" >&2
    exit 1
  fi
done
run_phase terminal_seal_sim cargo test -p ioi-consensus --features aft --lib adversarial_campaigns
require_tests_ran terminal_seal_sim
run_phase terminal_seal_receipts cargo test -p ioi-finality --features portable-assurance --lib portable_assurance::tests
require_tests_ran terminal_seal_receipts
run_phase quv_component_timing cargo test --release -p ioi-consensus --features aft --lib m16q_profiles_mldsa_signing_and_durable_write_before_reply -- --ignored --nocapture
require_tests_ran quv_component_timing

if [[ "${QUICK}" -ne 1 ]]; then
  run_phase diagnostic_retention cargo test --locked -p ioi-cli --lib --features consensus-aft,vm-wasm,state-iavl orchestration_restart_retains_diagnostics_and_refuses_unwritable_sink
  require_tests_ran diagnostic_retention
  run_phase quv_refusal_mapping cargo test --locked -p ioi-validator --features consensus-aft --lib conflict_status_preserves_type_and_never_classifies_message_text
  require_tests_ran quv_refusal_mapping
  run_phase quv_refusal_assertion cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl quv_conflict_assertion_requires_structured_refusal -- --exact
  require_tests_ran quv_refusal_assertion
  run_phase quv_expired_result_assertion cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl quv_expired_result_requires_strict_admitted_height_and_unchanged_receipt -- --exact
  require_tests_ran quv_expired_result_assertion
  run_phase readiness_recovery_probe cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl recovery_probe_retries_only_startup_and_requires_exact_result -- --exact
  require_tests_ran readiness_recovery_probe
  run_phase readiness_rpc_observation cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl readiness_wait_surfaces_early_rpc_error_without_diagnostic_timeout -- --exact
  require_tests_ran readiness_rpc_observation
  run_phase readiness_observation_assertion cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl readiness_observation_requires_positive_wait_and_exact_nonce -- --exact
  require_tests_ran readiness_observation_assertion
  run_process_phase quv_consecutive_readiness \
    env IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_consecutive_slots_wait_and_reopen_without_blocking_unrelated_effects -- --exact --nocapture
  require_tests_ran quv_consecutive_readiness
  run_phase quv_readiness_evidence python3 .github/scripts/check_aft_quv_readiness_evidence.py "${OUTPUT_DIR}/quv_consecutive_readiness.log" --components "${OUTPUT_DIR}/quv_consecutive_readiness-components"
  run_process_phase quv_single_correct_process \
    env IOI_TEST_ORCH_RUST_LOG=quv=debug,network=debug cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation -- --nocapture
  require_tests_ran quv_single_correct_process
  run_phase quv_process_evidence python3 .github/scripts/check_aft_m16q_process_evidence.py "${OUTPUT_DIR}/quv_single_correct_process.log" --components "${OUTPUT_DIR}/quv_single_correct_process-components"
  run_process_phase quv_disjoint_reconfiguration \
    env IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_disjoint_successors_install_live_handoff_before_activation -- --nocapture
  require_tests_ran quv_disjoint_reconfiguration
  run_phase quv_disjoint_evidence python3 .github/scripts/check_aft_quv_handoff_evidence.py "${OUTPUT_DIR}/quv_disjoint_reconfiguration.log" --components "${OUTPUT_DIR}/quv_disjoint_reconfiguration-components"
  run_process_phase quv_overlap_reconfiguration \
    env IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff -- --nocapture
  require_tests_ran quv_overlap_reconfiguration
  run_phase quv_overlap_evidence python3 .github/scripts/check_aft_quv_handoff_evidence.py "${OUTPUT_DIR}/quv_overlap_reconfiguration.log" --components "${OUTPUT_DIR}/quv_overlap_reconfiguration-components"
  run_process_phase pq_hash_async_process \
    cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
  require_tests_ran pq_hash_async_process
  run_process_phase pq_ordering_restart \
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
  echo "result_scope=selected_runner_gates"
  echo "quick=$([[ "${QUICK}" -eq 1 ]] && echo true || echo false)"
  echo "tree_dirty=$([[ -n "${TREE_STATUS}" ]] && echo true || echo false)"
  # R1's missing refinement/load/restart gates are not supplied by this runner
  # yet. A successful invocation must not promote itself to R2 admission.
  echo "r2_admission=NOT_ESTABLISHED"
} >"${OUTPUT_DIR}/result.txt"
find "${OUTPUT_DIR}" -type f ! -path "${OUTPUT_DIR}/artifact-sha256.txt" -print0 \
  | sort -z \
  | xargs -0 sha256sum >"${OUTPUT_DIR}/artifact-sha256.txt"
echo "M16Q selected runner gates PASS (R2 admission not established): ${OUTPUT_DIR}"
