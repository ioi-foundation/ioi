// Pure validators extracted from harness-workflow/core.ts: the activation-id
// gate click-proof blockers and the reviewed-package-import activation-apply
// proof blockers. Leaf module (depends only on graph types, harness constants,
// and string helpers) so core.ts and the activation/package-evidence facades
// can consume it without a cycle. Behavior is unchanged from the prior in-core
// definitions.
import type {
  WorkflowHarnessActivationIdGateClickProof,
  WorkflowHarnessPackageImportActivationApplyProof,
} from "../../types/graph";
import {
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_PROOF_MAX_AGE_MS,
} from "./constants";
import { uniqueStrings } from "./strings";

export function workflowHarnessActivationIdGateClickProofBlockers(
  proof: WorkflowHarnessActivationIdGateClickProof | null | undefined,
  options: {
    nowMs?: number;
    maxAgeMs?: number;
  } = {},
): string[] {
  const blockers: string[] = [];
  if (!proof) return ["activation_id_gate_click_proof_missing"];
  const maxAgeMs =
    options.maxAgeMs ??
    DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS;
  if (proof.passed !== true || proof.blockers.length > 0) {
    blockers.push("activation_id_gate_click_proof_failed");
  }
  if (
    typeof options.nowMs === "number" &&
    Number.isFinite(proof.generatedAtMs) &&
    (proof.generatedAtMs > options.nowMs + 1000 ||
      options.nowMs - proof.generatedAtMs > maxAgeMs)
  ) {
    blockers.push("activation_id_gate_click_proof_stale");
  }
  const blockedDryRun = proof.blockedDryRun;
  if (blockedDryRun.clicked !== true) {
    blockers.push("activation_id_gate_dry_run_not_clicked");
  }
  if (blockedDryRun.gateId !== "activation-id") {
    blockers.push("activation_id_gate_dry_run_gate_mismatch");
  }
  if (blockedDryRun.action.kind !== "run_activation_dry_run") {
    blockers.push("activation_id_gate_dry_run_kind_mismatch");
  }
  if (
    blockedDryRun.action.command !==
    "workflow-harness-gate-action-activation-id"
  ) {
    blockers.push("activation_id_gate_dry_run_command_mismatch");
  }
  if (blockedDryRun.decision !== "blocked") {
    blockers.push("activation_id_gate_dry_run_not_blocked");
  }
  if (blockedDryRun.activationBlockerCount <= 0) {
    blockers.push("activation_id_gate_dry_run_no_blockers");
  }
  if (blockedDryRun.workflowActivationId) {
    blockers.push("activation_id_gate_dry_run_minted_activation_id");
  }
  if (blockedDryRun.workflowActivationState !== "blocked") {
    blockers.push("activation_id_gate_dry_run_activation_state_mismatch");
  }
  if (blockedDryRun.latestAuditEventType !== "dry_run_blocked") {
    blockers.push("activation_id_gate_dry_run_audit_type_mismatch");
  }

  const minted = proof.mintedActivation;
  const activationId = minted.activationId;
  if (minted.clicked !== true)
    blockers.push("activation_id_gate_mint_not_clicked");
  if (minted.applied !== true)
    blockers.push("activation_id_gate_mint_not_applied");
  if (minted.gateId !== "activation-id") {
    blockers.push("activation_id_gate_mint_gate_mismatch");
  }
  if (minted.action.kind !== "mint_activation") {
    blockers.push("activation_id_gate_mint_kind_mismatch");
  }
  if (minted.action.command !== "workflow-harness-gate-action-activation-id") {
    blockers.push("activation_id_gate_mint_command_mismatch");
  }
  if (!activationId?.startsWith("activation:")) {
    blockers.push("activation_id_gate_mint_activation_id_missing");
  }
  if (minted.workflowActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_workflow_activation_mismatch");
  }
  if (minted.workflowActivationState !== "validated") {
    blockers.push("activation_id_gate_mint_activation_state_mismatch");
  }
  if (minted.workerBindingActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_worker_binding_mismatch");
  }
  if (minted.activationRecordWorkerBindingActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_activation_record_binding_mismatch");
  }
  if (minted.revisionBindingActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_revision_binding_mismatch");
  }
  if (minted.rollbackTarget !== DEFAULT_AGENT_HARNESS_ACTIVATION_ID) {
    blockers.push("activation_id_gate_mint_rollback_target_mismatch");
  }
  if (!minted.activationRecordRevisionBindingHash) {
    blockers.push("activation_id_gate_mint_revision_hash_missing");
  }
  if (!minted.rollbackRevisionBindingHash) {
    blockers.push("activation_id_gate_mint_rollback_hash_missing");
  }
  if (minted.latestAuditEventType !== "activation_minted") {
    blockers.push("activation_id_gate_mint_audit_type_mismatch");
  }
  if (minted.latestAuditStatus !== "applied") {
    blockers.push("activation_id_gate_mint_audit_status_mismatch");
  }
  if (minted.receiptRefs.length === 0) {
    blockers.push("activation_id_gate_mint_receipts_missing");
  }
  if (minted.evidenceRefs.length === 0) {
    blockers.push("activation_id_gate_mint_evidence_missing");
  }
  if ((minted.workerHandoffReceiptIds ?? []).length === 0) {
    blockers.push("activation_id_gate_mint_worker_handoff_receipts_missing");
  }
  if ((minted.workerHandoffNodeAttemptIds ?? []).length === 0) {
    blockers.push("activation_id_gate_mint_worker_handoff_attempts_missing");
  }
  if ((minted.workerHandoffReplayFixtureRefs ?? []).length === 0) {
    blockers.push("activation_id_gate_mint_worker_handoff_replay_missing");
  }
  const workerHandoffAttemptId =
    minted.workerHandoffNodeAttemptIds?.[0] ?? null;
  if (
    workerHandoffAttemptId &&
    minted.workerHandoffDeepLink?.includes("activationGateNodeAttemptId=") !==
      true
  ) {
    blockers.push("activation_id_gate_mint_handoff_node_link_missing");
  }
  if (
    workerHandoffAttemptId &&
    minted.workerHandoffDeepLinkState?.["data-selected-activation-gate-id"] !==
      "worker-handoff"
  ) {
    blockers.push("activation_id_gate_mint_handoff_gate_not_restored");
  }
  if (
    workerHandoffAttemptId &&
    minted.workerHandoffDeepLinkState?.[
      "data-selected-activation-gate-node-attempt-id"
    ] !== workerHandoffAttemptId
  ) {
    blockers.push("activation_id_gate_mint_handoff_attempt_not_selected");
  }
  if (
    workerHandoffAttemptId &&
    minted.workerHandoffDeepLinkState?.["data-selected-node-attempt-id"] !==
      workerHandoffAttemptId
  ) {
    blockers.push("activation_id_gate_mint_global_attempt_not_selected");
  }
  if (workerHandoffAttemptId && minted.workerHandoffTimelineVisible !== true) {
    blockers.push("activation_id_gate_mint_handoff_timeline_missing");
  }
  if (
    workerHandoffAttemptId &&
    minted.workerHandoffTimelineAttemptId !== workerHandoffAttemptId
  ) {
    blockers.push("activation_id_gate_mint_handoff_timeline_attempt_missing");
  }
  return uniqueStrings(blockers);
}

export function workflowHarnessPackageImportActivationApplyProofBlockers(
  proof: WorkflowHarnessPackageImportActivationApplyProof | null | undefined,
  options: {
    nowMs?: number;
    maxAgeMs?: number;
  } = {},
): string[] {
  const blockers: string[] = [];
  if (!proof) return ["package_import_activation_apply_proof_missing"];
  const maxAgeMs =
    options.maxAgeMs ??
    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_PROOF_MAX_AGE_MS;
  if (
    proof.schemaVersion !==
    "workflow.harness.package-import-activation-apply-proof.v1"
  ) {
    blockers.push("package_import_activation_apply_schema_mismatch");
  }
  if (proof.passed !== true || proof.blockers.length > 0) {
    blockers.push("package_import_activation_apply_proof_failed");
  }
  if (
    typeof options.nowMs === "number" &&
    Number.isFinite(proof.generatedAtMs) &&
    (proof.generatedAtMs > options.nowMs + 1000 ||
      options.nowMs - proof.generatedAtMs > maxAgeMs)
  ) {
    blockers.push("package_import_activation_apply_proof_stale");
  }
  if (proof.clicked !== true) {
    blockers.push("package_import_activation_apply_not_clicked");
  }
  const action = proof.activationAction;
  if (action.present !== true) {
    blockers.push("package_import_activation_apply_action_missing");
  }
  if (action.disabled !== false || action.mintable !== true) {
    blockers.push("package_import_activation_apply_action_not_mintable");
  }
  if (action.handoffDecision !== "mintable") {
    blockers.push("package_import_activation_apply_handoff_not_mintable");
  }
  const result = proof.activationResult;
  const review = proof.review;
  const activationId = result?.activationId ?? null;
  if (!result) {
    blockers.push("package_import_activation_apply_result_missing");
    return uniqueStrings(blockers);
  }
  if (review?.schemaVersion !== "workflow.package-import-review.v1") {
    blockers.push("package_import_activation_apply_review_missing");
  }
  if (result.applied !== true) {
    blockers.push("package_import_activation_apply_not_applied");
  }
  if (!activationId?.startsWith("activation:")) {
    blockers.push("package_import_activation_apply_activation_id_missing");
  }
  if (activationId !== action.activationIdPreview) {
    blockers.push(
      "package_import_activation_apply_activation_preview_mismatch",
    );
  }
  if (result.workflowActivationId !== activationId) {
    blockers.push(
      "package_import_activation_apply_workflow_activation_mismatch",
    );
  }
  if (result.workflowActivationState !== "validated") {
    blockers.push("package_import_activation_apply_workflow_state_mismatch");
  }
  if (result.workerBindingActivationId !== activationId) {
    blockers.push("package_import_activation_apply_worker_binding_mismatch");
  }
  if (result.activationRecordWorkerBindingActivationId !== activationId) {
    blockers.push(
      "package_import_activation_apply_record_worker_binding_mismatch",
    );
  }
  if (result.rollbackTarget !== action.rollbackTarget) {
    blockers.push("package_import_activation_apply_rollback_target_mismatch");
  }
  if (result.revisionBindingActivationId !== activationId) {
    blockers.push("package_import_activation_apply_revision_binding_mismatch");
  }
  if (!result.activationRecordRevisionBindingHash) {
    blockers.push("package_import_activation_apply_revision_hash_missing");
  }
  if (!result.rollbackRevisionBindingHash) {
    blockers.push("package_import_activation_apply_rollback_hash_missing");
  }
  if (result.latestAuditEventType !== "activation_minted") {
    blockers.push("package_import_activation_apply_audit_type_mismatch");
  }
  if (result.latestAuditStatus !== "applied") {
    blockers.push("package_import_activation_apply_audit_status_mismatch");
  }
  if (result.receiptRefs.length === 0) {
    blockers.push("package_import_activation_apply_receipts_missing");
  }
  if (result.evidenceRefs.length === 0) {
    blockers.push("package_import_activation_apply_evidence_missing");
  }
  if (result.workerHandoffReceiptIds.length === 0) {
    blockers.push(
      "package_import_activation_apply_worker_handoff_receipts_missing",
    );
  }
  if (result.workerHandoffNodeAttemptIds.length === 0) {
    blockers.push(
      "package_import_activation_apply_worker_handoff_attempts_missing",
    );
  }
  if (result.workerHandoffReplayFixtureRefs.length === 0) {
    blockers.push(
      "package_import_activation_apply_worker_handoff_replay_missing",
    );
  }
  if (!result.reviewedForkMutationCanaryId) {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_missing",
    );
  }
  if (result.reviewedForkMutationCanaryStatus !== "passed") {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_not_passed",
    );
  }
  if (!result.reviewedForkMutationCanaryDiffHash) {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_diff_missing",
    );
  }
  if ((result.reviewedForkMutationCanaryReceiptRefs ?? []).length === 0) {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_receipt_missing",
    );
  }
  if ((result.reviewedForkMutationCanaryReplayFixtureRefs ?? []).length === 0) {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_replay_missing",
    );
  }
  if ((result.reviewedForkMutationCanaryNodeAttemptIds ?? []).length === 0) {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_attempt_missing",
    );
  }
  if (!result.reviewedForkMutationCanaryRollbackTarget) {
    blockers.push(
      "package_import_activation_apply_fork_mutation_canary_rollback_missing",
    );
  }
  const reviewedSource = review?.source ?? null;
  const reviewedHandoff = review?.activationHandoff ?? null;
  const reviewedWorkerBindingActivationId =
    reviewedSource?.workerBindingActivationId ??
    reviewedHandoff?.workerBinding?.harnessActivationId ??
    null;
  if (
    reviewedSource?.reviewedPackageSnapshotHash &&
    (result.reviewedPackageSnapshotHash !==
      reviewedSource.reviewedPackageSnapshotHash ||
      reviewedHandoff?.reviewedPackageSnapshotHash !==
        reviewedSource.reviewedPackageSnapshotHash)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_snapshot_hash_mismatch",
    );
  }
  if (
    reviewedSource?.workflowContentHash &&
    result.reviewedWorkflowContentHash !== reviewedSource.workflowContentHash
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_workflow_hash_mismatch",
    );
  }
  if (
    reviewedSource?.activationId &&
    (result.reviewedActivationId !== reviewedSource.activationId ||
      activationId !== reviewedSource.activationId ||
      action.activationIdPreview !== reviewedSource.activationId)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_activation_id_mismatch",
    );
  }
  if (
    reviewedSource?.harnessWorkflowId &&
    result.reviewedHarnessWorkflowId !== reviewedSource.harnessWorkflowId
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_harness_workflow_mismatch",
    );
  }
  if (
    reviewedWorkerBindingActivationId &&
    (result.reviewedWorkerBindingActivationId !==
      reviewedWorkerBindingActivationId ||
      result.workerBindingActivationId !== reviewedWorkerBindingActivationId ||
      action.workerBindingId !== reviewedWorkerBindingActivationId)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_worker_binding_mismatch",
    );
  }
  if (
    reviewedSource?.rollbackTarget &&
    (result.reviewedRollbackTarget !== reviewedSource.rollbackTarget ||
      result.rollbackTarget !== reviewedSource.rollbackTarget ||
      action.rollbackTarget !== reviewedSource.rollbackTarget)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_rollback_target_mismatch",
    );
  }
  if (
    reviewedSource?.policyPosture &&
    (result.reviewedPolicyPosture !== reviewedSource.policyPosture ||
      reviewedHandoff?.policyPosture !== reviewedSource.policyPosture)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_policy_posture_mismatch",
    );
  }
  if (
    reviewedSource?.forkMutationCanaryId &&
    (result.reviewedForkMutationCanaryId !==
      reviewedSource.forkMutationCanaryId ||
      reviewedHandoff?.forkMutationCanaryId !==
        reviewedSource.forkMutationCanaryId ||
      action.mutationCanaryId !== reviewedSource.forkMutationCanaryId)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_mismatch",
    );
  }
  if (
    reviewedSource?.forkMutationCanaryStatus &&
    (result.reviewedForkMutationCanaryStatus !==
      reviewedSource.forkMutationCanaryStatus ||
      reviewedHandoff?.forkMutationCanaryStatus !==
        reviewedSource.forkMutationCanaryStatus ||
      action.mutationCanaryStatus !== reviewedSource.forkMutationCanaryStatus)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_status_mismatch",
    );
  }
  if (
    reviewedSource?.forkMutationCanaryDiffHash &&
    (result.reviewedForkMutationCanaryDiffHash !==
      reviewedSource.forkMutationCanaryDiffHash ||
      reviewedHandoff?.forkMutationCanaryDiffHash !==
        reviewedSource.forkMutationCanaryDiffHash ||
      action.mutationCanaryDiffHash !==
        reviewedSource.forkMutationCanaryDiffHash)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_diff_mismatch",
    );
  }
  const reviewedForkMutationCanaryReceiptRefs = uniqueStrings(
    reviewedSource?.forkMutationCanaryReceiptRefs ?? [],
  );
  if (
    reviewedForkMutationCanaryReceiptRefs.length > 0 &&
    !reviewedForkMutationCanaryReceiptRefs.every((receiptRef) =>
      (result.reviewedForkMutationCanaryReceiptRefs ?? []).includes(receiptRef),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_receipt_mismatch",
    );
  }
  const reviewedForkMutationCanaryReplayFixtureRefs = uniqueStrings(
    reviewedSource?.forkMutationCanaryReplayFixtureRefs ?? [],
  );
  if (
    reviewedForkMutationCanaryReplayFixtureRefs.length > 0 &&
    !reviewedForkMutationCanaryReplayFixtureRefs.every((fixtureRef) =>
      (result.reviewedForkMutationCanaryReplayFixtureRefs ?? []).includes(
        fixtureRef,
      ),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_replay_mismatch",
    );
  }
  const reviewedForkMutationCanaryNodeAttemptIds = uniqueStrings(
    reviewedSource?.forkMutationCanaryNodeAttemptIds ?? [],
  );
  if (
    reviewedForkMutationCanaryNodeAttemptIds.length > 0 &&
    !reviewedForkMutationCanaryNodeAttemptIds.every((attemptId) =>
      (result.reviewedForkMutationCanaryNodeAttemptIds ?? []).includes(
        attemptId,
      ),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_attempt_mismatch",
    );
  }
  if (
    reviewedSource?.forkMutationCanaryRollbackTarget &&
    (result.reviewedForkMutationCanaryRollbackTarget !==
      reviewedSource.forkMutationCanaryRollbackTarget ||
      reviewedHandoff?.forkMutationCanaryRollbackTarget !==
        reviewedSource.forkMutationCanaryRollbackTarget ||
      action.mutationCanaryRollbackTarget !==
        reviewedSource.forkMutationCanaryRollbackTarget)
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_fork_mutation_canary_rollback_mismatch",
    );
  }
  const reviewedReplayFixtureRefs = uniqueStrings(
    reviewedSource?.replayFixtureRefs ?? [],
  );
  if (
    reviewedReplayFixtureRefs.length > 0 &&
    !result.workerHandoffReplayFixtureRefs.every((fixtureRef) =>
      reviewedReplayFixtureRefs.includes(fixtureRef),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_replay_fixture_mismatch",
    );
  }
  const reviewedWorkerHandoffNodeAttemptIds = uniqueStrings(
    reviewedSource?.workerHandoffNodeAttemptIds ?? [],
  );
  if (
    reviewedWorkerHandoffNodeAttemptIds.length > 0 &&
    !result.workerHandoffNodeAttemptIds.every((attemptId) =>
      reviewedWorkerHandoffNodeAttemptIds.includes(attemptId),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_worker_attempt_mismatch",
    );
  }
  const reviewedWorkerHandoffReceiptIds = uniqueStrings(
    reviewedSource?.workerHandoffReceiptIds ?? [],
  );
  if (
    reviewedWorkerHandoffReceiptIds.length > 0 &&
    !result.workerHandoffReceiptIds.every((receiptId) =>
      reviewedWorkerHandoffReceiptIds.includes(receiptId),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_worker_receipt_mismatch",
    );
  }
  if (
    reviewedHandoff?.workflowContentHash &&
    reviewedSource?.workflowContentHash &&
    reviewedHandoff.workflowContentHash !== reviewedSource.workflowContentHash
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_handoff_workflow_hash_mismatch",
    );
  }
  if (
    reviewedHandoff?.replayFixtureRefs?.length &&
    !reviewedHandoff.replayFixtureRefs.every((fixtureRef) =>
      reviewedReplayFixtureRefs.includes(fixtureRef),
    )
  ) {
    blockers.push(
      "package_import_activation_replay_integrity_handoff_replay_fixture_mismatch",
    );
  }
  const workerHandoffAttemptId = result.workerHandoffNodeAttemptIds[0] ?? null;
  if (
    workerHandoffAttemptId &&
    proof.workerHandoff.deepLinkHash?.includes(
      "activationGateNodeAttemptId=",
    ) !== true
  ) {
    blockers.push("package_import_activation_apply_handoff_node_link_missing");
  }
  if (
    workerHandoffAttemptId &&
    proof.workerHandoff.selectedState["data-selected-activation-gate-id"] !==
      "worker-handoff"
  ) {
    blockers.push("package_import_activation_apply_handoff_gate_not_restored");
  }
  if (
    workerHandoffAttemptId &&
    proof.workerHandoff.selectedState[
      "data-selected-activation-gate-node-attempt-id"
    ] !== workerHandoffAttemptId
  ) {
    blockers.push(
      "package_import_activation_apply_handoff_attempt_not_selected",
    );
  }
  if (
    workerHandoffAttemptId &&
    proof.workerHandoff.selectedAttemptId !== workerHandoffAttemptId
  ) {
    blockers.push(
      "package_import_activation_apply_handoff_timeline_attempt_missing",
    );
  }
  if (workerHandoffAttemptId && proof.workerHandoff.timelineVisible !== true) {
    blockers.push("package_import_activation_apply_handoff_timeline_missing");
  }
  const mutationCanaryAttemptId =
    result.reviewedForkMutationCanaryNodeAttemptIds?.[0] ?? null;
  if (
    mutationCanaryAttemptId &&
    proof.mutationCanary?.deepLinkHash?.includes(
      "activationGateNodeAttemptId=",
    ) !== true
  ) {
    blockers.push(
      "package_import_activation_apply_mutation_canary_node_link_missing",
    );
  }
  if (
    mutationCanaryAttemptId &&
    proof.mutationCanary?.selectedState["data-selected-activation-gate-id"] !==
      "mutation-canary"
  ) {
    blockers.push(
      "package_import_activation_apply_mutation_canary_gate_not_restored",
    );
  }
  if (
    mutationCanaryAttemptId &&
    proof.mutationCanary?.selectedState[
      "data-selected-activation-gate-node-attempt-id"
    ] !== mutationCanaryAttemptId
  ) {
    blockers.push(
      "package_import_activation_apply_mutation_canary_attempt_not_selected",
    );
  }
  if (
    mutationCanaryAttemptId &&
    proof.mutationCanary?.nodeAttemptState["data-node-attempt-id"] !==
      mutationCanaryAttemptId
  ) {
    blockers.push(
      "package_import_activation_apply_mutation_canary_node_inspector_missing",
    );
  }
  if (
    mutationCanaryAttemptId &&
    proof.mutationCanary?.selectedAttemptId !== mutationCanaryAttemptId
  ) {
    blockers.push(
      "package_import_activation_apply_mutation_canary_timeline_attempt_missing",
    );
  }
  if (
    mutationCanaryAttemptId &&
    proof.mutationCanary?.timelineVisible !== true
  ) {
    blockers.push(
      "package_import_activation_apply_mutation_canary_timeline_missing",
    );
  }
  if (
    proof.incompleteAction.disabled !== true ||
    proof.incompleteAction.mintable !== false
  ) {
    blockers.push(
      "package_import_activation_apply_incomplete_action_not_blocked",
    );
  }
  return uniqueStrings(blockers);
}

