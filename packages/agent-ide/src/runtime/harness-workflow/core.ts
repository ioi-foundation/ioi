import type {
  Node,
  WorkflowEdge,
  WorkflowHarnessCanaryExecutionBoundary,
  WorkflowHarnessClusterPromotionStatus,
  WorkflowHarnessComponentAdapterResult,
  WorkflowHarnessComponentReadiness,
  WorkflowHarnessComponentKind,
  WorkflowHarnessComponentSpec,
  WorkflowHarnessCognitionNodeAuthorityGate,
  WorkflowHarnessDefaultRuntimeDispatchProof,
  WorkflowHarnessDivergenceClass,
  WorkflowHarnessExecutionMode,
  WorkflowHarnessActivationAuditEvent,
  WorkflowHarnessActivationAuditEventStatus,
  WorkflowHarnessActivationAuditEventType,
  WorkflowHarnessActiveRuntimeRollbackExecutionProof,
  WorkflowHarnessActiveRuntimeRollbackApplyProof,
  WorkflowHarnessActivationRollbackExecution,
  WorkflowHarnessActivationRollbackProof,
  WorkflowHarnessActivationIdGateClickProof,
  WorkflowHarnessAuthorityToolingNodeAuthorityGate,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessForkActivationRecord,
  WorkflowHarnessForkMutationCanary,
  WorkflowHarnessLiveHandoffProof,
  WorkflowHarnessLivePromotionClusterReadiness,
  WorkflowHarnessLivePromotionReadinessProof,
  WorkflowHarnessLiveShadowComparisonGate,
  WorkflowHarnessMetadata,
  WorkflowHarnessPackageEvidenceManifest,
  WorkflowHarnessNodeBinding,
  WorkflowHarnessNodeAttemptRecord,
  WorkflowHarnessPackageImportActivationApplyProof,
  WorkflowHarnessPromotionCluster,
  WorkflowHarnessPromotionClusterId,
  WorkflowHarnessPromotionClusterReplayGateProof,
  WorkflowHarnessPromotionTransitionAttempt,
  WorkflowHarnessPromotionTransitionEligibility,
  WorkflowHarnessPromotionTransitionTarget,
  WorkflowHarnessReplayEnvelope,
  WorkflowHarnessRoutingModelNodeAuthorityGate,
  WorkflowHarnessRuntimeSelectorDecision,
  WorkflowHarnessVerificationOutputNodeAuthorityGate,
  WorkflowHarnessReplayDrillDivergenceClass,
  WorkflowHarnessReplayDrillResult,
  WorkflowHarnessReplayGateResult,
  WorkflowHarnessShadowComparison,
  WorkflowHarnessSlotKind,
  WorkflowHarnessSlotSpec,
  WorkflowHarnessWorkerAttachReceipt,
  WorkflowHarnessWorkerAttachRequest,
  WorkflowHarnessWorkerAttachStatus,
  WorkflowHarnessWorkerAttachLifecycleEvent,
  WorkflowHarnessWorkerHandoffReceipt,
  WorkflowHarnessWorkerLaunchEnvelope,
  WorkflowHarnessWorkerLaunchPhase,
  WorkflowHarnessWorkerSessionRecord,
  WorkflowHarnessWorkerBinding,
  WorkflowHarnessWorkerBindingRegistryRecord,
  WorkflowRevisionBinding,
  WorkflowRevisionRestoreRequest,
  WorkflowRevisionRestoreResult,
  WorkflowNode,
  WorkflowProject,
  WorkflowProposal,
  WorkflowTestCase,
} from "../../types/graph";
import { normalizeGlobalConfig, slugify } from "../workflow-defaults";
import {
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
  DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS,
  DEFAULT_AGENT_HARNESS_FORK_MUTATION_AFTER_VALUE,
  DEFAULT_AGENT_HARNESS_FORK_MUTATION_BEFORE_VALUE,
  DEFAULT_AGENT_HARNESS_FORK_MUTATION_TARGET_PATH,
  DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET,
  DEFAULT_AGENT_HARNESS_HASH,
  DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_PROOF_MAX_AGE_MS,
  DEFAULT_AGENT_HARNESS_VERSION,
  DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
} from "./constants";
export {
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
  DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS,
  DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET,
  DEFAULT_AGENT_HARNESS_HASH,
  DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_PROOF_MAX_AGE_MS,
  DEFAULT_AGENT_HARNESS_VERSION,
  DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
} from "./constants";
import { stableContentHash } from "./hashing";

const HARNESS_INPUT_SCHEMA = {
  type: "object",
  required: ["sessionId", "turnId"],
  properties: {
    sessionId: { type: "string" },
    turnId: { type: "string" },
    input: {},
    state: { type: "object" },
    policyContext: { type: "object" },
  },
};

const HARNESS_OUTPUT_SCHEMA = {
  type: "object",
  required: ["status"],
  properties: {
    status: { type: "string" },
    value: {},
    evidence: { type: "array", items: { type: "string" } },
    receipts: { type: "array", items: { type: "string" } },
  },
};

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

const HARNESS_ERROR_SCHEMA = {
  type: "object",
  required: ["code", "message", "retryable"],
  properties: {
    code: { type: "string" },
    message: { type: "string" },
    retryable: { type: "boolean" },
    evidenceRef: { type: "string" },
  },
};

export function defaultHarnessComponentVersionSet(): Record<string, string> {
  return Object.fromEntries(
    DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => [
      component.componentId,
      component.version,
    ]),
  );
}

export function harnessForkActivationId(workflowId: string): string {
  const normalizedWorkflowId = slugify(
    workflowId || "default-agent-harness-fork",
  );
  return `activation:${normalizedWorkflowId}:validated-canary:${DEFAULT_AGENT_HARNESS_HASH.replace(
    /^sha256:/,
    "",
  ).slice(0, 12)}`;
}

export function workflowHarnessSourceContentHash(
  workflow: WorkflowProject,
): string {
  return stableContentHash(workflowSourceProjection(workflow));
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.length > 0,
      ),
    ),
  );
}

function sortedUniqueStrings(values: Array<string | null | undefined>): string[] {
  return uniqueStrings(values).sort();
}

export interface WorkflowHarnessReviewedPackageSnapshotFields {
  reviewedPackageSnapshotHash?: string | null;
  reviewedWorkflowContentHash?: string | null;
  reviewedActivationId?: string | null;
  reviewedHarnessWorkflowId?: string | null;
  reviewedWorkerBindingActivationId?: string | null;
  reviewedRollbackTarget?: string | null;
  reviewedReplayFixtureRefs?: Array<string | null | undefined>;
  reviewedWorkerHandoffNodeAttemptIds?: Array<string | null | undefined>;
  reviewedWorkerHandoffReceiptIds?: Array<string | null | undefined>;
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: Array<string | null | undefined>;
  reviewedForkMutationCanaryReplayFixtureRefs?: Array<string | null | undefined>;
  reviewedForkMutationCanaryNodeAttemptIds?: Array<string | null | undefined>;
  reviewedForkMutationCanaryRollbackTarget?: string | null;
  reviewedPolicyPosture?: string | null;
  rollbackTarget?: string | null;
}

function workflowHarnessReviewedPackageSnapshotIdentity(
  source: WorkflowHarnessReviewedPackageSnapshotFields,
) {
  return {
    schemaVersion: "workflow.harness.reviewed-package-snapshot.v1",
    reviewedWorkflowContentHash: source.reviewedWorkflowContentHash ?? null,
    reviewedActivationId: source.reviewedActivationId ?? null,
    reviewedHarnessWorkflowId: source.reviewedHarnessWorkflowId ?? null,
    reviewedWorkerBindingActivationId:
      source.reviewedWorkerBindingActivationId ?? null,
    reviewedRollbackTarget: source.reviewedRollbackTarget ?? null,
    reviewedReplayFixtureRefs: sortedUniqueStrings(
      source.reviewedReplayFixtureRefs ?? [],
    ),
    reviewedWorkerHandoffNodeAttemptIds: sortedUniqueStrings(
      source.reviewedWorkerHandoffNodeAttemptIds ?? [],
    ),
    reviewedWorkerHandoffReceiptIds: sortedUniqueStrings(
      source.reviewedWorkerHandoffReceiptIds ?? [],
    ),
    reviewedForkMutationCanaryId:
      source.reviewedForkMutationCanaryId ?? null,
    reviewedForkMutationCanaryStatus:
      source.reviewedForkMutationCanaryStatus ?? null,
    reviewedForkMutationCanaryDiffHash:
      source.reviewedForkMutationCanaryDiffHash ?? null,
    reviewedForkMutationCanaryReceiptRefs: sortedUniqueStrings(
      source.reviewedForkMutationCanaryReceiptRefs ?? [],
    ),
    reviewedForkMutationCanaryReplayFixtureRefs: sortedUniqueStrings(
      source.reviewedForkMutationCanaryReplayFixtureRefs ?? [],
    ),
    reviewedForkMutationCanaryNodeAttemptIds: sortedUniqueStrings(
      source.reviewedForkMutationCanaryNodeAttemptIds ?? [],
    ),
    reviewedForkMutationCanaryRollbackTarget:
      source.reviewedForkMutationCanaryRollbackTarget ?? null,
    reviewedPolicyPosture: source.reviewedPolicyPosture ?? null,
  };
}

export function workflowHarnessReviewedPackageSnapshotHash(
  source: WorkflowHarnessReviewedPackageSnapshotFields,
): string {
  return stableContentHash(workflowHarnessReviewedPackageSnapshotIdentity(source));
}

function workflowHarnessReviewedPackageSnapshotBlockers(
  prefix: string,
  source: WorkflowHarnessReviewedPackageSnapshotFields,
): string[] {
  const blockers: string[] = [];
  const snapshot = workflowHarnessReviewedPackageSnapshotIdentity(source);
  const expectedHash = workflowHarnessReviewedPackageSnapshotHash(source);
  if (!source.reviewedPackageSnapshotHash) {
    blockers.push(`${prefix}_reviewed_package_snapshot_hash_missing`);
  } else if (source.reviewedPackageSnapshotHash !== expectedHash) {
    blockers.push(`${prefix}_reviewed_package_snapshot_hash_mismatch`);
  }
  if (!snapshot.reviewedWorkflowContentHash) {
    blockers.push(`${prefix}_reviewed_package_workflow_hash_missing`);
  }
  if (!snapshot.reviewedActivationId) {
    blockers.push(`${prefix}_reviewed_package_activation_missing`);
  }
  if (!snapshot.reviewedHarnessWorkflowId) {
    blockers.push(`${prefix}_reviewed_package_workflow_id_missing`);
  }
  if (!snapshot.reviewedWorkerBindingActivationId) {
    blockers.push(`${prefix}_reviewed_package_worker_binding_missing`);
  }
  if (
    snapshot.reviewedActivationId &&
    snapshot.reviewedWorkerBindingActivationId &&
    snapshot.reviewedActivationId !== snapshot.reviewedWorkerBindingActivationId
  ) {
    blockers.push(`${prefix}_reviewed_package_activation_mismatch`);
  }
  if (!snapshot.reviewedRollbackTarget) {
    blockers.push(`${prefix}_reviewed_package_rollback_target_missing`);
  } else if (
    source.rollbackTarget &&
    snapshot.reviewedRollbackTarget !== source.rollbackTarget
  ) {
    blockers.push(`${prefix}_reviewed_package_rollback_target_mismatch`);
  }
  if (snapshot.reviewedReplayFixtureRefs.length === 0) {
    blockers.push(`${prefix}_reviewed_package_replay_fixture_missing`);
  }
  if (snapshot.reviewedWorkerHandoffNodeAttemptIds.length === 0) {
    blockers.push(`${prefix}_reviewed_package_worker_attempt_missing`);
  }
  if (snapshot.reviewedWorkerHandoffReceiptIds.length === 0) {
    blockers.push(`${prefix}_reviewed_package_worker_receipt_missing`);
  }
  if (!snapshot.reviewedForkMutationCanaryId) {
    blockers.push(`${prefix}_reviewed_package_fork_mutation_canary_missing`);
  }
  if (snapshot.reviewedForkMutationCanaryStatus !== "passed") {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_not_passed`,
    );
  }
  if (!snapshot.reviewedForkMutationCanaryDiffHash) {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_diff_missing`,
    );
  }
  if (snapshot.reviewedForkMutationCanaryReceiptRefs.length === 0) {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_receipt_missing`,
    );
  }
  if (snapshot.reviewedForkMutationCanaryReplayFixtureRefs.length === 0) {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_replay_missing`,
    );
  }
  if (snapshot.reviewedForkMutationCanaryNodeAttemptIds.length === 0) {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_attempt_missing`,
    );
  }
  if (!snapshot.reviewedForkMutationCanaryRollbackTarget) {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_rollback_missing`,
    );
  } else if (
    source.rollbackTarget &&
    snapshot.reviewedForkMutationCanaryRollbackTarget !== source.rollbackTarget
  ) {
    blockers.push(
      `${prefix}_reviewed_package_fork_mutation_canary_rollback_mismatch`,
    );
  }
  if (!snapshot.reviewedPolicyPosture) {
    blockers.push(`${prefix}_reviewed_package_policy_posture_missing`);
  }
  return uniqueStrings(blockers);
}

function workflowHarnessReviewedPackageSnapshotsMatch(
  left: WorkflowHarnessReviewedPackageSnapshotFields,
  right: WorkflowHarnessReviewedPackageSnapshotFields,
): boolean {
  return (
    left.reviewedPackageSnapshotHash === right.reviewedPackageSnapshotHash &&
    workflowHarnessReviewedPackageSnapshotHash(left) ===
      workflowHarnessReviewedPackageSnapshotHash(right)
  );
}

export function makeWorkflowHarnessWorkerBindingRegistryRecord(options: {
  workflowId?: string;
  activationId?: string;
  activationHash?: string;
  harnessHash?: string;
  reviewedPackageSnapshotHash?: string | null;
  reviewedWorkflowContentHash?: string | null;
  reviewedActivationId?: string | null;
  reviewedHarnessWorkflowId?: string | null;
  reviewedWorkerBindingActivationId?: string | null;
  reviewedRollbackTarget?: string | null;
  reviewedReplayFixtureRefs?: string[];
  reviewedWorkerHandoffNodeAttemptIds?: string[];
  reviewedWorkerHandoffReceiptIds?: string[];
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: string[];
  reviewedForkMutationCanaryReplayFixtureRefs?: string[];
  reviewedForkMutationCanaryNodeAttemptIds?: string[];
  reviewedForkMutationCanaryRollbackTarget?: string | null;
  reviewedPolicyPosture?: string | null;
  selectorDecisionId?: string;
  defaultDispatchId?: string;
  componentVersionSet?: Record<string, string>;
  rollbackTarget?: string;
  readinessProofId?: string;
  rollbackReadinessProofId?: string;
  rollbackLiveShadowComparisonGateId?: string;
  rollbackLiveShadowComparisonGateReady?: boolean;
  rollbackActivationId?: string;
  rollbackHarnessHash?: string;
  rollbackPolicyDecision?: string;
  canaryResultId?: string;
  policyDecision?: string;
  bindingStatus?: WorkflowHarnessWorkerBindingRegistryRecord["bindingStatus"];
  blockers?: string[];
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
  createdAtMs?: number;
}): WorkflowHarnessWorkerBindingRegistryRecord {
  const workflowId = options.workflowId ?? DEFAULT_AGENT_HARNESS_WORKFLOW_ID;
  const activationId =
    options.activationId ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
  const harnessHash = options.harnessHash ?? DEFAULT_AGENT_HARNESS_HASH;
  const activationHash = options.activationHash ?? harnessHash;
  const rollbackTarget =
    options.rollbackTarget ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
  const readinessProofId = options.readinessProofId ?? "";
  const rollbackReadinessProofId =
    options.rollbackReadinessProofId ?? readinessProofId;
  const rollbackLiveShadowComparisonGateId =
    options.rollbackLiveShadowComparisonGateId ??
    DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID;
  const rollbackActivationId = options.rollbackActivationId ?? activationId;
  const rollbackHarnessHash = options.rollbackHarnessHash ?? harnessHash;
  const policyDecision =
    options.policyDecision ?? "block_workflow_default_until_gates_pass";
  const blockers = uniqueStrings(options.blockers ?? []);
  const requiredInvariantIds = uniqueStrings(
    options.requiredInvariantIds ?? [
      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
    ],
  );
  const invariantBlockers = uniqueStrings(options.invariantBlockers ?? []);
  const bindingStatus =
    options.bindingStatus ??
    (blockers.length === 0 && invariantBlockers.length === 0 && readinessProofId
      ? "bound"
      : "blocked");
  const rollbackLiveShadowComparisonGateReady =
    options.rollbackLiveShadowComparisonGateReady ?? bindingStatus === "bound";
  const rollbackPolicyDecision =
    options.rollbackPolicyDecision ??
    (bindingStatus === "bound"
      ? "allow_default_harness_worker_rollback_from_live_shadow_gate"
      : "block_default_harness_worker_rollback_from_live_shadow_gate");
  const suppliedWorkerBinding = options.workerBinding;
  const workerBinding: WorkflowHarnessWorkerBinding = {
    harnessWorkflowId: suppliedWorkerBinding?.harnessWorkflowId ?? workflowId,
    harnessActivationId:
      suppliedWorkerBinding?.harnessActivationId ?? activationId,
    harnessHash: suppliedWorkerBinding?.harnessHash ?? harnessHash,
    executionMode:
      suppliedWorkerBinding?.executionMode ??
      (bindingStatus === "bound" ? "live" : "projection"),
    source: suppliedWorkerBinding?.source ?? "default",
    selectorDecisionId:
      suppliedWorkerBinding?.selectorDecisionId ?? options.selectorDecisionId,
    defaultDispatchId:
      suppliedWorkerBinding?.defaultDispatchId ?? options.defaultDispatchId,
    rollbackTarget: suppliedWorkerBinding?.rollbackTarget ?? rollbackTarget,
    authorityBindingReady:
      suppliedWorkerBinding?.authorityBindingReady ??
      (bindingStatus === "bound" &&
        blockers.length === 0 &&
        invariantBlockers.length === 0),
    authorityBindingBlockers: uniqueStrings(
      suppliedWorkerBinding?.authorityBindingBlockers ?? [
        ...blockers,
        ...invariantBlockers,
      ],
    ),
    livePromotionReadinessProofId:
      suppliedWorkerBinding?.livePromotionReadinessProofId ??
      (readinessProofId || undefined),
    liveShadowComparisonGateId:
      suppliedWorkerBinding?.liveShadowComparisonGateId ??
      rollbackLiveShadowComparisonGateId,
    liveShadowComparisonGateReady:
      suppliedWorkerBinding?.liveShadowComparisonGateReady ??
      rollbackLiveShadowComparisonGateReady,
    rollbackPolicyDecision:
      suppliedWorkerBinding?.rollbackPolicyDecision ?? rollbackPolicyDecision,
    policyDecision: suppliedWorkerBinding?.policyDecision ?? policyDecision,
    requiredInvariantIds: uniqueStrings(
      suppliedWorkerBinding?.requiredInvariantIds ?? requiredInvariantIds,
    ),
    invariantBlockers: uniqueStrings(
      suppliedWorkerBinding?.invariantBlockers ?? invariantBlockers,
    ),
  };
  const reviewedSnapshot = workflowHarnessReviewedPackageSnapshotIdentity({
    reviewedWorkflowContentHash:
      options.reviewedWorkflowContentHash ?? activationHash,
    reviewedActivationId: options.reviewedActivationId ?? activationId,
    reviewedHarnessWorkflowId: options.reviewedHarnessWorkflowId ?? workflowId,
    reviewedWorkerBindingActivationId:
      options.reviewedWorkerBindingActivationId ??
      workerBinding.harnessActivationId ??
      activationId,
    reviewedRollbackTarget: options.reviewedRollbackTarget ?? rollbackTarget,
    reviewedReplayFixtureRefs:
      options.reviewedReplayFixtureRefs ??
      (bindingStatus === "bound"
        ? [
            `harness-reviewed-package:fixture:${workflowId}:${activationId}`,
          ]
        : []),
    reviewedWorkerHandoffNodeAttemptIds:
      options.reviewedWorkerHandoffNodeAttemptIds ??
      (bindingStatus === "bound"
        ? [
            `harness-reviewed-package:worker-attempt:${workflowId}:${activationId}`,
          ]
        : []),
    reviewedWorkerHandoffReceiptIds:
      options.reviewedWorkerHandoffReceiptIds ??
      (bindingStatus === "bound"
        ? [
            `harness-reviewed-package:worker-receipt:${workflowId}:${activationId}`,
          ]
        : []),
    reviewedForkMutationCanaryId:
      options.reviewedForkMutationCanaryId ??
      (bindingStatus === "bound"
        ? `harness-reviewed-package:fork-mutation-canary:${workflowId}:${activationId}`
        : null),
    reviewedForkMutationCanaryStatus:
      options.reviewedForkMutationCanaryStatus ??
      (bindingStatus === "bound" ? "passed" : null),
    reviewedForkMutationCanaryDiffHash:
      options.reviewedForkMutationCanaryDiffHash ??
      (bindingStatus === "bound"
        ? stableContentHash({
            kind: "reviewed-fork-mutation-canary",
            workflowId,
            activationId,
          })
        : null),
    reviewedForkMutationCanaryReceiptRefs:
      options.reviewedForkMutationCanaryReceiptRefs ??
      (bindingStatus === "bound"
        ? [
            `harness-reviewed-package:fork-mutation-canary-receipt:${workflowId}:${activationId}`,
          ]
        : []),
    reviewedForkMutationCanaryReplayFixtureRefs:
      options.reviewedForkMutationCanaryReplayFixtureRefs ??
      (bindingStatus === "bound"
        ? [
            `harness-reviewed-package:fork-mutation-canary-fixture:${workflowId}:${activationId}`,
          ]
        : []),
    reviewedForkMutationCanaryNodeAttemptIds:
      options.reviewedForkMutationCanaryNodeAttemptIds ??
      (bindingStatus === "bound"
        ? [
            `harness-reviewed-package:fork-mutation-canary-attempt:${workflowId}:${activationId}`,
          ]
        : []),
    reviewedForkMutationCanaryRollbackTarget:
      options.reviewedForkMutationCanaryRollbackTarget ??
      (bindingStatus === "bound" ? rollbackTarget : null),
    reviewedPolicyPosture:
      options.reviewedPolicyPosture ??
      (bindingStatus === "bound" ? "canary" : null),
    rollbackTarget,
  });
  const reviewedPackageSnapshotHash =
    options.reviewedPackageSnapshotHash ??
    workflowHarnessReviewedPackageSnapshotHash({
      ...reviewedSnapshot,
      rollbackTarget,
    });
  const reviewedSnapshotFields = {
    reviewedWorkflowContentHash: reviewedSnapshot.reviewedWorkflowContentHash,
    reviewedActivationId: reviewedSnapshot.reviewedActivationId,
    reviewedHarnessWorkflowId: reviewedSnapshot.reviewedHarnessWorkflowId,
    reviewedWorkerBindingActivationId:
      reviewedSnapshot.reviewedWorkerBindingActivationId,
    reviewedRollbackTarget: reviewedSnapshot.reviewedRollbackTarget,
    reviewedReplayFixtureRefs: reviewedSnapshot.reviewedReplayFixtureRefs,
    reviewedWorkerHandoffNodeAttemptIds:
      reviewedSnapshot.reviewedWorkerHandoffNodeAttemptIds,
    reviewedWorkerHandoffReceiptIds:
      reviewedSnapshot.reviewedWorkerHandoffReceiptIds,
    reviewedForkMutationCanaryId:
      reviewedSnapshot.reviewedForkMutationCanaryId,
    reviewedForkMutationCanaryStatus:
      reviewedSnapshot.reviewedForkMutationCanaryStatus,
    reviewedForkMutationCanaryDiffHash:
      reviewedSnapshot.reviewedForkMutationCanaryDiffHash,
    reviewedForkMutationCanaryReceiptRefs:
      reviewedSnapshot.reviewedForkMutationCanaryReceiptRefs,
    reviewedForkMutationCanaryReplayFixtureRefs:
      reviewedSnapshot.reviewedForkMutationCanaryReplayFixtureRefs,
    reviewedForkMutationCanaryNodeAttemptIds:
      reviewedSnapshot.reviewedForkMutationCanaryNodeAttemptIds,
    reviewedForkMutationCanaryRollbackTarget:
      reviewedSnapshot.reviewedForkMutationCanaryRollbackTarget,
    reviewedPolicyPosture: reviewedSnapshot.reviewedPolicyPosture,
  };
  return {
    schemaVersion: "workflow.harness.worker-binding-registry.v1",
    registryRecordId: `harness-worker-binding-registry:${workflowId}:${activationId}:${options.defaultDispatchId ?? "pending"}`,
    workflowId,
    activationId,
    activationHash,
    harnessHash,
    reviewedPackageSnapshotHash,
    ...reviewedSnapshotFields,
    componentVersionSet:
      options.componentVersionSet ?? defaultHarnessComponentVersionSet(),
    rollbackTarget,
    readinessProofId,
    rollbackReadinessProofId,
    rollbackLiveShadowComparisonGateId,
    rollbackLiveShadowComparisonGateReady,
    rollbackActivationId,
    rollbackHarnessHash,
    rollbackPolicyDecision,
    canaryResultId:
      options.canaryResultId ??
      (bindingStatus === "bound"
        ? "harness-canary-result:default-agent-harness:passed"
        : "harness-canary-result:default-agent-harness:not-run"),
    policyDecision,
    bindingStatus,
    blockers,
    requiredInvariantIds,
    invariantBlockers,
    workerBinding,
    createdAtMs: options.createdAtMs,
  };
}

function workflowHarnessRequiredInvariantIdsPresent(
  invariantIds: string[] | null | undefined,
): boolean {
  return uniqueStrings(invariantIds ?? []).includes(
    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
  );
}

function workflowHarnessInvariantSetsMatch(
  left: string[] | null | undefined,
  right: string[] | null | undefined,
): boolean {
  const leftEntries = uniqueStrings(left ?? []).sort();
  const rightEntries = uniqueStrings(right ?? []).sort();
  return JSON.stringify(leftEntries) === JSON.stringify(rightEntries);
}

export function workflowHarnessWorkerBindingRegistryBlockers(
  record: WorkflowHarnessWorkerBindingRegistryRecord | null | undefined,
): string[] {
  if (!record) return ["worker_binding_registry_missing"];
  const blockers = uniqueStrings(record.blockers ?? []);
  if (record.schemaVersion !== "workflow.harness.worker-binding-registry.v1") {
    blockers.push("worker_binding_registry_schema_mismatch");
  }
  if (record.workflowId !== DEFAULT_AGENT_HARNESS_WORKFLOW_ID) {
    blockers.push("worker_binding_registry_workflow_mismatch");
  }
  if (record.activationId !== DEFAULT_AGENT_HARNESS_ACTIVATION_ID) {
    blockers.push("worker_binding_registry_activation_mismatch");
  }
  if (!record.activationHash) {
    blockers.push("worker_binding_registry_activation_hash_missing");
  }
  if (record.harnessHash !== DEFAULT_AGENT_HARNESS_HASH) {
    blockers.push("worker_binding_registry_harness_hash_mismatch");
  }
  blockers.push(
    ...workflowHarnessReviewedPackageSnapshotBlockers(
      "worker_binding_registry",
      record,
    ),
  );
  if (record.rollbackTarget !== DEFAULT_AGENT_HARNESS_ACTIVATION_ID) {
    blockers.push("worker_binding_registry_rollback_target_mismatch");
  }
  if (!record.readinessProofId) {
    blockers.push("worker_binding_registry_readiness_proof_missing");
  }
  if (!record.rollbackReadinessProofId) {
    blockers.push("worker_binding_registry_rollback_readiness_proof_missing");
  }
  if (record.rollbackReadinessProofId !== record.readinessProofId) {
    blockers.push("worker_binding_registry_rollback_readiness_proof_mismatch");
  }
  if (!record.rollbackLiveShadowComparisonGateId) {
    blockers.push("worker_binding_registry_rollback_live_shadow_gate_missing");
  }
  if (
    record.workerBinding.liveShadowComparisonGateId !==
    record.rollbackLiveShadowComparisonGateId
  ) {
    blockers.push("worker_binding_registry_rollback_live_shadow_gate_mismatch");
  }
  if (
    record.rollbackLiveShadowComparisonGateReady !== true ||
    record.workerBinding.liveShadowComparisonGateReady !== true
  ) {
    blockers.push(
      "worker_binding_registry_rollback_live_shadow_gate_not_ready",
    );
  }
  if (record.rollbackActivationId !== record.activationId) {
    blockers.push("worker_binding_registry_rollback_activation_mismatch");
  }
  if (record.rollbackHarnessHash !== record.harnessHash) {
    blockers.push("worker_binding_registry_rollback_harness_hash_mismatch");
  }
  if (
    record.rollbackPolicyDecision !==
      "allow_default_harness_worker_rollback_from_live_shadow_gate" ||
    record.workerBinding.rollbackPolicyDecision !==
      "allow_default_harness_worker_rollback_from_live_shadow_gate"
  ) {
    blockers.push("worker_binding_registry_rollback_policy_not_allowed");
  }
  if (!record.canaryResultId || record.canaryResultId.endsWith(":not-run")) {
    blockers.push("worker_binding_registry_canary_missing");
  }
  if (record.bindingStatus !== "bound") {
    blockers.push("worker_binding_registry_not_bound");
  }
  if (
    !workflowHarnessRequiredInvariantIdsPresent(record.requiredInvariantIds)
  ) {
    blockers.push(
      "worker_binding_registry_reviewed_import_activation_apply_invariant_missing",
    );
  }
  if ((record.invariantBlockers ?? []).length > 0) {
    blockers.push("worker_binding_registry_invariant_blocked");
  }
  if (
    record.policyDecision !==
    "promote_blessed_workflow_default_for_non_mutating_turn"
  ) {
    blockers.push("worker_binding_registry_policy_blocked");
  }
  if (record.workerBinding.harnessWorkflowId !== record.workflowId) {
    blockers.push("worker_binding_registry_worker_workflow_mismatch");
  }
  if (record.workerBinding.harnessActivationId !== record.activationId) {
    blockers.push("worker_binding_registry_worker_activation_mismatch");
  }
  if (record.workerBinding.harnessHash !== record.harnessHash) {
    blockers.push("worker_binding_registry_worker_hash_mismatch");
  }
  if (record.workerBinding.executionMode !== "live") {
    blockers.push("worker_binding_registry_worker_not_live");
  }
  if (record.workerBinding.rollbackTarget !== record.rollbackTarget) {
    blockers.push("worker_binding_registry_worker_rollback_mismatch");
  }
  if (record.workerBinding.authorityBindingReady !== true) {
    blockers.push("worker_binding_registry_worker_authority_not_ready");
  }
  if ((record.workerBinding.authorityBindingBlockers ?? []).length > 0) {
    blockers.push("worker_binding_registry_worker_authority_blocked");
  }
  if (
    record.workerBinding.livePromotionReadinessProofId !==
    record.readinessProofId
  ) {
    blockers.push("worker_binding_registry_worker_readiness_proof_mismatch");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      record.workerBinding.requiredInvariantIds,
      record.requiredInvariantIds,
    )
  ) {
    blockers.push("worker_binding_registry_worker_invariant_mismatch");
  }
  if ((record.workerBinding.invariantBlockers ?? []).length > 0) {
    blockers.push("worker_binding_registry_worker_invariant_blocked");
  }
  if (Object.keys(record.componentVersionSet ?? {}).length === 0) {
    blockers.push("worker_binding_registry_component_versions_missing");
  }
  return uniqueStrings(blockers);
}

function workflowHarnessWorkerBindingRegistryContractBlockers(
  record: WorkflowHarnessWorkerBindingRegistryRecord | null | undefined,
): string[] {
  if (!record) return ["worker_binding_registry_missing"];
  const blockers = uniqueStrings(record.blockers ?? []);
  if (record.schemaVersion !== "workflow.harness.worker-binding-registry.v1") {
    blockers.push("worker_binding_registry_schema_mismatch");
  }
  if (!record.workflowId) {
    blockers.push("worker_binding_registry_workflow_missing");
  }
  if (!record.activationId) {
    blockers.push("worker_binding_registry_activation_missing");
  }
  if (!record.activationHash) {
    blockers.push("worker_binding_registry_activation_hash_missing");
  }
  if (!record.harnessHash) {
    blockers.push("worker_binding_registry_harness_hash_missing");
  }
  blockers.push(
    ...workflowHarnessReviewedPackageSnapshotBlockers(
      "worker_binding_registry",
      record,
    ),
  );
  if (!record.rollbackTarget) {
    blockers.push("worker_binding_registry_rollback_target_missing");
  }
  if (!record.readinessProofId) {
    blockers.push("worker_binding_registry_readiness_proof_missing");
  }
  if (!record.canaryResultId || record.canaryResultId.endsWith(":not-run")) {
    blockers.push("worker_binding_registry_canary_missing");
  }
  if (record.bindingStatus !== "bound") {
    blockers.push("worker_binding_registry_not_bound");
  }
  if (
    !workflowHarnessRequiredInvariantIdsPresent(record.requiredInvariantIds)
  ) {
    blockers.push(
      "worker_binding_registry_reviewed_import_activation_apply_invariant_missing",
    );
  }
  if ((record.invariantBlockers ?? []).length > 0) {
    blockers.push("worker_binding_registry_invariant_blocked");
  }
  if (record.workerBinding.harnessWorkflowId !== record.workflowId) {
    blockers.push("worker_binding_registry_worker_workflow_mismatch");
  }
  if (record.workerBinding.harnessActivationId !== record.activationId) {
    blockers.push("worker_binding_registry_worker_activation_mismatch");
  }
  if (record.workerBinding.harnessHash !== record.harnessHash) {
    blockers.push("worker_binding_registry_worker_hash_mismatch");
  }
  if (record.workerBinding.executionMode !== "live") {
    blockers.push("worker_binding_registry_worker_not_live");
  }
  if (record.workerBinding.rollbackTarget !== record.rollbackTarget) {
    blockers.push("worker_binding_registry_worker_rollback_mismatch");
  }
  if (record.workerBinding.authorityBindingReady !== true) {
    blockers.push("worker_binding_registry_worker_authority_not_ready");
  }
  if ((record.workerBinding.authorityBindingBlockers ?? []).length > 0) {
    blockers.push("worker_binding_registry_worker_authority_blocked");
  }
  if (
    record.workerBinding.livePromotionReadinessProofId !==
    record.readinessProofId
  ) {
    blockers.push("worker_binding_registry_worker_readiness_proof_mismatch");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      record.workerBinding.requiredInvariantIds,
      record.requiredInvariantIds,
    )
  ) {
    blockers.push("worker_binding_registry_worker_invariant_mismatch");
  }
  if ((record.workerBinding.invariantBlockers ?? []).length > 0) {
    blockers.push("worker_binding_registry_worker_invariant_blocked");
  }
  if (Object.keys(record.componentVersionSet ?? {}).length === 0) {
    blockers.push("worker_binding_registry_component_versions_missing");
  }
  return uniqueStrings(blockers);
}

function componentVersionSetsMatch(
  left: Record<string, string> | null | undefined,
  right: Record<string, string> | null | undefined,
): boolean {
  const leftEntries = Object.entries(left ?? {}).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  const rightEntries = Object.entries(right ?? {}).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  return JSON.stringify(leftEntries) === JSON.stringify(rightEntries);
}

export function makeWorkflowHarnessWorkerAttachRequest(
  record: WorkflowHarnessWorkerBindingRegistryRecord,
  requestedStatus: WorkflowHarnessWorkerAttachStatus = "bound",
): WorkflowHarnessWorkerAttachRequest {
  return {
    schemaVersion: "workflow.harness.worker-attach-request.v1",
    requestId: `harness-worker-attach-request:${record.workflowId}:${record.activationId}:${requestedStatus}`,
    workerId: `harness-worker:${record.workflowId}:${record.activationId}`,
    workflowId: record.workflowId,
    activationId: record.activationId,
    activationHash: record.activationHash,
    harnessHash: record.harnessHash,
    reviewedPackageSnapshotHash: record.reviewedPackageSnapshotHash,
    reviewedWorkflowContentHash: record.reviewedWorkflowContentHash,
    reviewedActivationId: record.reviewedActivationId,
    reviewedHarnessWorkflowId: record.reviewedHarnessWorkflowId,
    reviewedWorkerBindingActivationId:
      record.reviewedWorkerBindingActivationId,
    reviewedRollbackTarget: record.reviewedRollbackTarget,
    reviewedReplayFixtureRefs: record.reviewedReplayFixtureRefs,
    reviewedWorkerHandoffNodeAttemptIds:
      record.reviewedWorkerHandoffNodeAttemptIds,
    reviewedWorkerHandoffReceiptIds: record.reviewedWorkerHandoffReceiptIds,
    reviewedForkMutationCanaryId: record.reviewedForkMutationCanaryId,
    reviewedForkMutationCanaryStatus: record.reviewedForkMutationCanaryStatus,
    reviewedForkMutationCanaryDiffHash: record.reviewedForkMutationCanaryDiffHash,
    reviewedForkMutationCanaryReceiptRefs:
      record.reviewedForkMutationCanaryReceiptRefs ?? [],
    reviewedForkMutationCanaryReplayFixtureRefs:
      record.reviewedForkMutationCanaryReplayFixtureRefs ?? [],
    reviewedForkMutationCanaryNodeAttemptIds:
      record.reviewedForkMutationCanaryNodeAttemptIds ?? [],
    reviewedForkMutationCanaryRollbackTarget:
      record.reviewedForkMutationCanaryRollbackTarget,
    reviewedPolicyPosture: record.reviewedPolicyPosture,
    componentVersionSet: record.componentVersionSet,
    rollbackTarget: record.rollbackTarget,
    readinessProofId: record.readinessProofId,
    rollbackReadinessProofId: record.rollbackReadinessProofId,
    rollbackLiveShadowComparisonGateId:
      record.rollbackLiveShadowComparisonGateId,
    rollbackLiveShadowComparisonGateReady:
      record.rollbackLiveShadowComparisonGateReady,
    rollbackActivationId: record.rollbackActivationId,
    rollbackHarnessHash: record.rollbackHarnessHash,
    rollbackPolicyDecision: record.rollbackPolicyDecision,
    requiredInvariantIds: record.requiredInvariantIds,
    requestedStatus,
  };
}

export function resolveWorkflowHarnessWorkerBinding(
  record: WorkflowHarnessWorkerBindingRegistryRecord,
  request = makeWorkflowHarnessWorkerAttachRequest(record),
): WorkflowHarnessWorkerAttachReceipt {
  const blockers = uniqueStrings([
    ...workflowHarnessWorkerBindingRegistryContractBlockers(record).map(
      (blocker) =>
        blocker === "worker_binding_registry_not_bound"
          ? "worker_attach_registry_not_bound"
          : `worker_attach_${blocker.replace(/^worker_binding_registry_/, "")}`,
    ),
  ]);
  if (request.schemaVersion !== "workflow.harness.worker-attach-request.v1") {
    blockers.push("worker_attach_request_schema_mismatch");
  }
  if (request.workflowId !== record.workflowId) {
    blockers.push("worker_attach_workflow_mismatch");
  }
  if (request.activationId !== record.activationId) {
    blockers.push("worker_attach_activation_mismatch");
  }
  if (request.activationHash !== record.activationHash) {
    blockers.push("worker_attach_activation_hash_mismatch");
  }
  if (request.harnessHash !== record.harnessHash) {
    blockers.push("worker_attach_harness_hash_mismatch");
  }
  blockers.push(
    ...workflowHarnessReviewedPackageSnapshotBlockers(
      "worker_attach",
      request,
    ),
  );
  if (!workflowHarnessReviewedPackageSnapshotsMatch(request, record)) {
    blockers.push("worker_attach_reviewed_package_snapshot_mismatch");
  }
  if (request.reviewedWorkflowContentHash !== record.reviewedWorkflowContentHash) {
    blockers.push("worker_attach_reviewed_package_workflow_hash_mismatch");
  }
  if (request.reviewedActivationId !== record.reviewedActivationId) {
    blockers.push("worker_attach_reviewed_package_activation_mismatch");
  }
  if (request.reviewedHarnessWorkflowId !== record.reviewedHarnessWorkflowId) {
    blockers.push("worker_attach_reviewed_package_workflow_id_mismatch");
  }
  if (
    request.reviewedWorkerBindingActivationId !==
    record.reviewedWorkerBindingActivationId
  ) {
    blockers.push("worker_attach_reviewed_package_worker_binding_mismatch");
  }
  if (request.reviewedRollbackTarget !== record.reviewedRollbackTarget) {
    blockers.push("worker_attach_reviewed_package_rollback_target_mismatch");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.reviewedReplayFixtureRefs,
      record.reviewedReplayFixtureRefs,
    )
  ) {
    blockers.push("worker_attach_reviewed_package_replay_fixture_mismatch");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.reviewedWorkerHandoffNodeAttemptIds,
      record.reviewedWorkerHandoffNodeAttemptIds,
    )
  ) {
    blockers.push("worker_attach_reviewed_package_worker_attempt_mismatch");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.reviewedWorkerHandoffReceiptIds,
      record.reviewedWorkerHandoffReceiptIds,
    )
  ) {
    blockers.push("worker_attach_reviewed_package_worker_receipt_mismatch");
  }
  if (request.reviewedPolicyPosture !== record.reviewedPolicyPosture) {
    blockers.push("worker_attach_reviewed_package_policy_posture_mismatch");
  }
  if (
    request.reviewedForkMutationCanaryId !==
    record.reviewedForkMutationCanaryId
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_mismatch",
    );
  }
  if (
    request.reviewedForkMutationCanaryStatus !==
    record.reviewedForkMutationCanaryStatus
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_status_mismatch",
    );
  }
  if (
    request.reviewedForkMutationCanaryDiffHash !==
    record.reviewedForkMutationCanaryDiffHash
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_diff_mismatch",
    );
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.reviewedForkMutationCanaryReceiptRefs,
      record.reviewedForkMutationCanaryReceiptRefs,
    )
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_receipt_mismatch",
    );
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.reviewedForkMutationCanaryReplayFixtureRefs,
      record.reviewedForkMutationCanaryReplayFixtureRefs,
    )
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_replay_mismatch",
    );
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.reviewedForkMutationCanaryNodeAttemptIds,
      record.reviewedForkMutationCanaryNodeAttemptIds,
    )
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_attempt_mismatch",
    );
  }
  if (
    request.reviewedForkMutationCanaryRollbackTarget !==
    record.reviewedForkMutationCanaryRollbackTarget
  ) {
    blockers.push(
      "worker_attach_reviewed_package_fork_mutation_canary_rollback_mismatch",
    );
  }
  if (
    !componentVersionSetsMatch(
      request.componentVersionSet,
      record.componentVersionSet,
    )
  ) {
    blockers.push("worker_attach_component_version_set_mismatch");
  }
  if (!request.rollbackTarget) {
    blockers.push("worker_attach_rollback_target_missing");
  }
  if (request.rollbackTarget !== record.rollbackTarget) {
    blockers.push("worker_attach_rollback_target_mismatch");
  }
  if (!request.readinessProofId) {
    blockers.push("worker_attach_readiness_proof_missing");
  }
  if (request.readinessProofId !== record.readinessProofId) {
    blockers.push("worker_attach_readiness_proof_mismatch");
  }
  if (!request.rollbackReadinessProofId) {
    blockers.push("worker_attach_rollback_readiness_proof_missing");
  }
  if (
    request.rollbackReadinessProofId !== record.readinessProofId ||
    record.rollbackReadinessProofId !== record.readinessProofId
  ) {
    blockers.push("worker_attach_rollback_readiness_proof_mismatch");
  }
  if (
    !request.rollbackLiveShadowComparisonGateId ||
    !record.rollbackLiveShadowComparisonGateId
  ) {
    blockers.push("worker_attach_rollback_live_shadow_gate_missing");
  }
  if (
    request.rollbackLiveShadowComparisonGateId !==
      record.rollbackLiveShadowComparisonGateId ||
    record.workerBinding.liveShadowComparisonGateId !==
      record.rollbackLiveShadowComparisonGateId
  ) {
    blockers.push("worker_attach_rollback_live_shadow_gate_mismatch");
  }
  if (
    request.rollbackLiveShadowComparisonGateReady !== true ||
    record.rollbackLiveShadowComparisonGateReady !== true ||
    record.workerBinding.liveShadowComparisonGateReady !== true
  ) {
    blockers.push("worker_attach_rollback_live_shadow_gate_not_ready");
  }
  if (
    request.rollbackActivationId !== record.activationId ||
    record.rollbackActivationId !== record.activationId
  ) {
    blockers.push("worker_attach_rollback_activation_mismatch");
  }
  if (
    request.rollbackHarnessHash !== record.harnessHash ||
    record.rollbackHarnessHash !== record.harnessHash
  ) {
    blockers.push("worker_attach_rollback_harness_hash_mismatch");
  }
  if (
    request.rollbackPolicyDecision !==
      "allow_default_harness_worker_rollback_from_live_shadow_gate" ||
    record.rollbackPolicyDecision !==
      "allow_default_harness_worker_rollback_from_live_shadow_gate" ||
    record.workerBinding.rollbackPolicyDecision !==
      "allow_default_harness_worker_rollback_from_live_shadow_gate"
  ) {
    blockers.push("worker_attach_rollback_policy_not_allowed");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      request.requiredInvariantIds,
      record.requiredInvariantIds,
    )
  ) {
    blockers.push("worker_attach_required_invariant_mismatch");
  }
  if (
    !workflowHarnessRequiredInvariantIdsPresent(record.requiredInvariantIds)
  ) {
    blockers.push(
      "worker_attach_reviewed_import_activation_apply_invariant_missing",
    );
  }
  if ((record.invariantBlockers ?? []).length > 0) {
    blockers.push("worker_attach_invariant_blocked");
  }
  if (record.bindingStatus !== "bound") {
    blockers.push("worker_attach_registry_not_bound");
  }
  if ((record.blockers ?? []).length > 0) {
    blockers.push("worker_attach_registry_blocked");
  }
  if (!record.canaryResultId?.endsWith(":passed")) {
    blockers.push("worker_attach_canary_not_passed");
  }
  if (record.workerBinding.executionMode !== "live") {
    blockers.push("worker_attach_worker_not_live");
  }
  if (record.workerBinding.rollbackTarget !== record.rollbackTarget) {
    blockers.push("worker_attach_worker_rollback_mismatch");
  }
  if (record.workerBinding.authorityBindingReady !== true) {
    blockers.push("worker_attach_authority_not_ready");
  }
  if ((record.workerBinding.authorityBindingBlockers ?? []).length > 0) {
    blockers.push("worker_attach_authority_blocked");
  }
  if (
    record.workerBinding.livePromotionReadinessProofId !==
    record.readinessProofId
  ) {
    blockers.push("worker_attach_worker_readiness_proof_mismatch");
  }
  if (
    !workflowHarnessInvariantSetsMatch(
      record.workerBinding.requiredInvariantIds,
      record.requiredInvariantIds,
    )
  ) {
    blockers.push("worker_attach_worker_invariant_mismatch");
  }
  if ((record.workerBinding.invariantBlockers ?? []).length > 0) {
    blockers.push("worker_attach_worker_invariant_blocked");
  }
  const accepted = uniqueStrings(blockers).length === 0;
  const attachStatus: WorkflowHarnessWorkerAttachStatus = accepted
    ? request.requestedStatus === "resumed" ||
      request.requestedStatus === "rolled_back"
      ? request.requestedStatus
      : "bound"
    : record.bindingStatus === "projection"
      ? "unbound"
      : record.bindingStatus === "canary"
        ? "canary"
        : "blocked";
  const dedupedBlockers = uniqueStrings(blockers).sort();
  return {
    schemaVersion: "workflow.harness.worker-attach-receipt.v1",
    receiptId: `harness-worker-attach-receipt:${request.workerId}:${record.registryRecordId}:${attachStatus}`,
    workerId: request.workerId,
    workflowId: request.workflowId,
    activationId: request.activationId,
    activationHash: request.activationHash,
    harnessHash: request.harnessHash,
    reviewedPackageSnapshotHash: request.reviewedPackageSnapshotHash,
    reviewedWorkflowContentHash: request.reviewedWorkflowContentHash,
    reviewedActivationId: request.reviewedActivationId,
    reviewedHarnessWorkflowId: request.reviewedHarnessWorkflowId,
    reviewedWorkerBindingActivationId:
      request.reviewedWorkerBindingActivationId,
    reviewedRollbackTarget: request.reviewedRollbackTarget,
    reviewedReplayFixtureRefs: request.reviewedReplayFixtureRefs,
    reviewedWorkerHandoffNodeAttemptIds:
      request.reviewedWorkerHandoffNodeAttemptIds,
    reviewedWorkerHandoffReceiptIds: request.reviewedWorkerHandoffReceiptIds,
    reviewedForkMutationCanaryId: request.reviewedForkMutationCanaryId,
    reviewedForkMutationCanaryStatus: request.reviewedForkMutationCanaryStatus,
    reviewedForkMutationCanaryDiffHash: request.reviewedForkMutationCanaryDiffHash,
    reviewedForkMutationCanaryReceiptRefs:
      request.reviewedForkMutationCanaryReceiptRefs ?? [],
    reviewedForkMutationCanaryReplayFixtureRefs:
      request.reviewedForkMutationCanaryReplayFixtureRefs ?? [],
    reviewedForkMutationCanaryNodeAttemptIds:
      request.reviewedForkMutationCanaryNodeAttemptIds ?? [],
    reviewedForkMutationCanaryRollbackTarget:
      request.reviewedForkMutationCanaryRollbackTarget,
    reviewedPolicyPosture: request.reviewedPolicyPosture,
    componentVersionSet: request.componentVersionSet,
    rollbackTarget: request.rollbackTarget,
    rollbackAvailable:
      request.rollbackTarget === record.rollbackTarget &&
      !!record.rollbackTarget,
    readinessProofId: request.readinessProofId,
    rollbackReadinessProofId: request.rollbackReadinessProofId,
    rollbackLiveShadowComparisonGateId:
      request.rollbackLiveShadowComparisonGateId,
    rollbackLiveShadowComparisonGateReady:
      request.rollbackLiveShadowComparisonGateReady === true &&
      record.rollbackLiveShadowComparisonGateReady === true,
    rollbackActivationId: request.rollbackActivationId,
    rollbackHarnessHash: request.rollbackHarnessHash,
    rollbackPolicyDecision: request.rollbackPolicyDecision,
    registryRecordId: record.registryRecordId,
    bindingStatus: record.bindingStatus,
    attachStatus,
    accepted,
    blockers: dedupedBlockers,
    workerBinding: record.workerBinding,
    policyDecision: accepted
      ? "allow_harness_worker_attach"
      : "block_harness_worker_attach",
    requiredInvariantIds: record.requiredInvariantIds,
    invariantBlockers: uniqueStrings([
      ...(record.invariantBlockers ?? []),
      ...(record.workerBinding.invariantBlockers ?? []),
    ]),
    evidenceRefs: uniqueStrings([
      record.registryRecordId,
      record.readinessProofId,
      record.rollbackReadinessProofId,
      record.rollbackLiveShadowComparisonGateId,
      record.rollbackActivationId,
      record.rollbackHarnessHash,
      record.canaryResultId,
      record.reviewedPackageSnapshotHash,
      record.reviewedWorkflowContentHash,
      record.reviewedActivationId,
      record.reviewedHarnessWorkflowId,
      record.reviewedWorkerBindingActivationId,
      record.reviewedRollbackTarget,
      ...(record.reviewedReplayFixtureRefs ?? []),
      ...(record.reviewedWorkerHandoffNodeAttemptIds ?? []),
      ...(record.reviewedWorkerHandoffReceiptIds ?? []),
      record.reviewedForkMutationCanaryId,
      record.reviewedForkMutationCanaryStatus,
      record.reviewedForkMutationCanaryDiffHash,
      ...(record.reviewedForkMutationCanaryReceiptRefs ?? []),
      ...(record.reviewedForkMutationCanaryReplayFixtureRefs ?? []),
      ...(record.reviewedForkMutationCanaryNodeAttemptIds ?? []),
      record.reviewedForkMutationCanaryRollbackTarget,
    ]),
    createdAtMs: record.createdAtMs,
  };
}

export function workflowHarnessWorkerAttachBlockers(
  receipt: WorkflowHarnessWorkerAttachReceipt | null | undefined,
): string[] {
  if (!receipt) return ["worker_attach_receipt_missing"];
  const blockers = uniqueStrings(receipt.blockers ?? []);
  if (receipt.schemaVersion !== "workflow.harness.worker-attach-receipt.v1") {
    blockers.push("worker_attach_receipt_schema_mismatch");
  }
  if (receipt.accepted !== true) {
    blockers.push("worker_attach_not_accepted");
  }
  if (
    receipt.attachStatus !== "bound" &&
    receipt.attachStatus !== "resumed" &&
    receipt.attachStatus !== "rolled_back"
  ) {
    blockers.push("worker_attach_not_bound");
  }
  return uniqueStrings(blockers);
}

export function makeWorkflowHarnessWorkerAttachLifecycle(
  record: WorkflowHarnessWorkerBindingRegistryRecord,
  options: { createdAtMs?: number } = {},
): WorkflowHarnessWorkerAttachLifecycleEvent[] {
  return [
    { phase: "attach" as const, requestedStatus: "bound" as const },
    { phase: "resume" as const, requestedStatus: "resumed" as const },
    { phase: "rollback" as const, requestedStatus: "rolled_back" as const },
  ].map(({ phase, requestedStatus }, sequence) => {
    const receipt = resolveWorkflowHarnessWorkerBinding(
      record,
      makeWorkflowHarnessWorkerAttachRequest(record, requestedStatus),
    );
    const attemptId = `harness-worker-attach:attempt:${phase}:${record.workflowId}:${record.activationId}`;
    return {
      schemaVersion: "workflow.harness.worker-attach-lifecycle.v1",
      eventId: `harness-worker-attach-lifecycle:${phase}:${record.workflowId}:${record.activationId}`,
      sequence,
      phase,
      attemptId,
      workflowNodeId: "harness.handoff_bridge",
      componentKind: "handoff_bridge",
      attachStatus: receipt.attachStatus,
      receiptId: receipt.receiptId,
      receipt,
      registryRecordId: record.registryRecordId,
      accepted: receipt.accepted,
      rollbackAvailable: receipt.rollbackAvailable,
      rollbackReadinessProofId: receipt.rollbackReadinessProofId,
      rollbackLiveShadowComparisonGateId:
        receipt.rollbackLiveShadowComparisonGateId,
      rollbackLiveShadowComparisonGateReady:
        receipt.rollbackLiveShadowComparisonGateReady,
      rollbackActivationId: receipt.rollbackActivationId,
      rollbackHarnessHash: receipt.rollbackHarnessHash,
      rollbackPolicyDecision: receipt.rollbackPolicyDecision,
      policyDecision: receipt.policyDecision,
      blockers: receipt.blockers,
      requiredInvariantIds: receipt.requiredInvariantIds,
      invariantBlockers: receipt.invariantBlockers,
      evidenceRefs: receipt.evidenceRefs,
      createdAtMs: options.createdAtMs ?? record.createdAtMs,
    };
  });
}

export function workflowHarnessWorkerAttachLifecycleComplete(
  lifecycle:
    | Array<WorkflowHarnessWorkerAttachLifecycleEvent>
    | null
    | undefined,
): boolean {
  if (!Array.isArray(lifecycle)) return false;
  const statuses = new Set(
    lifecycle
      .filter((event) => event.accepted === true && event.blockers.length === 0)
      .map((event) => event.attachStatus),
  );
  return (
    statuses.has("bound") &&
    statuses.has("resumed") &&
    statuses.has("rolled_back")
  );
}

export function makeWorkflowHarnessWorkerSessionRecord(
  record: WorkflowHarnessWorkerBindingRegistryRecord,
  lifecycle: Array<WorkflowHarnessWorkerAttachLifecycleEvent>,
  options: { sessionId?: string; createdAtMs?: number } = {},
): WorkflowHarnessWorkerSessionRecord {
  const sessionId = options.sessionId ?? "workflow-harness-session";
  const attachEvent = lifecycle.find((event) => event.phase === "attach");
  const resumeEvent = lifecycle.find((event) => event.phase === "resume");
  const rollbackEvent = lifecycle.find((event) => event.phase === "rollback");
  const blockers = uniqueStrings([
    ...(lifecycle.length >= 3 ? [] : ["worker_session_lifecycle_incomplete"]),
    ...(attachEvent?.accepted === true &&
    attachEvent.blockers.length === 0 &&
    attachEvent.attachStatus === "bound"
      ? []
      : ["worker_session_attach_not_bound"]),
    ...(resumeEvent?.accepted === true &&
    resumeEvent.blockers.length === 0 &&
    resumeEvent.attachStatus === "resumed"
      ? []
      : ["worker_session_resume_not_resolved"]),
    ...(rollbackEvent?.accepted === true &&
    rollbackEvent.blockers.length === 0 &&
    rollbackEvent.attachStatus === "rolled_back" &&
    rollbackEvent.rollbackAvailable === true
      ? []
      : ["worker_session_rollback_not_ready"]),
    ...lifecycle.flatMap((event) => [
      ...(event.registryRecordId === record.registryRecordId
        ? []
        : ["worker_session_registry_record_mismatch"]),
      ...(event.accepted ? [] : ["worker_session_lifecycle_event_blocked"]),
      ...(event.blockers ?? []),
      ...(event.invariantBlockers ?? []),
    ]),
    ...(workflowHarnessRequiredInvariantIdsPresent(record.requiredInvariantIds)
      ? []
      : ["worker_session_reviewed_import_activation_apply_invariant_missing"]),
    ...(record.rollbackReadinessProofId === record.readinessProofId
      ? []
      : ["worker_session_rollback_readiness_proof_mismatch"]),
    ...(record.rollbackLiveShadowComparisonGateId
      ? []
      : ["worker_session_rollback_live_shadow_gate_missing"]),
    ...(record.rollbackLiveShadowComparisonGateReady
      ? []
      : ["worker_session_rollback_live_shadow_gate_not_ready"]),
    ...(record.rollbackActivationId === record.activationId
      ? []
      : ["worker_session_rollback_activation_mismatch"]),
    ...(record.rollbackHarnessHash === record.harnessHash
      ? []
      : ["worker_session_rollback_harness_hash_mismatch"]),
    ...(record.rollbackPolicyDecision ===
    "allow_default_harness_worker_rollback_from_live_shadow_gate"
      ? []
      : ["worker_session_rollback_policy_not_allowed"]),
    ...(record.invariantBlockers ?? []),
    ...(record.workerBinding.invariantBlockers ?? []),
  ]).sort();
  const accepted = blockers.length === 0;
  const resumed =
    resumeEvent?.attachStatus === "resumed" && resumeEvent.accepted;
  const rollbackAvailable =
    rollbackEvent?.accepted === true &&
    rollbackEvent.rollbackAvailable === true;
  const rollbackTargetReady = rollbackAvailable && !!record.rollbackTarget;
  const currentStatus = !accepted
    ? "blocked"
    : rollbackTargetReady
      ? "rollback_ready"
      : resumed
        ? "resumed"
        : "attached";
  const currentEvent = rollbackTargetReady
    ? rollbackEvent
    : resumed
      ? resumeEvent
      : attachEvent;
  const workerId =
    attachEvent?.receipt.workerId ??
    lifecycle[0]?.receipt.workerId ??
    makeWorkflowHarnessWorkerAttachRequest(record).workerId;
  const sessionRecordId = `harness-worker-session:${record.workflowId}:${record.activationId}:${record.activationHash}:${workerId}:${sessionId}`;
  const lifecycleEventIds = lifecycle.map((event) => event.eventId);
  const lifecycleAttemptIds = lifecycle.map((event) => event.attemptId);
  const receiptIds = lifecycle.map((event) => event.receiptId);
  const requiredInvariantIds = uniqueStrings(record.requiredInvariantIds ?? []);
  const invariantBlockers = uniqueStrings([
    ...(record.invariantBlockers ?? []),
    ...(record.workerBinding.invariantBlockers ?? []),
    ...lifecycle.flatMap((event) => event.invariantBlockers ?? []),
  ]);
  const persistenceBlockers = accepted ? [] : blockers;
  const launchAuthorityBlockers = accepted ? [] : blockers;
  const rollbackHandoffBlockers = accepted ? [] : blockers;
  return {
    schemaVersion: "workflow.harness.worker-session.v1",
    sessionRecordId,
    sessionId,
    workerId,
    workflowId: record.workflowId,
    activationId: record.activationId,
    activationHash: record.activationHash,
    harnessHash: record.harnessHash,
    componentVersionSet: record.componentVersionSet,
    rollbackTarget: record.rollbackTarget,
    readinessProofId: record.readinessProofId,
    rollbackReadinessProofId: record.rollbackReadinessProofId,
    rollbackLiveShadowComparisonGateId:
      record.rollbackLiveShadowComparisonGateId,
    rollbackLiveShadowComparisonGateReady:
      record.rollbackLiveShadowComparisonGateReady,
    rollbackActivationId: record.rollbackActivationId,
    rollbackHarnessHash: record.rollbackHarnessHash,
    rollbackPolicyDecision: record.rollbackPolicyDecision,
    registryRecordId: record.registryRecordId,
    currentStatus,
    currentEventId: currentEvent?.eventId,
    currentAttemptId: currentEvent?.attemptId,
    currentReceiptId: currentEvent?.receiptId,
    attachEventId: attachEvent?.eventId,
    resumeEventId: resumeEvent?.eventId,
    rollbackEventId: rollbackEvent?.eventId,
    lifecycleEventIds,
    lifecycleAttemptIds,
    receiptIds,
    lifecycleStatuses: lifecycle.map((event) => event.attachStatus),
    resumed,
    rollbackAvailable,
    rollbackTargetReady,
    accepted,
    blockers,
    policyDecision: accepted
      ? "allow_harness_worker_session"
      : "block_harness_worker_session",
    requiredInvariantIds,
    invariantBlockers,
    evidenceRefs: uniqueStrings([
      record.registryRecordId,
      record.readinessProofId,
      record.rollbackReadinessProofId,
      record.rollbackLiveShadowComparisonGateId,
      record.rollbackActivationId,
      record.rollbackHarnessHash,
      ...lifecycleEventIds,
      ...receiptIds,
    ]),
    persistenceKey: `agent::harness_worker_session::${sessionId}`,
    recordPersistenceKey: `agent::harness_worker_session_record::${sessionRecordId}`,
    persistedInRuntimeCheckpoint: accepted,
    restoredFromPersistedSession: accepted,
    runtimeCheckpointSource:
      "runtime_state_access_harness_worker_session_record",
    persistenceBlockers,
    launchAuthorityReady: accepted,
    launchAuthorityBlockers,
    launchAuthorityInvariantIds: requiredInvariantIds,
    launchAuthorityInvariantBlockers: invariantBlockers,
    launchAuthoritySource: "persisted_harness_worker_session_record",
    rollbackHandoffReady: accepted,
    rollbackHandoffBlockers,
    rollbackHandoffTarget: record.rollbackTarget,
    createdAtMs: options.createdAtMs ?? record.createdAtMs,
  };
}

export function workflowHarnessWorkerSessionBlockers(
  session: WorkflowHarnessWorkerSessionRecord | null | undefined,
): string[] {
  if (!session) return ["worker_session_record_missing"];
  const blockers = uniqueStrings(session.blockers ?? []);
  if (session.schemaVersion !== "workflow.harness.worker-session.v1") {
    blockers.push("worker_session_schema_mismatch");
  }
  if (session.accepted !== true) {
    blockers.push("worker_session_not_accepted");
  }
  if (session.currentStatus !== "rollback_ready") {
    blockers.push("worker_session_not_rollback_ready");
  }
  if (session.resumed !== true) {
    blockers.push("worker_session_not_resumed");
  }
  if (session.rollbackTargetReady !== true) {
    blockers.push("worker_session_rollback_target_not_ready");
  }
  if (session.rollbackReadinessProofId !== session.readinessProofId) {
    blockers.push("worker_session_rollback_readiness_proof_mismatch");
  }
  if (!session.rollbackLiveShadowComparisonGateId) {
    blockers.push("worker_session_rollback_live_shadow_gate_missing");
  }
  if (session.rollbackLiveShadowComparisonGateReady !== true) {
    blockers.push("worker_session_rollback_live_shadow_gate_not_ready");
  }
  if (session.rollbackActivationId !== session.activationId) {
    blockers.push("worker_session_rollback_activation_mismatch");
  }
  if (session.rollbackHarnessHash !== session.harnessHash) {
    blockers.push("worker_session_rollback_harness_hash_mismatch");
  }
  if (
    session.rollbackPolicyDecision !==
    "allow_default_harness_worker_rollback_from_live_shadow_gate"
  ) {
    blockers.push("worker_session_rollback_policy_not_allowed");
  }
  if ((session.lifecycleEventIds ?? []).length < 3) {
    blockers.push("worker_session_lifecycle_events_missing");
  }
  if (session.persistedInRuntimeCheckpoint !== true) {
    blockers.push("worker_session_not_persisted");
  }
  if (session.restoredFromPersistedSession !== true) {
    blockers.push("worker_session_not_restored");
  }
  if ((session.persistenceBlockers ?? []).length > 0) {
    blockers.push("worker_session_persistence_blocked");
  }
  if (session.launchAuthorityReady !== true) {
    blockers.push("worker_session_launch_authority_not_ready");
  }
  if ((session.launchAuthorityBlockers ?? []).length > 0) {
    blockers.push("worker_session_launch_authority_blocked");
  }
  if (
    !workflowHarnessRequiredInvariantIdsPresent(
      session.launchAuthorityInvariantIds,
    )
  ) {
    blockers.push(
      "worker_session_reviewed_import_activation_apply_invariant_missing",
    );
  }
  if ((session.launchAuthorityInvariantBlockers ?? []).length > 0) {
    blockers.push("worker_session_launch_invariant_blocked");
  }
  if (session.rollbackHandoffReady !== true) {
    blockers.push("worker_session_rollback_handoff_not_ready");
  }
  if ((session.rollbackHandoffBlockers ?? []).length > 0) {
    blockers.push("worker_session_rollback_handoff_blocked");
  }
  return uniqueStrings(blockers);
}

export function makeWorkflowHarnessWorkerLaunchEnvelope(
  session: WorkflowHarnessWorkerSessionRecord,
  phase: WorkflowHarnessWorkerLaunchPhase,
  options: { createdAtMs?: number } = {},
): WorkflowHarnessWorkerLaunchEnvelope {
  const blockers = uniqueStrings([
    ...(session.schemaVersion === "workflow.harness.worker-session.v1"
      ? []
      : ["worker_launch_session_schema_mismatch"]),
    ...(session.sessionRecordId
      ? []
      : ["worker_launch_session_record_missing"]),
    ...(session.sessionId ? [] : ["worker_launch_session_id_missing"]),
    ...(session.workerId ? [] : ["worker_launch_worker_id_missing"]),
    ...(session.accepted ? [] : ["worker_launch_session_not_accepted"]),
    ...(session.blockers ?? []),
    ...(session.persistedInRuntimeCheckpoint
      ? []
      : ["worker_launch_session_not_persisted"]),
    ...(session.restoredFromPersistedSession
      ? []
      : ["worker_launch_session_not_restored"]),
    ...(session.persistenceBlockers ?? []),
    ...(session.launchAuthorityReady
      ? []
      : ["worker_launch_authority_not_ready"]),
    ...(session.launchAuthorityBlockers ?? []),
    ...(session.launchAuthorityInvariantBlockers ?? []),
    ...(workflowHarnessRequiredInvariantIdsPresent(
      session.launchAuthorityInvariantIds,
    )
      ? []
      : ["worker_launch_reviewed_import_activation_apply_invariant_missing"]),
    ...(session.launchAuthoritySource ===
    "persisted_harness_worker_session_record"
      ? []
      : ["worker_launch_authority_source_invalid"]),
    ...(session.rollbackReadinessProofId === session.readinessProofId
      ? []
      : ["worker_launch_rollback_readiness_proof_mismatch"]),
    ...(session.rollbackLiveShadowComparisonGateId
      ? []
      : ["worker_launch_rollback_live_shadow_gate_missing"]),
    ...(session.rollbackLiveShadowComparisonGateReady
      ? []
      : ["worker_launch_rollback_live_shadow_gate_not_ready"]),
    ...(session.rollbackActivationId === session.activationId
      ? []
      : ["worker_launch_rollback_activation_mismatch"]),
    ...(session.rollbackHarnessHash === session.harnessHash
      ? []
      : ["worker_launch_rollback_harness_hash_mismatch"]),
    ...(session.rollbackPolicyDecision ===
    "allow_default_harness_worker_rollback_from_live_shadow_gate"
      ? []
      : ["worker_launch_rollback_policy_not_allowed"]),
    ...(phase === "resume" && !session.resumed
      ? ["worker_launch_resume_not_resolved"]
      : []),
    ...(phase === "rollback" && !session.rollbackAvailable
      ? ["worker_launch_rollback_not_available"]
      : []),
    ...(phase === "rollback" && !session.rollbackTargetReady
      ? ["worker_launch_rollback_target_not_ready"]
      : []),
    ...(phase === "rollback" && !session.rollbackHandoffReady
      ? ["worker_launch_rollback_handoff_not_ready"]
      : []),
    ...(phase === "rollback" &&
    session.rollbackHandoffTarget !== session.rollbackTarget
      ? ["worker_launch_rollback_target_mismatch"]
      : []),
    ...(phase === "rollback" ? (session.rollbackHandoffBlockers ?? []) : []),
  ]).sort();
  const accepted = blockers.length === 0;
  return {
    schemaVersion: "workflow.harness.worker-launch-envelope.v1",
    envelopeId: `harness-worker-launch-envelope:${phase}:${session.sessionRecordId}`,
    phase,
    workflowNodeId: "harness.handoff_bridge",
    componentKind: "handoff_bridge",
    sessionRecordId: session.sessionRecordId,
    sessionId: session.sessionId,
    workerId: session.workerId,
    workflowId: session.workflowId,
    activationId: session.activationId,
    activationHash: session.activationHash,
    harnessHash: session.harnessHash,
    componentVersionSet: session.componentVersionSet,
    registryRecordId: session.registryRecordId,
    readinessProofId: session.readinessProofId,
    rollbackReadinessProofId: session.rollbackReadinessProofId,
    rollbackLiveShadowComparisonGateId:
      session.rollbackLiveShadowComparisonGateId,
    rollbackLiveShadowComparisonGateReady:
      session.rollbackLiveShadowComparisonGateReady,
    rollbackActivationId: session.rollbackActivationId,
    rollbackHarnessHash: session.rollbackHarnessHash,
    rollbackPolicyDecision: session.rollbackPolicyDecision,
    rollbackTarget: session.rollbackTarget,
    persistenceKey: session.persistenceKey,
    recordPersistenceKey: session.recordPersistenceKey,
    launchAuthoritySource: session.launchAuthoritySource,
    launchAuthorityReady: session.launchAuthorityReady,
    launchAuthorityInvariantIds: session.launchAuthorityInvariantIds,
    launchAuthorityInvariantBlockers: session.launchAuthorityInvariantBlockers,
    rollbackHandoffReady: session.rollbackHandoffReady,
    accepted,
    blockers,
    policyDecision: accepted
      ? "allow_harness_worker_launch_envelope"
      : "block_harness_worker_launch_envelope",
    evidenceRefs: uniqueStrings([
      session.sessionRecordId,
      session.registryRecordId,
      session.readinessProofId,
      session.rollbackReadinessProofId,
      session.rollbackLiveShadowComparisonGateId,
      session.rollbackActivationId,
      session.rollbackHarnessHash,
      ...session.lifecycleEventIds,
      ...session.receiptIds,
    ]),
    createdAtMs: options.createdAtMs ?? session.createdAtMs,
  };
}

export function resolveWorkflowHarnessWorkerHandoffReceipt(
  session: WorkflowHarnessWorkerSessionRecord,
  envelope: WorkflowHarnessWorkerLaunchEnvelope,
  options: { createdAtMs?: number } = {},
): WorkflowHarnessWorkerHandoffReceipt {
  const blockers = uniqueStrings([
    ...(envelope.schemaVersion === "workflow.harness.worker-launch-envelope.v1"
      ? []
      : ["worker_handoff_envelope_schema_mismatch"]),
    ...(envelope.accepted ? [] : ["worker_handoff_envelope_not_accepted"]),
    ...(envelope.blockers ?? []),
    ...(envelope.sessionRecordId === session.sessionRecordId
      ? []
      : ["worker_handoff_session_record_mismatch"]),
    ...(envelope.sessionId === session.sessionId
      ? []
      : ["worker_handoff_session_id_mismatch"]),
    ...(envelope.workerId === session.workerId
      ? []
      : ["worker_handoff_worker_id_mismatch"]),
    ...(envelope.workflowId === session.workflowId
      ? []
      : ["worker_handoff_workflow_mismatch"]),
    ...(envelope.activationId === session.activationId
      ? []
      : ["worker_handoff_activation_mismatch"]),
    ...(envelope.harnessHash === session.harnessHash
      ? []
      : ["worker_handoff_harness_hash_mismatch"]),
    ...(envelope.readinessProofId === session.readinessProofId
      ? []
      : ["worker_handoff_readiness_proof_mismatch"]),
    ...(envelope.rollbackReadinessProofId === session.rollbackReadinessProofId &&
    session.rollbackReadinessProofId === session.readinessProofId
      ? []
      : ["worker_handoff_rollback_readiness_proof_mismatch"]),
    ...(envelope.rollbackLiveShadowComparisonGateId ===
      session.rollbackLiveShadowComparisonGateId &&
    !!session.rollbackLiveShadowComparisonGateId
      ? []
      : ["worker_handoff_rollback_live_shadow_gate_mismatch"]),
    ...(envelope.rollbackLiveShadowComparisonGateReady === true &&
    session.rollbackLiveShadowComparisonGateReady === true
      ? []
      : ["worker_handoff_rollback_live_shadow_gate_not_ready"]),
    ...(envelope.rollbackActivationId === session.rollbackActivationId &&
    session.rollbackActivationId === session.activationId
      ? []
      : ["worker_handoff_rollback_activation_mismatch"]),
    ...(envelope.rollbackHarnessHash === session.rollbackHarnessHash &&
    session.rollbackHarnessHash === session.harnessHash
      ? []
      : ["worker_handoff_rollback_harness_hash_mismatch"]),
    ...(envelope.rollbackPolicyDecision === session.rollbackPolicyDecision &&
    session.rollbackPolicyDecision ===
      "allow_default_harness_worker_rollback_from_live_shadow_gate"
      ? []
      : ["worker_handoff_rollback_policy_not_allowed"]),
    ...(envelope.launchAuthorityReady
      ? []
      : ["worker_handoff_launch_authority_not_ready"]),
    ...(envelope.launchAuthorityInvariantBlockers ?? []),
    ...(workflowHarnessRequiredInvariantIdsPresent(
      envelope.launchAuthorityInvariantIds,
    )
      ? []
      : ["worker_handoff_reviewed_import_activation_apply_invariant_missing"]),
    ...(envelope.phase === "rollback" && !envelope.rollbackHandoffReady
      ? ["worker_handoff_rollback_not_ready"]
      : []),
  ]).sort();
  const accepted = blockers.length === 0;
  const handoffStatus = !accepted
    ? "blocked"
    : envelope.phase === "rollback"
      ? "rollback_handoff_ready"
      : envelope.phase === "resume"
        ? "resumed"
        : "launched";
  return {
    schemaVersion: "workflow.harness.worker-handoff-receipt.v1",
    receiptId: `harness-worker-handoff-receipt:${envelope.phase}:${session.sessionRecordId}`,
    envelopeId: envelope.envelopeId,
    phase: envelope.phase,
    workflowNodeId: envelope.workflowNodeId,
    componentKind: envelope.componentKind,
    sessionRecordId: session.sessionRecordId,
    sessionId: session.sessionId,
    workerId: session.workerId,
    workflowId: session.workflowId,
    activationId: session.activationId,
    activationHash: session.activationHash,
    harnessHash: session.harnessHash,
    registryRecordId: session.registryRecordId,
    readinessProofId: session.readinessProofId,
    rollbackReadinessProofId: session.rollbackReadinessProofId,
    rollbackLiveShadowComparisonGateId:
      session.rollbackLiveShadowComparisonGateId,
    rollbackLiveShadowComparisonGateReady:
      session.rollbackLiveShadowComparisonGateReady,
    rollbackActivationId: session.rollbackActivationId,
    rollbackHarnessHash: session.rollbackHarnessHash,
    rollbackPolicyDecision: session.rollbackPolicyDecision,
    rollbackTarget: session.rollbackTarget,
    rollbackAvailable: session.rollbackAvailable,
    launchAuthoritySource: session.launchAuthoritySource,
    accepted,
    handoffStatus,
    blockers,
    requiredInvariantIds: envelope.launchAuthorityInvariantIds,
    invariantBlockers: envelope.launchAuthorityInvariantBlockers,
    policyDecision: accepted
      ? "allow_harness_worker_handoff"
      : "block_harness_worker_handoff",
    receiptRefs: uniqueStrings([...session.receiptIds, envelope.envelopeId]),
    evidenceRefs: uniqueStrings([
      ...session.evidenceRefs,
      envelope.envelopeId,
      envelope.rollbackReadinessProofId,
      envelope.rollbackLiveShadowComparisonGateId,
      envelope.rollbackActivationId,
      envelope.rollbackHarnessHash,
      session.sessionRecordId,
    ]),
    createdAtMs: options.createdAtMs ?? envelope.createdAtMs,
  };
}

export function makeWorkflowHarnessWorkerHandoffNodeAttempt(
  receipt: WorkflowHarnessWorkerHandoffReceipt,
  attemptIndex: number,
  options: {
    executionMode?: Extract<WorkflowHarnessExecutionMode, "live" | "gated">;
    startedAtMs?: number;
    durationMs?: number;
  } = {},
): WorkflowHarnessNodeAttemptRecord {
  const component = componentFor("handoff_bridge");
  const executionMode =
    options.executionMode ?? (receipt.accepted ? "live" : "gated");
  const fixtureRef = `harness-worker-handoff:fixture:${receipt.phase}:${receipt.sessionRecordId}`;
  return {
    attemptId: `harness-worker-handoff:attempt:${receipt.phase}:${receipt.sessionRecordId}`,
    harnessWorkflowId: receipt.workflowId,
    harnessActivationId: receipt.activationId,
    harnessHash: receipt.harnessHash,
    workflowNodeId: receipt.workflowNodeId,
    componentId: component.componentId,
    componentKind: "handoff_bridge",
    executionMode,
    readiness: component.readiness,
    attemptIndex,
    status: receipt.accepted ? executionMode : "blocked",
    inputHash: `sha256:worker-handoff-input-${receipt.phase}-${receipt.sessionRecordId}`,
    outputHash: receipt.accepted
      ? `sha256:worker-handoff-output-${receipt.phase}-${receipt.sessionRecordId}`
      : undefined,
    errorClass: receipt.accepted ? undefined : "worker_handoff_blocked",
    policyDecision: receipt.policyDecision,
    startedAtMs: options.startedAtMs ?? receipt.createdAtMs,
    durationMs: options.durationMs,
    receiptIds: uniqueStrings([
      receipt.receiptId,
      receipt.envelopeId,
      ...receipt.receiptRefs,
    ]),
    evidenceRefs: uniqueStrings(receipt.evidenceRefs),
    replay: {
      ...replayEnvelopeFor(component),
      capturesPolicyDecision: true,
      fixtureRef,
    },
  };
}

export function makeWorkflowHarnessWorkerHandoffNodeAttempts(
  receipts: WorkflowHarnessWorkerHandoffReceipt[],
  options: {
    executionMode?: Extract<WorkflowHarnessExecutionMode, "live" | "gated">;
    startedAtMs?: number;
  } = {},
): WorkflowHarnessNodeAttemptRecord[] {
  return receipts.map((receipt, index) =>
    makeWorkflowHarnessWorkerHandoffNodeAttempt(receipt, index + 1, options),
  );
}

function makeWorkflowHarnessForkActivationHandoffProof(options: {
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  componentVersionSet: Record<string, string>;
  rollbackTarget: string;
  workerBinding: WorkflowHarnessWorkerBinding;
  policyPosture?: string | null;
  reviewedPackageSnapshot?: WorkflowHarnessReviewedPackageSnapshotFields | null;
  createdAtMs: number;
}): {
  workerBinding: WorkflowHarnessWorkerBinding;
  workerBindingRegistryRecord: WorkflowHarnessWorkerBindingRegistryRecord;
  workerAttachLifecycle: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerAttachReceipt: WorkflowHarnessWorkerAttachReceipt;
  workerSessionRecord: WorkflowHarnessWorkerSessionRecord;
  workerLaunchEnvelopes: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts: WorkflowHarnessWorkerHandoffReceipt[];
  workerLaunchEnvelopeIds: string[];
  workerHandoffReceiptIds: string[];
  workerHandoffNodeAttempts: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffNodeAttemptIds: string[];
  workerHandoffReplayFixtureRefs: string[];
} {
  const readinessProofId = `harness-fork-activation-readiness:${options.workflowId}:${options.activationId}`;
  const canaryWorkerBinding: WorkflowHarnessWorkerBinding = {
    ...options.workerBinding,
    harnessWorkflowId: options.workflowId,
    harnessActivationId: options.activationId,
    harnessHash: options.harnessHash,
    executionMode: "live",
    source: "fork",
    rollbackTarget: options.rollbackTarget,
    authorityBindingReady: true,
    authorityBindingBlockers: [],
    livePromotionReadinessProofId: readinessProofId,
    liveShadowComparisonGateId:
      DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID,
    liveShadowComparisonGateReady: true,
    rollbackPolicyDecision:
      "allow_default_harness_worker_rollback_from_live_shadow_gate",
    policyDecision: "allow_fork_harness_canary_worker_binding",
    requiredInvariantIds: [
      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
    ],
    invariantBlockers: [],
  };
  const workerId = `harness-worker:${options.workflowId}:${options.activationId}`;
  const sessionRecordId = `harness-worker-session:${options.workflowId}:${options.activationId}:${options.activationHash}:${workerId}:${options.workflowId}`;
  const handoffPhases = ["launch", "resume", "rollback"] as const;
  const reviewedPackageSnapshot = options.reviewedPackageSnapshot ?? {
    reviewedWorkflowContentHash: options.activationHash,
    reviewedActivationId: options.activationId,
    reviewedHarnessWorkflowId: options.workflowId,
    reviewedWorkerBindingActivationId: options.activationId,
    reviewedRollbackTarget: options.rollbackTarget,
    reviewedReplayFixtureRefs: handoffPhases.map(
      (phase) => `harness-worker-handoff:fixture:${phase}:${sessionRecordId}`,
    ),
    reviewedWorkerHandoffNodeAttemptIds: handoffPhases.map(
      (phase) => `harness-worker-handoff:attempt:${phase}:${sessionRecordId}`,
    ),
	    reviewedWorkerHandoffReceiptIds: handoffPhases.map(
	      (phase) =>
	        `harness-worker-handoff-receipt:${phase}:${sessionRecordId}`,
	    ),
    reviewedForkMutationCanaryId: `harness-reviewed-package:fork-mutation-canary:${options.workflowId}:${options.activationId}`,
    reviewedForkMutationCanaryStatus: "passed",
    reviewedForkMutationCanaryDiffHash: stableContentHash({
      kind: "reviewed-fork-mutation-canary",
      workflowId: options.workflowId,
      activationId: options.activationId,
    }),
    reviewedForkMutationCanaryReceiptRefs: [
      `harness-reviewed-package:fork-mutation-canary-receipt:${options.workflowId}:${options.activationId}`,
    ],
    reviewedForkMutationCanaryReplayFixtureRefs: [
      `harness-reviewed-package:fork-mutation-canary-fixture:${options.workflowId}:${options.activationId}`,
    ],
    reviewedForkMutationCanaryNodeAttemptIds: [
      `harness-reviewed-package:fork-mutation-canary-attempt:${options.workflowId}:${options.activationId}`,
    ],
    reviewedForkMutationCanaryRollbackTarget: options.rollbackTarget,
	    reviewedPolicyPosture: options.policyPosture ?? "canary",
    rollbackTarget: options.rollbackTarget,
  };
  const workerBindingRegistryRecord =
    makeWorkflowHarnessWorkerBindingRegistryRecord({
      workflowId: options.workflowId,
      activationId: options.activationId,
      activationHash: options.activationHash,
      harnessHash: options.harnessHash,
      reviewedPackageSnapshotHash:
        reviewedPackageSnapshot.reviewedPackageSnapshotHash,
      reviewedWorkflowContentHash:
        reviewedPackageSnapshot.reviewedWorkflowContentHash,
      reviewedActivationId: reviewedPackageSnapshot.reviewedActivationId,
      reviewedHarnessWorkflowId:
        reviewedPackageSnapshot.reviewedHarnessWorkflowId,
      reviewedWorkerBindingActivationId:
        reviewedPackageSnapshot.reviewedWorkerBindingActivationId,
      reviewedRollbackTarget:
        reviewedPackageSnapshot.reviewedRollbackTarget,
      reviewedReplayFixtureRefs:
        reviewedPackageSnapshot.reviewedReplayFixtureRefs?.filter(
          (ref): ref is string => Boolean(ref),
        ),
      reviewedWorkerHandoffNodeAttemptIds:
        reviewedPackageSnapshot.reviewedWorkerHandoffNodeAttemptIds?.filter(
          (attemptId): attemptId is string => Boolean(attemptId),
        ),
      reviewedWorkerHandoffReceiptIds:
        reviewedPackageSnapshot.reviewedWorkerHandoffReceiptIds?.filter(
          (receiptId): receiptId is string => Boolean(receiptId),
        ),
      reviewedForkMutationCanaryId:
        reviewedPackageSnapshot.reviewedForkMutationCanaryId,
      reviewedForkMutationCanaryStatus:
        reviewedPackageSnapshot.reviewedForkMutationCanaryStatus,
      reviewedForkMutationCanaryDiffHash:
        reviewedPackageSnapshot.reviewedForkMutationCanaryDiffHash,
      reviewedForkMutationCanaryReceiptRefs:
        reviewedPackageSnapshot.reviewedForkMutationCanaryReceiptRefs?.filter(
          (receiptId): receiptId is string => Boolean(receiptId),
        ),
      reviewedForkMutationCanaryReplayFixtureRefs:
        reviewedPackageSnapshot.reviewedForkMutationCanaryReplayFixtureRefs?.filter(
          (fixtureRef): fixtureRef is string => Boolean(fixtureRef),
        ),
      reviewedForkMutationCanaryNodeAttemptIds:
        reviewedPackageSnapshot.reviewedForkMutationCanaryNodeAttemptIds?.filter(
          (attemptId): attemptId is string => Boolean(attemptId),
        ),
      reviewedForkMutationCanaryRollbackTarget:
        reviewedPackageSnapshot.reviewedForkMutationCanaryRollbackTarget,
      reviewedPolicyPosture:
        reviewedPackageSnapshot.reviewedPolicyPosture,
      componentVersionSet: options.componentVersionSet,
      rollbackTarget: options.rollbackTarget,
      readinessProofId,
      canaryResultId: `harness-canary-result:${options.workflowId}:${options.activationId}:passed`,
      policyDecision: "allow_fork_harness_canary_worker_binding",
      bindingStatus: "bound",
      blockers: [],
      requiredInvariantIds: canaryWorkerBinding.requiredInvariantIds,
      invariantBlockers: [],
      workerBinding: canaryWorkerBinding,
      createdAtMs: options.createdAtMs,
    });
  const workerAttachLifecycle = makeWorkflowHarnessWorkerAttachLifecycle(
    workerBindingRegistryRecord,
    { createdAtMs: options.createdAtMs },
  );
  const workerAttachReceipt =
    workerAttachLifecycle.find((event) => event.phase === "attach")?.receipt ??
    workerAttachLifecycle[0].receipt;
  const workerSessionRecord = makeWorkflowHarnessWorkerSessionRecord(
    workerBindingRegistryRecord,
    workerAttachLifecycle,
    {
      sessionId: options.workflowId,
      createdAtMs: options.createdAtMs,
    },
  );
  const workerLaunchEnvelopes = (["launch", "resume", "rollback"] as const).map(
    (phase) =>
      makeWorkflowHarnessWorkerLaunchEnvelope(workerSessionRecord, phase, {
        createdAtMs: options.createdAtMs,
      }),
  );
  const workerHandoffReceipts = workerLaunchEnvelopes.map((envelope) =>
    resolveWorkflowHarnessWorkerHandoffReceipt(workerSessionRecord, envelope, {
      createdAtMs: options.createdAtMs,
    }),
  );
  const workerHandoffNodeAttempts =
    makeWorkflowHarnessWorkerHandoffNodeAttempts(workerHandoffReceipts, {
      executionMode: "gated",
      startedAtMs: options.createdAtMs,
    });
  return {
    workerBinding: canaryWorkerBinding,
    workerBindingRegistryRecord,
    workerAttachLifecycle,
    workerAttachReceipt,
    workerSessionRecord,
    workerLaunchEnvelopes,
    workerHandoffReceipts,
    workerLaunchEnvelopeIds: workerLaunchEnvelopes.map(
      (envelope) => envelope.envelopeId,
    ),
    workerHandoffReceiptIds: workerHandoffReceipts.map(
      (receipt) => receipt.receiptId,
    ),
    workerHandoffNodeAttempts,
    workerHandoffNodeAttemptIds: workerHandoffNodeAttempts.map(
      (attempt) => attempt.attemptId,
    ),
    workerHandoffReplayFixtureRefs: workerHandoffNodeAttempts
      .map((attempt) => attempt.replay.fixtureRef)
      .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef)),
  };
}

function receiptRefsFromEvidenceRefs(
  evidenceRefs: Array<string | null | undefined> = [],
): string[] {
  return uniqueStrings(
    evidenceRefs.filter(
      (reference): reference is string =>
        typeof reference === "string" &&
        reference.startsWith("workflow_restore_canary:"),
    ),
  );
}

function rollbackRestoreCanaryReceiptRefs(
  canary:
    | WorkflowHarnessForkActivationRecord["rollbackRestoreCanary"]
    | null
    | undefined,
): string[] {
  if (!canary) return [];
  return uniqueStrings([
    canary.receiptBindingRef,
    ...receiptRefsFromEvidenceRefs(canary.evidenceRefs),
  ]);
}

export function workflowHarnessForkMutationCanaryRefs(
  canary: WorkflowHarnessForkMutationCanary | null | undefined,
): string[] {
  if (!canary) return [];
  return uniqueStrings([
    canary.canaryId,
    canary.mutationId,
    canary.diffHash,
    canary.proposalId,
    ...canary.receiptRefs,
    ...canary.replayFixtureRefs,
    ...canary.nodeAttemptIds,
    ...canary.evidenceRefs,
  ]);
}

export function workflowHarnessForkMutationCanaryReady(
  canary: WorkflowHarnessForkMutationCanary | null | undefined,
): boolean {
  const nodeAttempts = workflowHarnessForkMutationCanaryNodeAttempts(canary);
  return Boolean(
    canary &&
      canary.schemaVersion === "workflow.harness.fork-mutation-canary.v1" &&
      canary.status === "passed" &&
      canary.canaryStatus === "passed" &&
      canary.rollbackAvailable === true &&
      canary.blockers.length === 0 &&
      canary.receiptRefs.length > 0 &&
      canary.replayFixtureRefs.length > 0 &&
      canary.nodeAttemptIds.length > 0 &&
      nodeAttempts.length > 0 &&
      canary.evidenceRefs.length > 0 &&
      canary.diffHash,
  );
}

export function makeWorkflowHarnessForkMutationCanaryNodeAttempt(
  canary: WorkflowHarnessForkMutationCanary,
  attemptIndex = 1,
): WorkflowHarnessNodeAttemptRecord {
  const component = componentFor("budget_gate");
  const receiptIds = uniqueStrings(canary.receiptRefs);
  const replayFixtureRef =
    canary.replayFixtureRefs[attemptIndex - 1] ?? canary.replayFixtureRefs[0];
  const attemptId =
    canary.nodeAttemptIds[attemptIndex - 1] ??
    canary.nodeAttemptIds[0] ??
    `${canary.canaryId}:attempt:${attemptIndex}`;
  const inputHash = stableContentHash({
    schemaVersion: "workflow.harness.fork-mutation-canary-input.v1",
    mutationId: canary.mutationId,
    mutationKind: canary.mutationKind,
    targetPath: canary.targetPath,
    beforeValue: canary.beforeValue,
    afterValue: canary.afterValue,
    proposalId: canary.proposalId,
  });
  const outputHash = stableContentHash({
    schemaVersion: "workflow.harness.fork-mutation-canary-output.v1",
    canaryId: canary.canaryId,
    diffHash: canary.diffHash,
    status: canary.status,
    canaryStatus: canary.canaryStatus,
    rollbackTarget: canary.rollbackTarget,
  });
  return {
    attemptId,
    harnessWorkflowId: canary.harnessWorkflowId,
    harnessActivationId: canary.rollbackTarget || DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: canary.diffHash,
    workflowNodeId: canary.workflowNodeId,
    componentId: canary.componentId || component.componentId,
    componentKind: "budget_gate",
    executionMode: "gated",
    readiness: component.readiness,
    attemptIndex,
    status: canary.status === "passed" ? "gated" : "blocked",
    inputHash,
    outputHash: canary.status === "passed" ? outputHash : undefined,
    errorClass:
      canary.status === "passed" ? undefined : "fork_mutation_canary_blocked",
    policyDecision: canary.policyDecision,
    startedAtMs: canary.createdAtMs,
    durationMs: canary.status === "passed" ? 1 : undefined,
    receiptIds,
    evidenceRefs: uniqueStrings([
      ...canary.evidenceRefs,
      canary.diffHash,
      canary.rollbackTarget,
    ]),
    replay: {
      ...replayEnvelopeFor(component),
      capturesPolicyDecision: true,
      fixtureRef: replayFixtureRef,
    },
  };
}

export function workflowHarnessForkMutationCanaryNodeAttempts(
  canary: WorkflowHarnessForkMutationCanary | null | undefined,
): WorkflowHarnessNodeAttemptRecord[] {
  if (!canary) return [];
  if (Array.isArray(canary.nodeAttempts) && canary.nodeAttempts.length > 0) {
    return canary.nodeAttempts;
  }
  if (!Array.isArray(canary.nodeAttemptIds) || canary.nodeAttemptIds.length === 0) {
    return [];
  }
  return canary.nodeAttemptIds.map((_, index) =>
    makeWorkflowHarnessForkMutationCanaryNodeAttempt(canary, index + 1),
  );
}

export function makeWorkflowHarnessForkMutationCanary(
  workflow: WorkflowProject,
  options: {
    proposalId: string;
    beforeValue?: string | number;
    afterValue?: string | number;
    nowMs?: number;
    status?: WorkflowHarnessForkMutationCanary["status"];
  },
): WorkflowHarnessForkMutationCanary {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const workflowSlug = slugify(workflowId);
  const beforeValue = String(
    options.beforeValue ?? DEFAULT_AGENT_HARNESS_FORK_MUTATION_BEFORE_VALUE,
  );
  const afterValue = String(
    options.afterValue ?? DEFAULT_AGENT_HARNESS_FORK_MUTATION_AFTER_VALUE,
  );
  const mutationId = `harness-fork-mutation:${workflowSlug}:budget-gate-max-steps`;
  const canaryId = `harness-fork-mutation-canary:${workflowSlug}:budget-gate-max-steps`;
  const diffHash = stableContentHash({
    schemaVersion: "workflow.harness.fork-mutation-diff.v1",
    workflowId,
    mutationKind: "budget_gate_limit",
    mutationScope: "workflow_policy",
    componentId: componentId("budget_gate"),
    workflowNodeId: "harness.budget_gate",
    targetPath: DEFAULT_AGENT_HARNESS_FORK_MUTATION_TARGET_PATH,
    beforeValue,
    afterValue,
  });
  const receiptRefs = [
    `workflow_mutation_canary:receipt:${workflowSlug}:budget_gate_limit`,
  ];
  const replayFixtureRefs = [
    `workflow_mutation_canary:fixture:${workflowSlug}:budget_gate_limit`,
  ];
  const nodeAttemptIds = [
    `workflow_mutation_canary:attempt:${workflowSlug}:budget_gate_limit`,
  ];
  const status = options.status ?? "passed";
  const blockers =
    status === "passed" ? [] : ["harness_fork_mutation_canary_not_passed"];
  const canary: WorkflowHarnessForkMutationCanary = {
    schemaVersion: "workflow.harness.fork-mutation-canary.v1",
    canaryId,
    mutationId,
    mutationKind: "budget_gate_limit",
    mutationScope: "workflow_policy",
    workflowId,
    harnessWorkflowId:
      workflow.metadata.harness?.harnessWorkflowId ?? workflowId,
    componentId: componentId("budget_gate"),
    workflowNodeId: "harness.budget_gate",
    targetPath: DEFAULT_AGENT_HARNESS_FORK_MUTATION_TARGET_PATH,
    beforeValue,
    afterValue,
    diffHash,
    proposalId: options.proposalId,
    status,
    canaryStatus: status === "passed" ? "passed" : "not_run",
    replayFixtureRefs,
    receiptRefs,
    nodeAttemptIds,
    evidenceRefs: uniqueStrings([
      canaryId,
      mutationId,
      diffHash,
      options.proposalId,
      ...receiptRefs,
      ...replayFixtureRefs,
      ...nodeAttemptIds,
    ]),
    policyDecision: "allow_proposal_only_budget_gate_limit_canary",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    blockers,
    createdAtMs: options.nowMs ?? Date.now(),
  };
  return {
    ...canary,
    nodeAttempts: workflowHarnessForkMutationCanaryNodeAttempts(canary),
  };
}

function activationCandidateReceiptRefs(
  candidate: WorkflowHarnessForkActivationCandidate | null | undefined,
): string[] {
  if (!candidate) return [];
  return uniqueStrings([
    ...rollbackRestoreCanaryReceiptRefs(candidate.rollbackRestoreCanary),
    ...(candidate.forkMutationCanary?.receiptRefs ?? []),
    ...receiptRefsFromEvidenceRefs(candidate.evidenceRefs),
  ]);
}

function workflowRollbackReceiptRefs(
  workflow: WorkflowProject,
  latestMintEvent?: WorkflowHarnessActivationAuditEvent,
): string[] {
  return uniqueStrings([
    ...(latestMintEvent?.receiptRefs ?? []),
    ...receiptRefsFromEvidenceRefs(latestMintEvent?.evidenceRefs ?? []),
    ...rollbackRestoreCanaryReceiptRefs(
      workflow.metadata.harness?.activationRecord?.rollbackRestoreCanary,
    ),
    ...(workflow.metadata.harness?.activationRecord?.forkMutationCanary
      ?.receiptRefs ?? []),
    ...receiptRefsFromEvidenceRefs(
      workflow.metadata.harness?.activationRecord?.evidenceRefs ?? [],
    ),
  ]);
}

function workflowSourceProjection(workflow: WorkflowProject): unknown {
  const harness = workflow.metadata.harness;
  return {
    version: workflow.version,
    metadata: {
      id: workflow.metadata.id,
      name: workflow.metadata.name,
      slug: workflow.metadata.slug,
      workflowKind: workflow.metadata.workflowKind,
      executionMode: workflow.metadata.executionMode,
      gitLocation: workflow.metadata.gitLocation,
      branch: workflow.metadata.branch,
      readOnly: workflow.metadata.readOnly,
      harness: harness
        ? {
            schemaVersion: harness.schemaVersion,
            harnessVersion: harness.harnessVersion,
            harnessHash: harness.harnessHash,
            executionMode: harness.executionMode,
            templateName: harness.templateName,
            blessed: harness.blessed,
            forkable: harness.forkable,
            forkedFrom: harness.forkedFrom,
            packageName: harness.packageName,
            validationGates: harness.validationGates,
            aiMutationMode: harness.aiMutationMode,
            componentIds: harness.componentIds,
            slotIds: harness.slotIds,
            componentReadiness: harness.componentReadiness,
            promotionClusters: harness.promotionClusters,
          }
        : undefined,
    },
    nodes: workflow.nodes,
    edges: workflow.edges,
    global_config: workflow.global_config,
  };
}

function harnessWorkbenchDeepLinkHash(
  params: Record<string, string | null | undefined>,
): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value) search.set(key, value);
  });
  return `#harness-workbench?${search.toString()}`;
}

export function makeWorkflowHarnessPackageEvidenceManifest(
  workflow: WorkflowProject,
  nowMs = Date.now(),
): WorkflowHarnessPackageEvidenceManifest | null {
  const harness = workflow.metadata.harness;
  if (!harness) return null;
  const activationRecord = harness.activationRecord;
  const forkMutationCanary =
    activationRecord?.forkMutationCanary ?? harness.forkMutationCanary ?? null;
  const canaryBoundaries = harness.canaryExecutionBoundaries ?? [];
  const rollbackRestoreCanary = activationRecord?.rollbackRestoreCanary ?? null;
  const workerHandoffReceipts =
    activationRecord?.workerHandoffReceipts ??
    harness.workerHandoffReceipts ??
    [];
  const workerHandoffReceiptIds = workerHandoffReceipts.map(
    (receipt) => receipt.receiptId,
  );
  const workerHandoffNodeAttemptIds = uniqueStrings([
    ...(activationRecord?.workerHandoffNodeAttemptIds ?? []),
    ...(harness.workerHandoffNodeAttemptIds ?? []),
  ]);
  const workerHandoffReplayFixtureRefs = uniqueStrings([
    ...(activationRecord?.workerHandoffReplayFixtureRefs ?? []),
    ...(harness.workerHandoffReplayFixtureRefs ?? []),
  ]);
  const forkMutationCanaryReceiptRefs =
    forkMutationCanary?.receiptRefs ?? [];
  const forkMutationCanaryReplayFixtureRefs =
    forkMutationCanary?.replayFixtureRefs ?? [];
  const forkMutationCanaryNodeAttemptIds =
    forkMutationCanary?.nodeAttemptIds ?? [];
  const rollbackRestoreReceiptRefs = rollbackRestoreCanaryReceiptRefs(
    rollbackRestoreCanary,
  );
  const receiptRefs = uniqueStrings([
    ...workflowRollbackReceiptRefs(workflow),
    ...forkMutationCanaryReceiptRefs,
    ...workerHandoffReceipts.map((receipt) => receipt.receiptId),
    ...canaryBoundaries.flatMap((boundary) => boundary.receiptIds),
    ...(harness.replayGates ?? []).flatMap((gate) => gate.receiptRefs),
    ...(harness.activationAudit ?? []).flatMap((event) => event.receiptRefs),
    ...(harness.defaultRuntimeDispatchProof?.receiptIds ?? []),
  ]);
  const replayFixtureRefs = uniqueStrings([
    ...forkMutationCanaryReplayFixtureRefs,
    ...workerHandoffReplayFixtureRefs,
    ...canaryBoundaries.flatMap((boundary) => boundary.replayFixtureRefs),
    ...(harness.replayGates ?? []).flatMap((gate) => gate.replayFixtureRefs),
    ...(harness.defaultRuntimeDispatchProof?.replayFixtureRefs ?? []),
  ]);
  const evidenceRefs = uniqueStrings([
    ...(activationRecord?.evidenceRefs ?? []),
    ...workflowHarnessForkMutationCanaryRefs(forkMutationCanary),
    ...(harness.activationAudit ?? []).flatMap((event) => event.evidenceRefs),
    ...canaryBoundaries.flatMap((boundary) => boundary.evidenceRefs),
    ...(rollbackRestoreCanary?.evidenceRefs ?? []),
    ...workerHandoffNodeAttemptIds,
    ...workerHandoffReplayFixtureRefs,
  ]);
  const canaryBoundaryIds = uniqueStrings(
    canaryBoundaries.map((boundary) => boundary.boundaryId),
  );
  const rollbackDrillIds = uniqueStrings(
    canaryBoundaries.map((boundary) => boundary.rollbackDrill.drillId),
  );
  const activationId = harness.activationId ?? activationRecord?.activationId;
  const rollbackTarget =
    activationRecord?.rollbackTarget ??
    workflow.metadata.workerHarnessBinding?.rollbackTarget ??
    harness.activationId;
  const workflowContentHash =
    activationRecord?.revisionBinding?.workflowContentHash ??
    workflowHarnessSourceContentHash(workflow);
  const reviewedPackageSnapshotFields: WorkflowHarnessReviewedPackageSnapshotFields =
    {
      reviewedWorkflowContentHash: workflowContentHash,
      reviewedActivationId: activationId,
      reviewedHarnessWorkflowId: harness.harnessWorkflowId,
      reviewedWorkerBindingActivationId:
        activationRecord?.workerBinding?.harnessActivationId ??
        workflow.metadata.workerHarnessBinding?.harnessActivationId ??
        activationId,
      reviewedRollbackTarget: rollbackTarget,
      reviewedReplayFixtureRefs: replayFixtureRefs,
      reviewedWorkerHandoffNodeAttemptIds: workerHandoffNodeAttemptIds,
      reviewedWorkerHandoffReceiptIds: workerHandoffReceiptIds,
      reviewedForkMutationCanaryId:
        activationRecord?.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryId ??
        harness.workerBindingRegistryRecord?.reviewedForkMutationCanaryId ??
        forkMutationCanary?.canaryId ??
        null,
      reviewedForkMutationCanaryStatus:
        activationRecord?.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryStatus ??
        harness.workerBindingRegistryRecord?.reviewedForkMutationCanaryStatus ??
        forkMutationCanary?.status ??
        null,
      reviewedForkMutationCanaryDiffHash:
        activationRecord?.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryDiffHash ??
        harness.workerBindingRegistryRecord?.reviewedForkMutationCanaryDiffHash ??
        forkMutationCanary?.diffHash ??
        null,
      reviewedForkMutationCanaryReceiptRefs: forkMutationCanaryReceiptRefs,
      reviewedForkMutationCanaryReplayFixtureRefs:
        forkMutationCanaryReplayFixtureRefs,
      reviewedForkMutationCanaryNodeAttemptIds:
        forkMutationCanaryNodeAttemptIds,
      reviewedForkMutationCanaryRollbackTarget:
        activationRecord?.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryRollbackTarget ??
        harness.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryRollbackTarget ??
        rollbackTarget,
      reviewedPolicyPosture: activationRecord?.policyPosture,
      rollbackTarget,
    };
  const reviewedPackageSnapshotHash = workflowHarnessReviewedPackageSnapshotHash({
    ...reviewedPackageSnapshotFields,
    reviewedPackageSnapshotHash:
      activationRecord?.workerBindingRegistryRecord?.reviewedPackageSnapshotHash ??
      harness.workerBindingRegistryRecord?.reviewedPackageSnapshotHash,
  });
  const deepLinks: WorkflowHarnessPackageEvidenceManifest["deepLinks"] = [
    activationId
      ? {
          kind: "activation",
          ref: activationId,
          hash: harnessWorkbenchDeepLinkHash({
            panel: "settings",
            workerBindingId: activationId,
          }),
        }
      : null,
    forkMutationCanary
      ? {
          kind: "fork_mutation_canary",
          ref: forkMutationCanary.canaryId,
          hash: harnessWorkbenchDeepLinkHash({
            panel: "settings",
            activationGateId: "mutation-canary",
            activationGateEvidenceRef: forkMutationCanary.canaryId,
            activationGateReceiptRef: forkMutationCanary.receiptRefs[0],
            receiptRef: forkMutationCanary.receiptRefs[0],
            activationGateReplayFixtureRef:
              forkMutationCanary.replayFixtureRefs[0],
            replayFixtureRef: forkMutationCanary.replayFixtureRefs[0],
            activationGateNodeAttemptId: forkMutationCanary.nodeAttemptIds[0],
            nodeAttemptId: forkMutationCanary.nodeAttemptIds[0],
          }),
        }
      : null,
    ...canaryBoundaries.flatMap((boundary) => [
      {
        kind: "canary_boundary",
        ref: boundary.boundaryId,
        hash: harnessWorkbenchDeepLinkHash({
          panel: "settings",
          activationGateId: "canary",
          activationGateEvidenceRef: boundary.boundaryId,
          activationGateReceiptRef: boundary.receiptIds[0],
          receiptRef: boundary.receiptIds[0],
          activationGateReplayFixtureRef: boundary.replayFixtureRefs[0],
          replayFixtureRef: boundary.replayFixtureRefs[0],
        }),
      },
      {
        kind: "rollback_drill",
        ref: boundary.rollbackDrill.drillId,
        hash: harnessWorkbenchDeepLinkHash({
          panel: "settings",
          activationGateId: "canary",
          activationGateEvidenceRef: boundary.rollbackDrill.drillId,
          activationGateReceiptRef: boundary.receiptIds[0],
          receiptRef: boundary.receiptIds[0],
          activationGateReplayFixtureRef: boundary.replayFixtureRefs[0],
          replayFixtureRef: boundary.replayFixtureRefs[0],
        }),
      },
    ]),
    ...(rollbackRestoreCanary
      ? rollbackRestoreReceiptRefs.map((receiptRef) => ({
          kind: "rollback_restore",
          ref: receiptRef,
          hash: harnessWorkbenchDeepLinkHash({
            panel: "settings",
            receiptRef,
            activationGateId: "rollback-restore",
            activationGateEvidenceRef: rollbackRestoreCanary.canaryId,
            activationGateReceiptRef: receiptRef,
          }),
        }))
      : []),
    ...workerHandoffNodeAttemptIds.map((nodeAttemptId, index) => ({
      kind: "worker_handoff",
      ref: nodeAttemptId,
      hash: harnessWorkbenchDeepLinkHash({
        panel: "settings",
        activationGateId: "worker-handoff",
        activationGateNodeAttemptId: nodeAttemptId,
        nodeAttemptId,
        activationGateReceiptRef: workerHandoffReceipts[index]?.receiptId,
        receiptRef: workerHandoffReceipts[index]?.receiptId,
        activationGateReplayFixtureRef: workerHandoffReplayFixtureRefs[index],
        replayFixtureRef: workerHandoffReplayFixtureRefs[index],
      }),
    })),
  ].filter(
    (
      link,
    ): link is WorkflowHarnessPackageEvidenceManifest["deepLinks"][number] =>
      Boolean(link),
  );
  return {
    schemaVersion: "workflow.harness.package-evidence-manifest.v1",
    packageName:
      harness.packageName ?? workflow.metadata.slug ?? workflow.metadata.id,
    workflowId: workflow.metadata.id,
    harnessWorkflowId: harness.harnessWorkflowId,
    activationId,
    activationState:
      harness.activationState ?? activationRecord?.activationState,
    harnessHash: harness.harnessHash,
    workflowContentHash,
    reviewedPackageSnapshotHash,
    rollbackTarget,
    policyPosture: activationRecord?.policyPosture,
    componentVersionSet:
      activationRecord?.componentVersionSet ??
      Object.fromEntries(
        workflow.nodes
          .map((node) => node.runtimeBinding?.componentId)
          .filter((componentId): componentId is string => Boolean(componentId))
          .map((componentId) => [componentId, "unversioned"]),
      ),
    evidenceRefs,
    receiptRefs,
    replayFixtureRefs,
    nodeAttemptIds: uniqueStrings([
      ...forkMutationCanaryNodeAttemptIds,
      ...workerHandoffNodeAttemptIds,
    ]),
    forkMutationCanary: forkMutationCanary ?? undefined,
    forkMutationCanaryReceiptRefs,
    forkMutationCanaryReplayFixtureRefs,
    forkMutationCanaryNodeAttemptIds,
    canaryBoundaryIds,
    rollbackDrillIds,
    workerHandoffNodeAttemptIds,
    workerHandoffReceiptIds,
    rollbackRestoreReceiptRefs,
    deepLinks,
    createdAtMs: nowMs,
  };
}

export function withWorkflowHarnessPackageManifest(
  workflow: WorkflowProject,
  nowMs = Date.now(),
): WorkflowProject {
  const manifest = makeWorkflowHarnessPackageEvidenceManifest(workflow, nowMs);
  if (!manifest || !workflow.metadata.harness) return workflow;
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: {
        ...workflow.metadata.harness,
        packageManifest: manifest,
        activationRecord: workflow.metadata.harness.activationRecord
          ? {
              ...workflow.metadata.harness.activationRecord,
              packageManifest: manifest,
            }
          : workflow.metadata.harness.activationRecord,
      },
    },
  };
}

function defaultWorkflowPath(workflow: WorkflowProject): string {
  return (
    workflow.metadata.gitLocation ||
    `.agents/workflows/${workflow.metadata.slug}.workflow.json`
  );
}

export function workflowRevisionBindingFor(
  workflow: WorkflowProject,
  options: {
    workflowPath?: string;
    repoRoot?: string;
    branch?: string;
    baseRevision?: string;
    activatedRevision?: string;
    workflowContentHash?: string;
    proposalId?: string;
    activationId?: string;
    rollbackActivationId?: string;
    rollbackRevision?: string;
    revisionSource?: WorkflowRevisionBinding["revisionSource"];
    nowMs?: number;
  } = {},
): WorkflowRevisionBinding {
  const workflowContentHash =
    options.workflowContentHash ??
    stableContentHash(workflowSourceProjection(workflow));
  const revisionSource =
    options.revisionSource ??
    (options.baseRevision || options.activatedRevision
      ? "git"
      : "file_hash_only");
  return {
    schemaVersion: "workflow.revision-binding.v1",
    workflowPath: options.workflowPath ?? defaultWorkflowPath(workflow),
    repoRoot: options.repoRoot,
    branch: options.branch ?? workflow.metadata.branch ?? "main",
    baseRevision: options.baseRevision,
    activatedRevision:
      options.activatedRevision ??
      (revisionSource === "file_hash_only" ? workflowContentHash : undefined),
    workflowContentHash,
    proposalId: options.proposalId,
    activationId:
      options.activationId ?? workflow.metadata.harness?.activationId,
    rollbackActivationId:
      options.rollbackActivationId ??
      workflow.metadata.harness?.activationRecord?.rollbackTarget,
    rollbackRevision: options.rollbackRevision,
    revisionSource,
    createdAtMs: options.nowMs ?? Date.now(),
  };
}

function workflowWithRefreshedHarnessRevisionBinding(
  workflow: WorkflowProject,
  createdAtMs: number,
): WorkflowProject {
  const harness = workflow.metadata.harness;
  if (!harness) return workflow;
  const current = harness.revisionBinding;
  const rollbackRevisionBinding =
    harness.activationRecord?.rollbackRevisionBinding;
  const revisionBinding = workflowRevisionBindingFor(workflow, {
    workflowPath: current?.workflowPath,
    repoRoot: current?.repoRoot,
    branch: current?.branch,
    baseRevision: current?.baseRevision,
    activatedRevision:
      current?.revisionSource === "git" ? current.activatedRevision : undefined,
    proposalId: current?.proposalId,
    activationId: current?.activationId ?? harness.activationId,
    rollbackActivationId:
      current?.rollbackActivationId ?? harness.activationRecord?.rollbackTarget,
    rollbackRevision:
      current?.rollbackRevision ??
      rollbackRevisionBinding?.activatedRevision ??
      rollbackRevisionBinding?.workflowContentHash,
    revisionSource: current?.revisionSource,
    nowMs: createdAtMs,
  });
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: {
        ...harness,
        revisionBinding,
        activationRecord: harness.activationRecord
          ? {
              ...harness.activationRecord,
              revisionBinding,
            }
          : harness.activationRecord,
      },
    },
  };
}

export function makeHarnessForkActivationRecord(options: {
  workflowId: string;
  harnessWorkflowId?: string;
  activationId?: string;
  activationState: WorkflowHarnessForkActivationRecord["activationState"];
  activationBlockers?: string[];
  componentVersionSet?: Record<string, string>;
  harnessHash?: string;
  policyPosture?: WorkflowHarnessForkActivationRecord["policyPosture"];
  canaryStatus?: WorkflowHarnessForkActivationRecord["canaryStatus"];
  rollbackTarget?: string;
  rollbackAvailable?: boolean;
  liveAuthorityTransferred?: boolean;
  evidenceRefs?: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
  workerBindingRegistryRecord?: WorkflowHarnessWorkerBindingRegistryRecord;
  workerAttachReceipt?: WorkflowHarnessWorkerAttachReceipt;
  workerAttachLifecycle?: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerSessionRecord?: WorkflowHarnessWorkerSessionRecord;
  workerLaunchEnvelopes?: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts?: WorkflowHarnessWorkerHandoffReceipt[];
  workerHandoffNodeAttemptIds?: string[];
  workerHandoffNodeAttempts?: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffReplayFixtureRefs?: string[];
  revisionBinding?: WorkflowRevisionBinding;
  rollbackRevisionBinding?: WorkflowRevisionBinding;
  rollbackRestoreCanary?: WorkflowHarnessForkActivationRecord["rollbackRestoreCanary"];
  forkMutationCanary?: WorkflowHarnessForkActivationRecord["forkMutationCanary"];
  mintedAtMs?: number;
}): WorkflowHarnessForkActivationRecord {
  const activationId =
    options.activationId ??
    (options.activationState === "validated" ||
    options.activationState === "active"
      ? harnessForkActivationId(options.workflowId)
      : undefined);
  return {
    schemaVersion: "workflow.harness.activation.v1",
    workflowId: options.workflowId,
    harnessWorkflowId: options.harnessWorkflowId ?? options.workflowId,
    activationId,
    harnessHash: options.harnessHash ?? DEFAULT_AGENT_HARNESS_HASH,
    activationState: options.activationState,
    activationBlockers:
      options.activationBlockers ??
      (options.activationState === "validated" ||
      options.activationState === "active"
        ? []
        : [...DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS]),
    componentVersionSet:
      options.componentVersionSet ?? defaultHarnessComponentVersionSet(),
    policyPosture:
      options.policyPosture ??
      (options.activationState === "validated" ||
      options.activationState === "active"
        ? "canary"
        : "proposal_only"),
    canaryStatus:
      options.canaryStatus ??
      (options.activationState === "validated" ||
      options.activationState === "active"
        ? "passed"
        : "not_run"),
    rollbackTarget:
      options.rollbackTarget ?? DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET,
    rollbackAvailable:
      options.rollbackAvailable ??
      (options.activationState === "validated" ||
        options.activationState === "active"),
    liveAuthorityTransferred: options.liveAuthorityTransferred ?? false,
    evidenceRefs: options.evidenceRefs ?? [],
    workerBinding: options.workerBinding,
    workerBindingRegistryRecord: options.workerBindingRegistryRecord,
    workerAttachReceipt: options.workerAttachReceipt,
    workerAttachLifecycle: options.workerAttachLifecycle,
    workerSessionRecord: options.workerSessionRecord,
    workerLaunchEnvelopes: options.workerLaunchEnvelopes,
    workerHandoffReceipts: options.workerHandoffReceipts,
    workerHandoffNodeAttemptIds: options.workerHandoffNodeAttemptIds,
    workerHandoffNodeAttempts: options.workerHandoffNodeAttempts,
    workerHandoffReplayFixtureRefs: options.workerHandoffReplayFixtureRefs,
    revisionBinding: options.revisionBinding,
    rollbackRevisionBinding: options.rollbackRevisionBinding,
    rollbackRestoreCanary: options.rollbackRestoreCanary,
    forkMutationCanary: options.forkMutationCanary,
    mintedAtMs: options.mintedAtMs,
  };
}

function harnessActivationAuditEventId(
  workflowId: string,
  eventType: WorkflowHarnessActivationAuditEventType,
  createdAtMs: number,
): string {
  return `harness-activation-audit:${slugify(workflowId)}:${eventType}:${createdAtMs}`;
}

function makeWorkflowHarnessActivationAuditEvent(options: {
  workflow: WorkflowProject;
  eventType: WorkflowHarnessActivationAuditEventType;
  status: WorkflowHarnessActivationAuditEventStatus;
  candidateId?: string;
  activationId?: string;
  previousActivationId?: string;
  nextActivationId?: string;
  previousWorkerBinding?: WorkflowHarnessWorkerBinding;
  nextWorkerBinding?: WorkflowHarnessWorkerBinding;
  previousRevisionBinding?: WorkflowRevisionBinding;
  nextRevisionBinding?: WorkflowRevisionBinding;
  rollbackTarget?: string;
  rollbackExecuted?: boolean;
  blockers?: string[];
  evidenceRefs?: string[];
  receiptRefs?: string[];
  summary: string;
  createdAtMs: number;
}): WorkflowHarnessActivationAuditEvent {
  const workflowId =
    options.workflow.metadata.id || options.workflow.metadata.slug;
  const evidenceRefs = options.evidenceRefs ?? [];
  const receiptRefs = uniqueStrings([
    ...(options.receiptRefs ?? []),
    ...receiptRefsFromEvidenceRefs(evidenceRefs),
  ]);
  return {
    schemaVersion: "workflow.harness.activation-audit.v1",
    eventId: harnessActivationAuditEventId(
      workflowId,
      options.eventType,
      options.createdAtMs,
    ),
    eventType: options.eventType,
    status: options.status,
    workflowId,
    candidateId: options.candidateId,
    activationId: options.activationId,
    previousActivationId: options.previousActivationId,
    nextActivationId: options.nextActivationId,
    previousWorkerBinding: options.previousWorkerBinding,
    nextWorkerBinding: options.nextWorkerBinding,
    previousRevisionBinding: options.previousRevisionBinding,
    nextRevisionBinding: options.nextRevisionBinding,
    rollbackTarget: options.rollbackTarget,
    rollbackExecuted: options.rollbackExecuted,
    blockers: options.blockers ?? [],
    evidenceRefs,
    receiptRefs,
    summary: options.summary,
    createdAtMs: options.createdAtMs,
  };
}

function appendWorkflowHarnessActivationAudit(
  workflow: WorkflowProject,
  event: WorkflowHarnessActivationAuditEvent,
  extras: Partial<NonNullable<WorkflowProject["metadata"]["harness"]>> = {},
): WorkflowProject {
  if (!workflow.metadata.harness) return workflow;
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      dirty: true,
      harness: {
        ...workflow.metadata.harness,
        ...extras,
        activationAudit: [
          ...(workflow.metadata.harness.activationAudit ?? []),
          event,
        ],
      },
      updatedAtMs: event.createdAtMs,
    },
  };
}

export function recordWorkflowHarnessActivationDryRun(
  workflow: WorkflowProject,
  candidate: WorkflowHarnessForkActivationCandidate,
  options: { nowMs?: number } = {},
): WorkflowProject {
  if (!workflowIsHarnessFork(workflow)) return workflow;
  const createdAtMs = options.nowMs ?? Date.now();
  const receiptRefs = activationCandidateReceiptRefs(candidate);
  return appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        candidate.decision === "mintable"
          ? "dry_run_mintable"
          : "dry_run_blocked",
      status: candidate.decision === "mintable" ? "passed" : "blocked",
      candidateId: candidate.candidateId,
      activationId: candidate.activationIdPreview,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: candidate.activationIdPreview,
      previousWorkerBinding: workflow.metadata.workerHarnessBinding,
      nextWorkerBinding: candidate.workerBindingPreview,
      previousRevisionBinding: workflow.metadata.harness?.revisionBinding,
      nextRevisionBinding: candidate.revisionBindingPreview,
      rollbackTarget: candidate.rollbackTarget,
      blockers: candidate.activationBlockers,
      evidenceRefs: candidate.evidenceRefs,
      receiptRefs,
      summary:
        candidate.decision === "mintable"
          ? `Activation dry run mintable for ${candidate.activationIdPreview}`
          : `Activation dry run blocked by ${candidate.activationBlockers.length} blockers`,
      createdAtMs,
    }),
  );
}

export function recordWorkflowHarnessRollbackTargetSelection(
  workflow: WorkflowProject,
  rollbackTarget: string,
  options: { nowMs?: number } = {},
): WorkflowProject {
  if (!workflowIsHarnessFork(workflow)) return workflow;
  const createdAtMs = options.nowMs ?? Date.now();
  return appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: "rollback_target_selected",
      status: "applied",
      activationId: workflow.metadata.harness?.activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      previousWorkerBinding: workflow.metadata.workerHarnessBinding,
      nextWorkerBinding: workflow.metadata.workerHarnessBinding,
      previousRevisionBinding: workflow.metadata.harness?.revisionBinding,
      nextRevisionBinding: workflow.metadata.harness?.revisionBinding,
      rollbackTarget,
      evidenceRefs: [rollbackTarget],
      summary: `Rollback target selected: ${rollbackTarget}`,
      createdAtMs,
    }),
  );
}

function rollbackWorkerBindingForTarget(
  workflow: WorkflowProject,
  rollbackTarget: string,
): WorkflowHarnessWorkerBinding {
  if (
    rollbackTarget === DEFAULT_AGENT_HARNESS_ACTIVATION_ID ||
    rollbackTarget === DEFAULT_AGENT_HARNESS_WORKFLOW_ID
  ) {
    return {
      harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      harnessHash: DEFAULT_AGENT_HARNESS_HASH,
      executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
      source: "default",
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      authorityBindingReady: false,
      authorityBindingBlockers: ["worker_binding_authority_not_live"],
    };
  }
  return {
    harnessWorkflowId: workflow.metadata.id || workflow.metadata.slug,
    harnessActivationId: rollbackTarget,
    harnessHash:
      workflow.metadata.harness?.harnessHash ?? DEFAULT_AGENT_HARNESS_HASH,
    executionMode:
      workflow.metadata.harness?.executionMode ??
      DEFAULT_HARNESS_EXECUTION_MODE,
    source: "fork",
    rollbackTarget,
    authorityBindingReady: false,
    authorityBindingBlockers: ["fork_activation_not_live_default"],
  };
}

function latestHarnessActivationMintEvent(
  workflow: WorkflowProject,
): WorkflowHarnessActivationAuditEvent | undefined {
  return [...(workflow.metadata.harness?.activationAudit ?? [])]
    .reverse()
    .find((event) => event.eventType === "activation_minted");
}

function harnessRollbackTargetFor(
  workflow: WorkflowProject,
  rollbackTarget?: string | null,
): string {
  const latestMintEvent = latestHarnessActivationMintEvent(workflow);
  return (
    rollbackTarget?.trim() ||
    workflow.metadata.harness?.activationRecord?.rollbackTarget ||
    latestMintEvent?.rollbackTarget ||
    DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET
  );
}

function harnessRollbackBindingsFor(
  workflow: WorkflowProject,
  rollbackTarget: string,
  createdAtMs: number,
): {
  latestMintEvent?: WorkflowHarnessActivationAuditEvent;
  activeWorkerBinding: WorkflowHarnessWorkerBinding;
  restoredWorkerBinding: WorkflowHarnessWorkerBinding;
  activeRevisionBinding: WorkflowRevisionBinding;
  restoredRevisionBinding: WorkflowRevisionBinding;
} {
  const latestMintEvent = latestHarnessActivationMintEvent(workflow);
  const activeWorkerBinding =
    workflow.metadata.workerHarnessBinding ??
    workflowHarnessWorkerBinding(workflow);
  const restoredWorkerBinding =
    latestMintEvent?.previousWorkerBinding ??
    rollbackWorkerBindingForTarget(workflow, rollbackTarget);
  const activeRevisionBinding =
    workflow.metadata.harness?.revisionBinding ??
    workflow.metadata.harness?.activationRecord?.revisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: workflow.metadata.harness?.activationId,
      rollbackActivationId: rollbackTarget,
      nowMs: createdAtMs,
    });
  const restoredRevisionBinding =
    latestMintEvent?.previousRevisionBinding ??
    workflow.metadata.harness?.activationRecord?.rollbackRevisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: restoredWorkerBinding.harnessActivationId,
      rollbackActivationId: workflow.metadata.harness?.activationId,
      rollbackRevision:
        activeRevisionBinding.activatedRevision ??
        activeRevisionBinding.workflowContentHash,
      nowMs: createdAtMs,
    });
  return {
    latestMintEvent,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
  };
}

function rollbackRestoreStrategyFor(
  binding: WorkflowRevisionBinding,
): WorkflowHarnessActivationRollbackExecution["restoreStrategy"] {
  if (binding.revisionSource === "git" && binding.activatedRevision) {
    return "git_show_file_restore";
  }
  if (binding.revisionSource === "file_hash_only") {
    return "file_hash_only_metadata_restore";
  }
  return "worker_binding_restore";
}

export interface WorkflowHarnessRollbackRestoreProbeRuntime {
  restoreWorkflowRevision?: (
    request: WorkflowRevisionRestoreRequest,
  ) => Promise<WorkflowRevisionRestoreResult>;
}

export async function runWorkflowHarnessRollbackRestoreCanaryProbe(options: {
  runtime: WorkflowHarnessRollbackRestoreProbeRuntime;
  workflowPath: string;
  rollbackRevisionBinding: WorkflowRevisionBinding | null | undefined;
}): Promise<{
  rollbackRestoreResult: WorkflowRevisionRestoreResult | null;
  rollbackRestoreBlockers: string[];
  restoreRequest?: WorkflowRevisionRestoreRequest;
}> {
  const { runtime, workflowPath, rollbackRevisionBinding } = options;
  if (rollbackRevisionBinding?.revisionSource !== "git") {
    return {
      rollbackRestoreResult: null,
      rollbackRestoreBlockers: [],
    };
  }
  const restoreRequest: WorkflowRevisionRestoreRequest = {
    workflowPath,
    revisionBinding: rollbackRevisionBinding,
    expectedWorkflowContentHash: rollbackRevisionBinding.workflowContentHash,
    dryRun: true,
  };
  if (!runtime.restoreWorkflowRevision) {
    return {
      rollbackRestoreResult: null,
      rollbackRestoreBlockers: ["rollback_restore_api_unavailable"],
      restoreRequest,
    };
  }
  try {
    return {
      rollbackRestoreResult:
        await runtime.restoreWorkflowRevision(restoreRequest),
      rollbackRestoreBlockers: [],
      restoreRequest,
    };
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : "Unknown rollback restore failure";
    return {
      rollbackRestoreResult: null,
      rollbackRestoreBlockers: ["rollback_restore_canary_failed", message],
      restoreRequest,
    };
  }
}

export function executeWorkflowHarnessRollbackDrill(
  workflow: WorkflowProject,
  options: {
    rollbackTarget?: string | null;
    nowMs?: number;
  } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  proof?: WorkflowHarnessActivationRollbackProof;
  blockers: string[];
  rollbackTarget?: string;
  restoredWorkerBinding?: WorkflowHarnessWorkerBinding;
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const rollbackTarget = harnessRollbackTargetFor(
    workflow,
    options.rollbackTarget,
  );
  const blockers = [
    ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ...(rollbackTarget ? [] : ["rollback_target_missing"]),
    ...(workflow.metadata.harness?.activationRecord?.rollbackAvailable === false
      ? ["rollback_unavailable"]
      : []),
  ];
  const {
    latestMintEvent,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
  } = harnessRollbackBindingsFor(workflow, rollbackTarget, createdAtMs);
  const receiptRefs = workflowRollbackReceiptRefs(workflow, latestMintEvent);
  const proof: WorkflowHarnessActivationRollbackProof = {
    schemaVersion: "workflow.harness.activation-rollback-proof.v1",
    drillId: `harness-rollback-drill:${slugify(workflow.metadata.id || workflow.metadata.slug)}:${createdAtMs}`,
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    activationId: workflow.metadata.harness?.activationId,
    rollbackTarget,
    rollbackAvailable: blockers.length === 0,
    rollbackExecuted: blockers.length === 0,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
    drillStatus: blockers.length === 0 ? "passed" : "blocked",
    policyDecision:
      blockers.length === 0
        ? "rollback_drill_restored_previous_worker_binding"
        : "rollback_drill_blocked",
    blockers,
    evidenceRefs: [
      ...receiptRefs,
      rollbackTarget,
      ...(latestMintEvent ? [latestMintEvent.eventId] : []),
    ],
    receiptRefs,
    createdAtMs,
  };
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        blockers.length === 0
          ? "rollback_drill_passed"
          : "rollback_drill_blocked",
      status: blockers.length === 0 ? "passed" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: restoredWorkerBinding.harnessActivationId,
      previousWorkerBinding: activeWorkerBinding,
      nextWorkerBinding: restoredWorkerBinding,
      previousRevisionBinding: activeRevisionBinding,
      nextRevisionBinding: restoredRevisionBinding,
      rollbackTarget,
      rollbackExecuted: blockers.length === 0,
      blockers,
      evidenceRefs: proof.evidenceRefs,
      receiptRefs: proof.receiptRefs,
      summary:
        blockers.length === 0
          ? `Rollback drill restored ${restoredWorkerBinding.harnessActivationId ?? restoredWorkerBinding.harnessWorkflowId}`
          : `Rollback drill blocked by ${blockers.length} blockers`,
      createdAtMs,
    }),
    { activationRollbackProof: proof },
  );
  return {
    executed: blockers.length === 0,
    workflow: workflowWithAudit,
    proof,
    blockers,
    rollbackTarget,
    restoredWorkerBinding,
  };
}

function activationStateForRestoredWorkerBinding(
  restoredWorkerBinding: WorkflowHarnessWorkerBinding,
): WorkflowHarnessForkActivationRecord["activationState"] {
  if (restoredWorkerBinding.source === "recovery") return "blocked";
  return restoredWorkerBinding.harnessActivationId ? "validated" : "blocked";
}

export function executeWorkflowHarnessRevisionRollback(
  workflow: WorkflowProject,
  options: {
    rollbackTarget?: string | null;
    restoredWorkflow?: WorkflowProject | null;
    restoreResult?: WorkflowRevisionRestoreResult | null;
    restoreBlockers?: string[];
    nowMs?: number;
  } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  execution?: WorkflowHarnessActivationRollbackExecution;
  blockers: string[];
  rollbackTarget?: string;
  restoredWorkerBinding?: WorkflowHarnessWorkerBinding;
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const rollbackTarget = harnessRollbackTargetFor(
    workflow,
    options.rollbackTarget,
  );
  const {
    latestMintEvent,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
  } = harnessRollbackBindingsFor(workflow, rollbackTarget, createdAtMs);
  const restoredRevisionWithRollForward: WorkflowRevisionBinding = {
    ...restoredRevisionBinding,
    rollbackActivationId:
      activeWorkerBinding.harnessActivationId ??
      workflow.metadata.harness?.activationId ??
      activeWorkerBinding.harnessWorkflowId,
    rollbackRevision:
      activeRevisionBinding.activatedRevision ??
      activeRevisionBinding.workflowContentHash,
    createdAtMs,
  };
  const restoredActivationState = activationStateForRestoredWorkerBinding(
    restoredWorkerBinding,
  );
  const restoredWorkflowSource = options.restoredWorkflow ?? workflow;
  const restoreBlockers = Array.from(
    new Set(
      [
        ...(options.restoreResult?.blockers ?? []),
        ...(options.restoreBlockers ?? []),
      ].filter(Boolean),
    ),
  );
  const receiptRefs = uniqueStrings([
    options.restoreResult?.receiptBindingRef,
    ...workflowRollbackReceiptRefs(workflow, latestMintEvent),
    ...receiptRefsFromEvidenceRefs(options.restoreResult?.blockers ?? []),
  ]);
  const rollbackActivationRecord = makeHarnessForkActivationRecord({
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    harnessWorkflowId: restoredWorkerBinding.harnessWorkflowId,
    activationId: restoredWorkerBinding.harnessActivationId,
    activationState: restoredActivationState,
    activationBlockers:
      restoredActivationState === "validated"
        ? []
        : ["rollback_restored_non_fork_authority"],
    componentVersionSet:
      workflow.metadata.harness?.activationRecord?.componentVersionSet ??
      defaultHarnessComponentVersionSet(),
    harnessHash: restoredWorkerBinding.harnessHash,
    policyPosture:
      restoredActivationState === "validated"
        ? (workflow.metadata.harness?.activationRecord?.policyPosture ??
          "canary")
        : "proposal_only",
    canaryStatus:
      restoredActivationState === "validated"
        ? (workflow.metadata.harness?.activationRecord?.canaryStatus ??
          "passed")
        : "not_run",
    rollbackTarget:
      activeWorkerBinding.harnessActivationId ??
      activeWorkerBinding.harnessWorkflowId,
    rollbackAvailable: true,
    liveAuthorityTransferred: false,
    evidenceRefs: [
      ...receiptRefs,
      rollbackTarget,
      restoredRevisionWithRollForward.workflowContentHash,
      ...(latestMintEvent ? [latestMintEvent.eventId] : []),
    ],
    workerBinding: restoredWorkerBinding,
    revisionBinding: restoredRevisionWithRollForward,
    rollbackRevisionBinding: activeRevisionBinding,
    mintedAtMs: createdAtMs,
  });
  const restoredWorkflowBase: WorkflowProject = {
    ...restoredWorkflowSource,
    metadata: {
      ...restoredWorkflowSource.metadata,
      dirty: true,
      harness: restoredWorkflowSource.metadata.harness
        ? {
            ...restoredWorkflowSource.metadata.harness,
            harnessWorkflowId: restoredWorkerBinding.harnessWorkflowId,
            harnessHash: restoredWorkerBinding.harnessHash,
            executionMode:
              restoredWorkerBinding.executionMode ??
              restoredWorkflowSource.metadata.harness.executionMode,
            activationId: restoredWorkerBinding.harnessActivationId,
            activationState: restoredActivationState,
            activationRecord: rollbackActivationRecord,
            activationAudit: workflow.metadata.harness?.activationAudit,
            activationRollbackProof:
              workflow.metadata.harness?.activationRollbackProof,
            revisionBinding: restoredRevisionWithRollForward,
          }
        : restoredWorkflowSource.metadata.harness,
      workerHarnessBinding: restoredWorkerBinding,
      updatedAtMs: createdAtMs,
    },
  };
  const actualWorkflowContentHash = stableContentHash(
    workflowSourceProjection(restoredWorkflowBase),
  );
  const expectedWorkflowContentHash =
    options.restoreResult?.expectedWorkflowContentHash ??
    restoredRevisionWithRollForward.workflowContentHash;
  const hashVerified =
    actualWorkflowContentHash === expectedWorkflowContentHash;
  const blockers = [
    ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ...(rollbackTarget ? [] : ["rollback_target_missing"]),
    ...(workflow.metadata.harness?.activationRecord?.rollbackAvailable === false
      ? ["rollback_unavailable"]
      : []),
    ...restoreBlockers,
    ...(hashVerified ? [] : ["rollback_revision_hash_mismatch"]),
  ];
  const execution: WorkflowHarnessActivationRollbackExecution = {
    schemaVersion: "workflow.harness.activation-rollback-execution.v1",
    executionId: `harness-rollback-execution:${slugify(workflow.metadata.id || workflow.metadata.slug)}:${createdAtMs}`,
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    activationId: workflow.metadata.harness?.activationId,
    rollbackTarget,
    rollbackAvailable: blockers.length === 0,
    rollbackExecuted: blockers.length === 0,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding: restoredRevisionWithRollForward,
    restoreStrategy:
      options.restoreResult?.restoreStrategy ??
      rollbackRestoreStrategyFor(restoredRevisionWithRollForward),
    restoreRepoRoot:
      options.restoreResult?.repoRoot ??
      restoredRevisionWithRollForward.repoRoot,
    restoreRelativeWorkflowPath: options.restoreResult?.relativeWorkflowPath,
    restoredRevision:
      options.restoreResult?.restoredRevision ??
      restoredRevisionWithRollForward.activatedRevision,
    restoredFileSha256: options.restoreResult?.fileSha256,
    restoreBlockers,
    restoreReceiptBindingRef: options.restoreResult?.receiptBindingRef,
    workflowPath:
      options.restoreResult?.workflowPath ??
      restoredRevisionWithRollForward.workflowPath,
    expectedWorkflowContentHash,
    actualWorkflowContentHash,
    hashVerified,
    executionStatus: blockers.length === 0 ? "applied" : "blocked",
    policyDecision:
      blockers.length === 0
        ? "rollback_execution_restored_verified_workflow_revision"
        : "rollback_execution_blocked",
    blockers,
    evidenceRefs: [
      ...receiptRefs,
      rollbackTarget,
      restoredRevisionWithRollForward.workflowContentHash,
      ...(latestMintEvent ? [latestMintEvent.eventId] : []),
    ],
    receiptRefs,
    createdAtMs,
  };
  const workflowForAudit =
    blockers.length === 0 ? restoredWorkflowBase : workflow;
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflowForAudit,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        blockers.length === 0
          ? "rollback_executed"
          : "rollback_execution_blocked",
      status: blockers.length === 0 ? "applied" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: restoredWorkerBinding.harnessActivationId,
      previousWorkerBinding: activeWorkerBinding,
      nextWorkerBinding: restoredWorkerBinding,
      previousRevisionBinding: activeRevisionBinding,
      nextRevisionBinding: restoredRevisionWithRollForward,
      rollbackTarget,
      rollbackExecuted: blockers.length === 0,
      blockers,
      evidenceRefs: execution.evidenceRefs,
      receiptRefs: execution.receiptRefs,
      summary:
        blockers.length === 0
          ? `Rollback executed: restored ${restoredRevisionWithRollForward.workflowContentHash}`
          : `Rollback execution blocked by ${blockers.length} blockers`,
      createdAtMs,
    }),
    { activationRollbackExecution: execution },
  );
  return {
    executed: blockers.length === 0,
    workflow: workflowWithAudit,
    execution,
    blockers,
    rollbackTarget,
    restoredWorkerBinding,
  };
}

export function executeWorkflowHarnessActiveRuntimeRollbackDryRun(
  workflow: WorkflowProject,
  options: {
    nowMs?: number;
  } = {},
): {
  workflow: WorkflowProject;
  proof: WorkflowHarnessActiveRuntimeRollbackExecutionProof;
  passed: boolean;
  blockers: string[];
} {
  const generatedAtMs = options.nowMs ?? Date.now();
  const harness = workflow.metadata.harness;
  const defaultDispatch = harness?.defaultRuntimeDispatchProof ?? null;
  const selector = harness?.runtimeSelectorDecision ?? null;
  const workerLaunchEnvelopes =
    defaultDispatch?.workerLaunchEnvelopes ??
    harness?.workerLaunchEnvelopes ??
    harness?.activationRecord?.workerLaunchEnvelopes ??
    [];
  const workerHandoffReceipts =
    defaultDispatch?.workerHandoffReceipts ??
    harness?.workerHandoffReceipts ??
    harness?.activationRecord?.workerHandoffReceipts ??
    [];
  const workerHandoffNodeAttempts =
    defaultDispatch?.workerHandoffNodeAttempts ??
    harness?.workerHandoffNodeAttempts ??
    [];
  const workerHandoffReplayFixtureRefs =
    defaultDispatch?.workerHandoffReplayFixtureRefs ??
    harness?.workerHandoffReplayFixtureRefs ??
    [];
  const rollbackLaunchEnvelope =
    workerLaunchEnvelopes.find((envelope) => envelope.phase === "rollback") ??
    null;
  const rollbackHandoffReceipt =
    workerHandoffReceipts.find((receipt) => receipt.phase === "rollback") ??
    null;
  const rollbackNodeAttempt =
    workerHandoffNodeAttempts.find(
      (attempt) =>
        Boolean(rollbackHandoffReceipt?.receiptId) &&
        attempt.receiptIds.includes(rollbackHandoffReceipt?.receiptId ?? ""),
    ) ??
    workerHandoffNodeAttempts.find((attempt) =>
      attempt.attemptId.includes(":rollback:"),
    ) ??
    null;
  const replayFixtureRef =
    rollbackNodeAttempt?.replay.fixtureRef ??
    workerHandoffReplayFixtureRefs.find((fixtureRef) =>
      fixtureRef.includes(":rollback:"),
    ) ??
    null;
  const readinessProofId =
    rollbackHandoffReceipt?.rollbackReadinessProofId ??
    rollbackLaunchEnvelope?.rollbackReadinessProofId ??
    selector?.livePromotionReadinessProof?.proofId ??
    defaultDispatch?.livePromotionReadinessProof?.proofId ??
    "";
  const liveShadowComparisonGateId =
    rollbackHandoffReceipt?.rollbackLiveShadowComparisonGateId ??
    rollbackLaunchEnvelope?.rollbackLiveShadowComparisonGateId ??
    defaultDispatch?.liveShadowComparisonGate?.gateId ??
    defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate
      ?.gateId ??
    "";
  const liveShadowComparisonGateReady =
    rollbackHandoffReceipt?.rollbackLiveShadowComparisonGateReady ??
    rollbackLaunchEnvelope?.rollbackLiveShadowComparisonGateReady ??
    defaultDispatch?.liveShadowComparisonGateReady ??
    defaultDispatch?.livePromotionReadinessProof
      ?.liveShadowComparisonGateReady ??
    false;
  const activationId =
    rollbackHandoffReceipt?.rollbackActivationId ??
    rollbackLaunchEnvelope?.rollbackActivationId ??
    defaultDispatch?.activationId ??
    selector?.activationId ??
    "";
  const harnessHash =
    rollbackHandoffReceipt?.rollbackHarnessHash ??
    rollbackLaunchEnvelope?.rollbackHarnessHash ??
    defaultDispatch?.harnessHash ??
    selector?.harnessHash ??
    "";
  const rollbackTarget =
    defaultDispatch?.rollbackTarget ??
    selector?.rollbackTarget ??
    harness?.activationId ??
    "";
  const policyDecision =
    rollbackHandoffReceipt?.rollbackPolicyDecision ??
    rollbackLaunchEnvelope?.rollbackPolicyDecision ??
    "";
  const receiptRefs = uniqueStrings([
    rollbackLaunchEnvelope?.envelopeId,
    rollbackHandoffReceipt?.receiptId,
    ...(rollbackNodeAttempt?.receiptIds ?? []),
  ]);
  const replayFixtureRefs = uniqueStrings([replayFixtureRef]);
  const blockers = uniqueStrings([
    ...(defaultDispatch ? [] : ["missing_default_runtime_dispatch"]),
    ...(selector ? [] : ["missing_runtime_selector_decision"]),
    ...(rollbackTarget ? [] : ["rollback_target_missing"]),
    ...(rollbackLaunchEnvelope?.accepted === true &&
    rollbackLaunchEnvelope.phase === "rollback" &&
    rollbackLaunchEnvelope.rollbackHandoffReady === true &&
    (rollbackLaunchEnvelope.blockers ?? []).length === 0
      ? []
      : ["rollback_launch_envelope_not_ready"]),
    ...(rollbackHandoffReceipt?.accepted === true &&
    rollbackHandoffReceipt.phase === "rollback" &&
    rollbackHandoffReceipt.handoffStatus === "rollback_handoff_ready" &&
    (rollbackHandoffReceipt.blockers ?? []).length === 0
      ? []
      : ["rollback_handoff_receipt_not_ready"]),
    ...(rollbackNodeAttempt?.workflowNodeId === "harness.handoff_bridge" &&
    rollbackNodeAttempt.componentKind === "handoff_bridge" &&
    Boolean(replayFixtureRef) &&
    Boolean(rollbackHandoffReceipt?.receiptId) &&
    rollbackNodeAttempt.receiptIds.includes(
      rollbackHandoffReceipt?.receiptId ?? "",
    )
      ? []
      : ["rollback_node_attempt_not_bound"]),
    ...(readinessProofId &&
    readinessProofId ===
      (selector?.livePromotionReadinessProof?.proofId ??
        defaultDispatch?.livePromotionReadinessProof?.proofId)
      ? []
      : ["rollback_readiness_proof_mismatch"]),
    ...(liveShadowComparisonGateId ===
    DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID
      ? []
      : ["rollback_live_shadow_gate_mismatch"]),
    ...(liveShadowComparisonGateReady
      ? []
      : ["rollback_live_shadow_gate_not_ready"]),
    ...(activationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID
      ? []
      : ["rollback_activation_mismatch"]),
    ...(harnessHash === DEFAULT_AGENT_HARNESS_HASH
      ? []
      : ["rollback_harness_hash_mismatch"]),
    ...(policyDecision ===
    "allow_default_harness_worker_rollback_from_live_shadow_gate"
      ? []
      : ["rollback_policy_decision_mismatch"]),
    ...(receiptRefs.length > 0 ? [] : ["rollback_receipts_missing"]),
    ...(replayFixtureRefs.length > 0 ? [] : ["rollback_replay_missing"]),
  ]);
  const canaryHashVerified =
    blockers.length === 0 &&
    Boolean(rollbackLaunchEnvelope?.envelopeId) &&
    Boolean(rollbackHandoffReceipt?.receiptId) &&
    Boolean(rollbackNodeAttempt?.attemptId) &&
    Boolean(replayFixtureRef);
  const dryRunPassed = blockers.length === 0 && canaryHashVerified;
  const canaryResultId = dryRunPassed
    ? `harness-active-runtime-rollback-canary:${slugify(
        workflow.metadata.id || workflow.metadata.slug,
      )}:${generatedAtMs}`
    : null;
  const proof: WorkflowHarnessActiveRuntimeRollbackExecutionProof = {
    schemaVersion:
      "workflow.harness.active-runtime-rollback-execution-proof.v1",
    method:
      "active runtime rollback workbench runs a dry-run against the bound default-live rollback proof and gates apply readiness on the restored proof row",
    generatedAtMs,
    workflowId:
      defaultDispatch?.workflowId ??
      selector?.workflowId ??
      harness?.harnessWorkflowId ??
      workflow.metadata.id,
    activationId,
    rollbackTarget,
    readinessProofId,
    liveShadowComparisonGateId,
    liveShadowComparisonGateReady,
    harnessHash,
    policyDecision,
    launchEnvelopeId: rollbackLaunchEnvelope?.envelopeId ?? null,
    handoffReceiptId: rollbackHandoffReceipt?.receiptId ?? null,
    nodeAttemptId: rollbackNodeAttempt?.attemptId ?? null,
    replayFixtureRef,
    dryRun: {
      clicked: true,
      passed: dryRunPassed,
      canaryResultId,
      canaryStatus: dryRunPassed ? "passed" : "blocked",
      canaryHashVerified,
      policyDecision: dryRunPassed
        ? "allow_default_live_rollback_dry_run_from_bound_proof"
        : "block_default_live_rollback_dry_run",
      receiptRefs,
      replayFixtureRefs,
      blockers,
    },
    apply: {
      attempted: false,
      disabled: !dryRunPassed,
      readiness: dryRunPassed ? "ready" : "blocked",
      applied: false,
      policyDecision: dryRunPassed
        ? "allow_default_live_rollback_apply_after_bound_dry_run"
        : "block_default_live_rollback_apply_until_dry_run_passes",
      blockers: dryRunPassed ? [] : ["rollback_dry_run_not_passed"],
    },
    passed: dryRunPassed,
    blockers,
  };
  return {
    workflow: {
      ...workflow,
      metadata: {
        ...workflow.metadata,
        dirty: true,
        harness: harness
          ? {
              ...harness,
              activeRuntimeRollbackExecutionProof: proof,
            }
          : harness,
        updatedAtMs: generatedAtMs,
      },
    },
    proof,
    passed: dryRunPassed,
    blockers,
  };
}

export function executeWorkflowHarnessActiveRuntimeRollbackApply(
  workflow: WorkflowProject,
  options: {
    nowMs?: number;
  } = {},
): {
  workflow: WorkflowProject;
  proof: WorkflowHarnessActiveRuntimeRollbackApplyProof;
  executionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof;
  applied: boolean;
  blockers: string[];
} {
  const generatedAtMs = options.nowMs ?? Date.now();
  const harness = workflow.metadata.harness;
  const existingProof = harness?.activeRuntimeRollbackExecutionProof ?? null;
  const defaultDispatch = harness?.defaultRuntimeDispatchProof ?? null;
  const selector = harness?.runtimeSelectorDecision ?? null;
  const workerLaunchEnvelopes =
    defaultDispatch?.workerLaunchEnvelopes ??
    harness?.workerLaunchEnvelopes ??
    harness?.activationRecord?.workerLaunchEnvelopes ??
    [];
  const workerHandoffReceipts =
    defaultDispatch?.workerHandoffReceipts ??
    harness?.workerHandoffReceipts ??
    harness?.activationRecord?.workerHandoffReceipts ??
    [];
  const workerHandoffNodeAttempts =
    defaultDispatch?.workerHandoffNodeAttempts ??
    harness?.workerHandoffNodeAttempts ??
    [];
  const workerHandoffReplayFixtureRefs =
    defaultDispatch?.workerHandoffReplayFixtureRefs ??
    harness?.workerHandoffReplayFixtureRefs ??
    [];
  const rollbackLaunchEnvelope =
    workerLaunchEnvelopes.find((envelope) => envelope.phase === "rollback") ??
    null;
  const rollbackHandoffReceipt =
    workerHandoffReceipts.find((receipt) => receipt.phase === "rollback") ??
    null;
  const rollbackNodeAttempt =
    workerHandoffNodeAttempts.find(
      (attempt) =>
        Boolean(rollbackHandoffReceipt?.receiptId) &&
        attempt.receiptIds.includes(rollbackHandoffReceipt?.receiptId ?? ""),
    ) ??
    workerHandoffNodeAttempts.find((attempt) =>
      attempt.attemptId.includes(":rollback:"),
    ) ??
    null;
  const rollbackNodeAttemptBound =
    Boolean(rollbackNodeAttempt) &&
    Boolean(rollbackHandoffReceipt?.receiptId) &&
    rollbackNodeAttempt?.receiptIds.includes(
      rollbackHandoffReceipt?.receiptId ?? "",
    ) === true;
  const replayFixtureRef =
    rollbackNodeAttempt?.replay.fixtureRef ??
    workerHandoffReplayFixtureRefs.find((fixtureRef) =>
      fixtureRef.includes(":rollback:"),
    ) ??
    null;
  const rollbackReplayFixtureBound =
    Boolean(replayFixtureRef) &&
    workerHandoffReplayFixtureRefs.includes(replayFixtureRef ?? "");
  const readinessProofId =
    rollbackHandoffReceipt?.rollbackReadinessProofId ??
    rollbackLaunchEnvelope?.rollbackReadinessProofId ??
    selector?.livePromotionReadinessProof?.proofId ??
    defaultDispatch?.livePromotionReadinessProof?.proofId ??
    "";
  const liveShadowComparisonGateId =
    rollbackHandoffReceipt?.rollbackLiveShadowComparisonGateId ??
    rollbackLaunchEnvelope?.rollbackLiveShadowComparisonGateId ??
    defaultDispatch?.liveShadowComparisonGate?.gateId ??
    defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate
      ?.gateId ??
    "";
  const liveShadowComparisonGateReady =
    rollbackHandoffReceipt?.rollbackLiveShadowComparisonGateReady ??
    rollbackLaunchEnvelope?.rollbackLiveShadowComparisonGateReady ??
    defaultDispatch?.liveShadowComparisonGateReady ??
    defaultDispatch?.livePromotionReadinessProof
      ?.liveShadowComparisonGateReady ??
    false;
  const activationId =
    rollbackHandoffReceipt?.rollbackActivationId ??
    rollbackLaunchEnvelope?.rollbackActivationId ??
    defaultDispatch?.activationId ??
    selector?.activationId ??
    "";
  const harnessHash =
    rollbackHandoffReceipt?.rollbackHarnessHash ??
    rollbackLaunchEnvelope?.rollbackHarnessHash ??
    defaultDispatch?.harnessHash ??
    selector?.harnessHash ??
    "";
  const rollbackTarget =
    defaultDispatch?.rollbackTarget ??
    selector?.rollbackTarget ??
    harness?.activationId ??
    "";
  const policyDecision =
    rollbackHandoffReceipt?.rollbackPolicyDecision ??
    rollbackLaunchEnvelope?.rollbackPolicyDecision ??
    "";
  const detachedBlockers = uniqueStrings([
    ...(harness ? [] : ["missing_harness_metadata"]),
    ...(defaultDispatch ? [] : ["missing_default_runtime_dispatch"]),
    ...(selector ? [] : ["missing_runtime_selector_decision"]),
    ...(rollbackLaunchEnvelope ? [] : ["rollback_launch_envelope_missing"]),
    ...(rollbackHandoffReceipt ? [] : ["rollback_handoff_receipt_missing"]),
    ...(rollbackNodeAttempt ? [] : ["rollback_node_attempt_missing"]),
    ...(replayFixtureRef ? [] : ["rollback_replay_fixture_missing"]),
    ...(rollbackNodeAttempt && !rollbackNodeAttemptBound
      ? ["rollback_node_attempt_orphaned"]
      : []),
    ...(replayFixtureRef && !rollbackReplayFixtureBound
      ? ["rollback_replay_fixture_orphaned"]
      : []),
  ]);
  const staleBlockers = uniqueStrings([
    ...(existingProof?.readinessProofId === readinessProofId
      ? []
      : ["rollback_readiness_proof_stale"]),
    ...(existingProof?.liveShadowComparisonGateId === liveShadowComparisonGateId
      ? []
      : ["rollback_live_shadow_gate_stale"]),
    ...(existingProof?.activationId === activationId
      ? []
      : ["rollback_activation_stale"]),
    ...(existingProof?.harnessHash === harnessHash
      ? []
      : ["rollback_harness_hash_stale"]),
    ...(existingProof?.rollbackTarget === rollbackTarget
      ? []
      : ["rollback_target_stale"]),
    ...(existingProof?.launchEnvelopeId ===
    (rollbackLaunchEnvelope?.envelopeId ?? null)
      ? []
      : ["rollback_launch_envelope_stale"]),
    ...(existingProof?.handoffReceiptId ===
    (rollbackHandoffReceipt?.receiptId ?? null)
      ? []
      : ["rollback_handoff_receipt_stale"]),
    ...(existingProof?.nodeAttemptId ===
    (rollbackNodeAttempt?.attemptId ?? null)
      ? []
      : ["rollback_node_attempt_stale"]),
    ...(existingProof?.replayFixtureRef === (replayFixtureRef ?? null)
      ? []
      : ["rollback_replay_fixture_stale"]),
  ]);
  const baseBlockers = uniqueStrings([
    ...(existingProof ? [] : ["active_runtime_rollback_dry_run_required"]),
    ...(existingProof?.passed === true &&
    existingProof.dryRun.clicked === true &&
    existingProof.dryRun.passed === true &&
    existingProof.dryRun.canaryStatus === "passed" &&
    existingProof.dryRun.canaryHashVerified === true
      ? []
      : ["active_runtime_rollback_dry_run_not_passed"]),
    ...(existingProof?.apply.disabled === false &&
    existingProof?.apply.readiness === "ready"
      ? []
      : ["active_runtime_rollback_apply_not_ready"]),
    ...(rollbackTarget ? [] : ["rollback_target_missing"]),
    ...(liveShadowComparisonGateReady
      ? []
      : ["rollback_live_shadow_gate_not_ready"]),
    ...(liveShadowComparisonGateId ===
    DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID
      ? []
      : ["rollback_live_shadow_gate_mismatch"]),
    ...(activationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID
      ? []
      : ["rollback_activation_mismatch"]),
    ...(harnessHash === DEFAULT_AGENT_HARNESS_HASH
      ? []
      : ["rollback_harness_hash_mismatch"]),
    ...(policyDecision ===
    "allow_default_harness_worker_rollback_from_live_shadow_gate"
      ? []
      : ["rollback_policy_decision_mismatch"]),
  ]);
  const receiptRefs = uniqueStrings([
    `harness-active-runtime-rollback-apply-receipt:${slugify(
      workflow.metadata.id || workflow.metadata.slug,
    )}:${generatedAtMs}`,
    rollbackLaunchEnvelope?.envelopeId,
    rollbackHandoffReceipt?.receiptId,
    ...(rollbackNodeAttempt?.receiptIds ?? []),
    ...(existingProof?.dryRun.receiptRefs ?? []),
  ]);
  const replayFixtureRefs = uniqueStrings([
    replayFixtureRef,
    ...(existingProof?.dryRun.replayFixtureRefs ?? []),
  ]);
  const rollbackReceiptId = receiptRefs[0] ?? "";
  const executionId = `harness-active-runtime-rollback-apply:${slugify(
    workflow.metadata.id || workflow.metadata.slug,
  )}:${generatedAtMs}`;
  const auditEventType: WorkflowHarnessActivationAuditEventType =
    baseBlockers.length === 0 &&
    detachedBlockers.length === 0 &&
    staleBlockers.length === 0
      ? "active_runtime_rollback_applied"
      : "active_runtime_rollback_apply_blocked";
  const auditEventId = harnessActivationAuditEventId(
    workflow.metadata.id || workflow.metadata.slug,
    auditEventType,
    generatedAtMs,
  );
  const rollbackTargetVerified =
    Boolean(rollbackTarget) &&
    existingProof?.rollbackTarget === rollbackTarget &&
    (defaultDispatch?.rollbackTarget ?? selector?.rollbackTarget) ===
      rollbackTarget;
  const hashVerified =
    existingProof?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
    harnessHash === DEFAULT_AGENT_HARNESS_HASH;
  const evidenceRefs = uniqueStrings([
    executionId,
    rollbackReceiptId,
    auditEventId,
    rollbackTarget,
    readinessProofId,
    liveShadowComparisonGateId,
    activationId,
    harnessHash,
    existingProof?.dryRun.canaryResultId,
    rollbackLaunchEnvelope?.envelopeId,
    rollbackHandoffReceipt?.receiptId,
    rollbackNodeAttempt?.attemptId,
    replayFixtureRef,
  ]);
  const blockers = uniqueStrings([
    ...baseBlockers,
    ...detachedBlockers,
    ...staleBlockers,
    ...(receiptRefs.length > 0 ? [] : ["rollback_apply_receipt_missing"]),
    ...(replayFixtureRefs.length > 0 ? [] : ["rollback_apply_replay_missing"]),
    ...(rollbackTargetVerified ? [] : ["rollback_apply_target_not_verified"]),
    ...(hashVerified ? [] : ["rollback_apply_hash_not_verified"]),
  ]);
  const applied = blockers.length === 0;
  const applyProof: WorkflowHarnessActiveRuntimeRollbackApplyProof = {
    schemaVersion: "workflow.harness.active-runtime-rollback-apply-proof.v1",
    method:
      "active runtime rollback apply reuses the bound dry-run canary, verifies the live-shadow rollback proof has not drifted, and records a rollback receipt plus audit event",
    generatedAtMs,
    workflowId:
      defaultDispatch?.workflowId ??
      selector?.workflowId ??
      harness?.harnessWorkflowId ??
      workflow.metadata.id,
    activationId,
    previousActivationId: harness?.activationId ?? activationId,
    nextActivationId: applied ? rollbackTarget : harness?.activationId ?? null,
    rollbackTarget,
    readinessProofId,
    liveShadowComparisonGateId,
    liveShadowComparisonGateReady,
    harnessHash,
    launchEnvelopeId: rollbackLaunchEnvelope?.envelopeId ?? null,
    handoffReceiptId: rollbackHandoffReceipt?.receiptId ?? null,
    nodeAttemptId: rollbackNodeAttempt?.attemptId ?? null,
    replayFixtureRef,
    dryRunCanaryResultId: existingProof?.dryRun.canaryResultId ?? null,
    executionId,
    rollbackReceiptId,
    auditEventId,
    applyStatus: applied ? "applied" : "blocked",
    rollbackApplied: applied,
    rollbackTargetVerified,
    hashVerified,
    policyDecision: applied
      ? "active_runtime_rollback_apply_verified_bound_dry_run"
      : "active_runtime_rollback_apply_blocked",
    receiptRefs,
    evidenceRefs,
    replayFixtureRefs,
    staleProofBlocked: staleBlockers.length > 0,
    detachedProofBlocked: detachedBlockers.length > 0,
    blockers,
    passed: applied,
  };
  const executionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof =
    existingProof ?? {
      schemaVersion:
        "workflow.harness.active-runtime-rollback-execution-proof.v1",
      method:
        "active runtime rollback apply was requested before a bound dry-run proof existed",
      generatedAtMs,
      workflowId:
        defaultDispatch?.workflowId ??
        selector?.workflowId ??
        harness?.harnessWorkflowId ??
        workflow.metadata.id,
      activationId,
      rollbackTarget,
      readinessProofId,
      liveShadowComparisonGateId,
      liveShadowComparisonGateReady,
      harnessHash,
      policyDecision,
      launchEnvelopeId: rollbackLaunchEnvelope?.envelopeId ?? null,
      handoffReceiptId: rollbackHandoffReceipt?.receiptId ?? null,
      nodeAttemptId: rollbackNodeAttempt?.attemptId ?? null,
      replayFixtureRef,
      dryRun: {
        clicked: false,
        passed: false,
        canaryResultId: null,
        canaryStatus: "blocked",
        canaryHashVerified: false,
        policyDecision: "block_default_live_rollback_dry_run",
        receiptRefs: [],
        replayFixtureRefs: [],
        blockers: ["active_runtime_rollback_dry_run_required"],
      },
      apply: {
        attempted: true,
        disabled: true,
        readiness: "blocked",
        applied: false,
        policyDecision: "active_runtime_rollback_apply_blocked",
        blockers,
      },
      passed: false,
      blockers,
    };
  const nextExecutionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof = {
    ...executionProof,
    apply: {
      ...executionProof.apply,
      attempted: true,
      disabled: !applied,
      readiness: applied ? "applied" : "blocked",
      applied,
      policyDecision: applyProof.policyDecision,
      executionId,
      rollbackReceiptId,
      auditEventId,
      rollbackTargetVerified,
      hashVerified,
      receiptRefs,
      evidenceRefs,
      replayFixtureRefs,
      appliedAtMs: applied ? generatedAtMs : null,
      blockers,
    },
    blockers,
    passed: executionProof.passed === true && applied,
  };
  const workflowWithProof: WorkflowProject = {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      dirty: true,
      harness: harness
        ? {
            ...harness,
            activeRuntimeRollbackExecutionProof: nextExecutionProof,
            activeRuntimeRollbackApplyProof: applyProof,
          }
        : harness,
      updatedAtMs: generatedAtMs,
    },
  };
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflowWithProof,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: auditEventType,
      status: applied ? "applied" : "blocked",
      activationId,
      previousActivationId: harness?.activationId ?? activationId,
      nextActivationId: applied ? rollbackTarget : harness?.activationId,
      previousWorkerBinding: workflow.metadata.workerHarnessBinding,
      nextWorkerBinding: workflow.metadata.workerHarnessBinding,
      previousRevisionBinding: harness?.revisionBinding,
      nextRevisionBinding: harness?.revisionBinding,
      rollbackTarget,
      rollbackExecuted: applied,
      blockers,
      evidenceRefs,
      receiptRefs,
      summary: applied
        ? `Active runtime rollback applied to ${rollbackTarget}`
        : `Active runtime rollback apply blocked by ${blockers.length} blockers`,
      createdAtMs: generatedAtMs,
    }),
    {
      activeRuntimeRollbackExecutionProof: nextExecutionProof,
      activeRuntimeRollbackApplyProof: applyProof,
    },
  );
  return {
    workflow: workflowWithAudit,
    proof: applyProof,
    executionProof: nextExecutionProof,
    applied,
    blockers,
  };
}

export interface WorkflowHarnessReplayDrillInput {
  replayFixtureRef: string;
  sourceKind: string;
  sourceLabel: string;
  producerComponent: string;
  policyDecision: string;
  attemptId: string;
  receiptRef: string;
  runId: string;
  executionMode: string;
  readiness: string;
  inputHash: string;
  outputHash: string;
  deterministicEnvelope: boolean;
  capturesInput: boolean;
  capturesOutput: boolean;
  capturesPolicyDecision: boolean;
  determinism: string;
  redactionPolicy: string;
  evidenceRefs: string[];
}

function unresolvedHarnessReplayValue(
  value: string | null | undefined,
): boolean {
  if (!value) return true;
  return /pending|not resolved|not captured|unknown/i.test(value);
}

function harnessReplayDrillDivergenceClass(
  blockers: string[],
  replay: WorkflowHarnessReplayDrillInput,
): WorkflowHarnessReplayDrillDivergenceClass {
  if (blockers.includes("replay_fixture_unresolved"))
    return "fixture_unresolved";
  if (blockers.includes("replay_receipt_missing")) return "missing_receipt";
  if (blockers.includes("replay_policy_decision_not_captured")) {
    return "policy_divergence";
  }
  if (blockers.includes("replay_output_not_captured"))
    return "output_divergence";
  if (
    !replay.deterministicEnvelope ||
    replay.determinism === "nondeterministic"
  ) {
    return "harmless_metadata_drift";
  }
  return "none";
}

function workflowHarnessReplayDrillResultFor(
  workflow: WorkflowProject,
  replay: WorkflowHarnessReplayDrillInput | null | undefined,
  createdAtMs: number,
): {
  drill: WorkflowHarnessReplayDrillResult;
  blockers: string[];
} {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const replayFixtureRef = replay?.replayFixtureRef?.trim() ?? "";
  const blockers = uniqueStrings([
    ...(workflow.metadata.harness ? [] : ["not_harness_workflow"]),
    ...(replay ? [] : ["replay_fixture_unresolved"]),
    ...(replayFixtureRef ? [] : ["replay_fixture_missing"]),
    ...(replay?.sourceKind === "unresolved"
      ? ["replay_fixture_unresolved"]
      : []),
    ...(unresolvedHarnessReplayValue(replay?.receiptRef)
      ? ["replay_receipt_missing"]
      : []),
    ...(replay?.capturesOutput ? [] : ["replay_output_not_captured"]),
    ...(replay?.capturesPolicyDecision
      ? []
      : ["replay_policy_decision_not_captured"]),
  ]);
  const drillId = `harness-replay-drill:${slugify(workflowId)}:${slugify(
    replayFixtureRef || "fixture",
  )}:${createdAtMs}`;
  const expectedInputHash =
    replay?.inputHash && !unresolvedHarnessReplayValue(replay.inputHash)
      ? replay.inputHash
      : stableContentHash({ replayFixtureRef, phase: "input" });
  const expectedOutputHash =
    replay?.outputHash && !unresolvedHarnessReplayValue(replay.outputHash)
      ? replay.outputHash
      : stableContentHash({ replayFixtureRef, phase: "output" });
  const actualInputHash = blockers.length === 0 ? expectedInputHash : "not_run";
  const actualOutputHash =
    blockers.length === 0
      ? expectedOutputHash
      : stableContentHash({ drillId, blockers, phase: "blocked_output" });
  const divergenceClass = replay
    ? harnessReplayDrillDivergenceClass(blockers, replay)
    : "fixture_unresolved";
  const receiptRefs = uniqueStrings([
    unresolvedHarnessReplayValue(replay?.receiptRef)
      ? undefined
      : replay?.receiptRef,
  ]);
  const evidenceRefs = uniqueStrings([
    drillId,
    replayFixtureRef,
    ...(replay?.evidenceRefs ?? []),
    ...receiptRefs,
  ]);
  return {
    blockers,
    drill: {
      schemaVersion: "workflow.harness.replay-drill-result.v1",
      drillId,
      workflowId,
      activationId: workflow.metadata.harness?.activationId,
      replayFixtureRef: replayFixtureRef || "replay fixture missing",
      sourceKind: replay?.sourceKind ?? "unresolved",
      sourceLabel: replay?.sourceLabel ?? "Unresolved harness replay fixture",
      drillStatus: blockers.length === 0 ? "passed" : "blocked",
      divergenceClass,
      componentId: replay?.producerComponent ?? "unknown",
      producerComponent: replay?.producerComponent ?? "unknown",
      attemptId: replay?.attemptId ?? "not resolved",
      receiptRef: replay?.receiptRef ?? "not resolved",
      runId: replay?.runId ?? "run pending",
      executionMode: replay?.executionMode ?? "projection",
      readiness: replay?.readiness ?? "projection_only",
      policyDecision:
        blockers.length === 0
          ? (replay?.policyDecision ?? "replay_policy_not_recorded")
          : "replay_drill_blocked",
      expectedInputHash,
      actualInputHash,
      expectedOutputHash,
      actualOutputHash,
      deterministicEnvelope: replay?.deterministicEnvelope ?? false,
      capturesInput: replay?.capturesInput ?? false,
      capturesOutput: replay?.capturesOutput ?? false,
      capturesPolicyDecision: replay?.capturesPolicyDecision ?? false,
      determinism: replay?.determinism ?? "disabled",
      redactionPolicy: replay?.redactionPolicy ?? "not resolved",
      blockers,
      evidenceRefs,
      receiptRefs,
      createdAtMs,
    },
  };
}

function replayDrillBlocksPromotion(
  drill: WorkflowHarnessReplayDrillResult,
): boolean {
  return (
    drill.drillStatus !== "passed" ||
    !["none", "harmless_metadata_drift"].includes(drill.divergenceClass)
  );
}

function workflowHarnessPromotionClusterReplayGateProofFor(
  clusterId: WorkflowHarnessPromotionClusterId,
  gate: WorkflowHarnessReplayGateResult,
): WorkflowHarnessPromotionClusterReplayGateProof {
  return {
    schemaVersion: "workflow.harness.promotion-cluster-replay-gate-proof.v1",
    clusterId,
    gateId: gate.gateId,
    gateStatus: gate.gateStatus,
    activationGateImpact: gate.activationGateImpact,
    totalFixtures: gate.totalFixtures,
    passedCount: gate.passedCount,
    blockedCount: gate.blockedCount,
    failedCount: gate.failedCount,
    blockingDivergenceCount:
      gate.blockedCount +
      gate.failedCount +
      gate.blockingReplayFixtureRefs.length,
    replayFixtureRefs: gate.replayFixtureRefs,
    blockingReplayFixtureRefs: gate.blockingReplayFixtureRefs,
    receiptRefs: gate.receiptRefs,
    evidenceRefs: gate.evidenceRefs,
    blockers: gate.blockers,
    verifiedAtMs: gate.createdAtMs,
  };
}

function workflowHarnessPromotionClustersWithReplayGateProof(
  workflow: WorkflowProject,
  gate: WorkflowHarnessReplayGateResult,
): WorkflowHarnessPromotionCluster[] | undefined {
  if (gate.scopeKind !== "harness_group")
    return workflow.metadata.harness?.promotionClusters;
  const clusters = workflow.metadata.harness?.promotionClusters;
  if (!clusters) return clusters;
  const cluster = clusters.find(
    (candidate) => candidate.clusterId === gate.targetId,
  );
  if (!cluster) return clusters;
  const proof = workflowHarnessPromotionClusterReplayGateProofFor(
    cluster.clusterId,
    gate,
  );
  return clusters.map((candidate) =>
    candidate.clusterId === cluster.clusterId
      ? { ...candidate, replayGateProof: proof }
      : candidate,
  );
}

const HARNESS_READINESS_ORDER: Record<
  WorkflowHarnessComponentReadiness,
  number
> = {
  projection_only: 0,
  simulated: 1,
  shadow_ready: 2,
  live_ready: 3,
};

function workflowHarnessReadinessAllows(
  actual: WorkflowHarnessComponentReadiness | undefined,
  required: WorkflowHarnessComponentReadiness,
): boolean {
  return (
    (HARNESS_READINESS_ORDER[actual ?? "projection_only"] ?? 0) >=
    HARNESS_READINESS_ORDER[required]
  );
}

function workflowHarnessClusterForId(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId | string,
): WorkflowHarnessPromotionCluster | null {
  return (
    (workflow.metadata.harness?.promotionClusters ?? []).find(
      (cluster) => String(cluster.clusterId) === String(clusterId),
    ) ?? null
  );
}

function workflowHarnessNodesForCluster(
  workflow: WorkflowProject,
  cluster: WorkflowHarnessPromotionCluster,
): Node[] {
  const componentKinds = new Set(cluster.componentKinds);
  return workflow.nodes.filter((node) => {
    const componentKind =
      node.runtimeBinding?.componentKind ?? harnessComponentForNode(node)?.kind;
    return Boolean(componentKind && componentKinds.has(componentKind));
  });
}

function workflowHarnessPromotionClusterCurrentStatus(
  workflow: WorkflowProject,
  cluster: WorkflowHarnessPromotionCluster,
): WorkflowHarnessClusterPromotionStatus {
  if (cluster.promotionStatus) return cluster.promotionStatus;
  const latestPromoted = [
    ...(workflow.metadata.harness?.promotionTransitions ?? []),
  ]
    .reverse()
    .find(
      (attempt) =>
        attempt.clusterId === cluster.clusterId &&
        attempt.attemptStatus === "promoted",
    );
  return latestPromoted?.nextStatus ?? "shadow_ready";
}

function workflowHarnessPromotionClusterWithStatus(
  clusters: WorkflowHarnessPromotionCluster[] | undefined,
  clusterId: WorkflowHarnessPromotionClusterId,
  status: WorkflowHarnessClusterPromotionStatus,
): WorkflowHarnessPromotionCluster[] | undefined {
  if (!clusters) return clusters;
  return clusters.map((cluster) =>
    cluster.clusterId === clusterId
      ? { ...cluster, promotionStatus: status }
      : cluster,
  );
}

function workflowHarnessCanaryBoundaryForCluster(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId,
): WorkflowHarnessCanaryExecutionBoundary | null {
  const harness = workflow.metadata.harness;
  return (
    [
      ...(harness?.canaryExecutionBoundaries ?? []),
      ...(harness?.canaryExecutionBoundary
        ? [harness.canaryExecutionBoundary]
        : []),
    ].find((boundary) => boundary.clusterId === clusterId) ?? null
  );
}

export function workflowHarnessPromotionTransitionEligibility(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId | string,
  targetExecutionMode: WorkflowHarnessPromotionTransitionTarget,
  options: { nowMs?: number } = {},
): WorkflowHarnessPromotionTransitionEligibility {
  const createdAtMs = options.nowMs ?? Date.now();
  const cluster = workflowHarnessClusterForId(workflow, clusterId);
  const fallbackClusterId = (
    typeof clusterId === "string" ? clusterId : "cognition"
  ) as WorkflowHarnessPromotionClusterId;
  const currentStatus = cluster
    ? workflowHarnessPromotionClusterCurrentStatus(workflow, cluster)
    : "blocked";
  const nodes = cluster
    ? workflowHarnessNodesForCluster(workflow, cluster)
    : [];
  const requiredReadiness =
    targetExecutionMode === "live"
      ? "live_ready"
      : (cluster?.minimumReadiness ?? "shadow_ready");
  const readinessReady =
    Boolean(cluster) &&
    nodes.length > 0 &&
    nodes.every((node) =>
      workflowHarnessReadinessAllows(
        node.runtimeBinding?.readiness ??
          harnessComponentForNode(node)?.readiness,
        requiredReadiness,
      ),
    );
  const replayGateProof = cluster?.replayGateProof;
  const canaryBoundary = cluster
    ? workflowHarnessCanaryBoundaryForCluster(workflow, cluster.clusterId)
    : null;
  const receiptRefs = uniqueStrings([
    ...(replayGateProof?.receiptRefs ?? []),
    ...(canaryBoundary?.receiptIds ?? []),
  ]);
  const receiptReady =
    Boolean(cluster) && nodes.length > 0 && receiptRefs.length > 0;
  const replayGateReady =
    replayGateProof?.gateStatus === "passed" &&
    replayGateProof.activationGateImpact === "passed" &&
    replayGateProof.totalFixtures > 0 &&
    replayGateProof.blockingDivergenceCount === 0 &&
    replayGateProof.blockingReplayFixtureRefs.length === 0;
  const activationRecord = workflow.metadata.harness?.activationRecord;
  const canaryReady =
    canaryBoundary?.status === "passed" &&
    canaryBoundary.canaryEligible === true &&
    canaryBoundary.rollbackDrill.drillStatus === "passed";
  const rollbackReady =
    (canaryBoundary?.rollbackAvailable === true &&
      Boolean(canaryBoundary.rollbackTarget)) ||
    (activationRecord?.rollbackAvailable === true &&
      Boolean(activationRecord.rollbackTarget));
  const targetOrderReady =
    targetExecutionMode === "gated" ||
    currentStatus === "gated" ||
    currentStatus === "live";
  const blockers = uniqueStrings([
    ...(cluster ? [] : ["promotion_cluster_missing"]),
    ...(targetOrderReady ? [] : ["promotion_live_requires_gated_cluster"]),
    ...(readinessReady
      ? []
      : [`promotion_readiness_below_${requiredReadiness}`]),
    ...(receiptReady ? [] : ["promotion_receipts_missing"]),
    ...(replayGateReady ? [] : ["promotion_replay_gate_not_passed"]),
    ...(canaryReady ? [] : ["promotion_canary_not_passed"]),
    ...(rollbackReady ? [] : ["promotion_rollback_unavailable"]),
  ]);
  return {
    schemaVersion: "workflow.harness.promotion-transition-eligibility.v1",
    clusterId: cluster?.clusterId ?? fallbackClusterId,
    targetExecutionMode,
    currentStatus,
    eligible: blockers.length === 0,
    readinessReady,
    receiptReady,
    replayGateReady,
    canaryReady,
    rollbackReady,
    componentIds: uniqueStrings(
      nodes.map(
        (node) =>
          node.runtimeBinding?.componentId ??
          harnessComponentForNode(node)?.componentId ??
          node.id,
      ),
    ),
    receiptRefs,
    replayFixtureRefs: uniqueStrings([
      ...(replayGateProof?.replayFixtureRefs ?? []),
      ...(canaryBoundary?.replayFixtureRefs ?? []),
    ]),
    canaryBoundaryId: canaryBoundary?.boundaryId,
    rollbackTarget:
      canaryBoundary?.rollbackTarget ?? activationRecord?.rollbackTarget,
    blockers,
    evidenceRefs: uniqueStrings([
      replayGateProof?.gateId,
      canaryBoundary?.boundaryId,
      ...(replayGateProof?.evidenceRefs ?? []),
      ...(canaryBoundary?.evidenceRefs ?? []),
    ]),
    createdAtMs,
  };
}

export function executeWorkflowHarnessPromotionTransition(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId | string,
  targetExecutionMode: WorkflowHarnessPromotionTransitionTarget,
  options: { nowMs?: number } = {},
): {
  promoted: boolean;
  workflow: WorkflowProject;
  attempt: WorkflowHarnessPromotionTransitionAttempt;
  eligibility: WorkflowHarnessPromotionTransitionEligibility;
  blockers: string[];
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const eligibility = workflowHarnessPromotionTransitionEligibility(
    workflow,
    clusterId,
    targetExecutionMode,
    { nowMs: createdAtMs },
  );
  const cluster = workflowHarnessClusterForId(workflow, eligibility.clusterId);
  const previousStatus = eligibility.currentStatus;
  const nextStatus: WorkflowHarnessClusterPromotionStatus = eligibility.eligible
    ? targetExecutionMode
    : previousStatus;
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const transitionId = `harness-promotion-transition:${slugify(workflowId)}:${slugify(
    `${eligibility.clusterId}:${targetExecutionMode}`,
  )}:${createdAtMs}`;
  const attempt: WorkflowHarnessPromotionTransitionAttempt = {
    schemaVersion: "workflow.harness.promotion-transition-attempt.v1",
    transitionId,
    workflowId,
    activationId: workflow.metadata.harness?.activationId,
    clusterId: eligibility.clusterId,
    clusterLabel:
      cluster?.label ?? HARNESS_PROMOTION_CLUSTER_LABELS[eligibility.clusterId],
    targetExecutionMode,
    previousStatus,
    nextStatus,
    attemptStatus: eligibility.eligible ? "promoted" : "blocked",
    gateDecision: eligibility.eligible
      ? "allow_promotion_transition"
      : "block_promotion_transition",
    eligibility,
    blockers: eligibility.blockers,
    receiptRefs: eligibility.receiptRefs,
    replayFixtureRefs: eligibility.replayFixtureRefs,
    evidenceRefs: uniqueStrings([transitionId, ...eligibility.evidenceRefs]),
    createdAtMs,
  };
  const promotionClusters = eligibility.eligible
    ? workflowHarnessPromotionClusterWithStatus(
        workflow.metadata.harness?.promotionClusters,
        eligibility.clusterId,
        nextStatus,
      )
    : workflow.metadata.harness?.promotionClusters;
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: eligibility.eligible
        ? "promotion_transition_promoted"
        : "promotion_transition_blocked",
      status: eligibility.eligible ? "passed" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      blockers: eligibility.blockers,
      evidenceRefs: attempt.evidenceRefs,
      receiptRefs: attempt.receiptRefs,
      summary: eligibility.eligible
        ? `${attempt.clusterLabel} promoted to ${targetExecutionMode}`
        : `${attempt.clusterLabel} promotion to ${targetExecutionMode} blocked by ${eligibility.blockers.length} gates`,
      createdAtMs,
    }),
    {
      promotionClusters,
      promotionTransitions: [
        ...(workflow.metadata.harness?.promotionTransitions ?? []),
        attempt,
      ],
    },
  );
  return {
    promoted: eligibility.eligible,
    workflow: workflowWithRefreshedHarnessRevisionBinding(
      workflowWithAudit,
      createdAtMs,
    ),
    attempt,
    eligibility,
    blockers: eligibility.blockers,
  };
}

export function executeWorkflowHarnessReplayDrill(
  workflow: WorkflowProject,
  replay: WorkflowHarnessReplayDrillInput | null | undefined,
  options: { nowMs?: number } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  drill?: WorkflowHarnessReplayDrillResult;
  blockers: string[];
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const { drill, blockers } = workflowHarnessReplayDrillResultFor(
    workflow,
    replay,
    createdAtMs,
  );
  return {
    executed: blockers.length === 0,
    workflow: appendWorkflowHarnessActivationAudit(
      workflow,
      makeWorkflowHarnessActivationAuditEvent({
        workflow,
        eventType:
          blockers.length === 0
            ? "replay_drill_passed"
            : "replay_drill_blocked",
        status: blockers.length === 0 ? "passed" : "blocked",
        activationId: workflow.metadata.harness?.activationId,
        blockers,
        evidenceRefs: drill.evidenceRefs,
        receiptRefs: drill.receiptRefs,
        summary:
          blockers.length === 0
            ? `Replay drill passed: ${drill.replayFixtureRef}`
            : `Replay drill blocked by ${blockers.length} blockers`,
        createdAtMs,
      }),
      {
        replayDrills: [
          ...(workflow.metadata.harness?.replayDrills ?? []),
          drill,
        ],
      },
    ),
    drill,
    blockers,
  };
}

export function executeWorkflowHarnessReplayGate(
  workflow: WorkflowProject,
  replays: Array<WorkflowHarnessReplayDrillInput | null | undefined>,
  options: {
    scopeKind?: WorkflowHarnessReplayGateResult["scopeKind"];
    targetId?: string;
    nowMs?: number;
  } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  gate: WorkflowHarnessReplayGateResult;
  drills: WorkflowHarnessReplayDrillResult[];
  blockers: string[];
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const scopeKind = options.scopeKind ?? "workflow";
  const targetId = options.targetId ?? workflowId;
  const drills = replays.map(
    (replay, index) =>
      workflowHarnessReplayDrillResultFor(workflow, replay, createdAtMs + index)
        .drill,
  );
  const blockingDrills = drills.filter(replayDrillBlocksPromotion);
  const divergenceCounts = drills.reduce<Record<string, number>>(
    (counts, drill) => {
      counts[drill.divergenceClass] = (counts[drill.divergenceClass] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const blockers = uniqueStrings([
    ...(workflow.metadata.harness ? [] : ["not_harness_workflow"]),
    ...(drills.length > 0 ? [] : ["replay_gate_no_fixtures"]),
    ...blockingDrills.flatMap((drill) =>
      drill.blockers.length > 0
        ? drill.blockers
        : [`replay_divergence:${drill.divergenceClass}`],
    ),
  ]);
  const gateId = `harness-replay-gate:${slugify(workflowId)}:${slugify(
    `${scopeKind}:${targetId}`,
  )}:${createdAtMs}`;
  const gate: WorkflowHarnessReplayGateResult = {
    schemaVersion: "workflow.harness.replay-gate-result.v1",
    gateId,
    workflowId,
    activationId: workflow.metadata.harness?.activationId,
    scopeKind,
    targetId,
    gateStatus: blockers.length === 0 ? "passed" : "blocked",
    totalFixtures: drills.length,
    passedCount: drills.filter((drill) => drill.drillStatus === "passed")
      .length,
    blockedCount: drills.filter((drill) => drill.drillStatus === "blocked")
      .length,
    failedCount: drills.filter((drill) => drill.drillStatus === "failed")
      .length,
    divergenceCounts,
    replayFixtureRefs: uniqueStrings(
      drills.map((drill) => drill.replayFixtureRef),
    ),
    blockingReplayFixtureRefs: uniqueStrings(
      blockingDrills.map((drill) => drill.replayFixtureRef),
    ),
    drillIds: drills.map((drill) => drill.drillId),
    receiptRefs: uniqueStrings(drills.flatMap((drill) => drill.receiptRefs)),
    evidenceRefs: uniqueStrings([
      gateId,
      ...drills.flatMap((drill) => drill.evidenceRefs),
    ]),
    activationGateImpact: blockers.length === 0 ? "passed" : "blocked",
    blockers,
    createdAtMs,
  };
  const promotionClusters = workflowHarnessPromotionClustersWithReplayGateProof(
    workflow,
    gate,
  );
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        blockers.length === 0 ? "replay_gate_passed" : "replay_gate_blocked",
      status: blockers.length === 0 ? "passed" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      blockers,
      evidenceRefs: gate.evidenceRefs,
      receiptRefs: gate.receiptRefs,
      summary:
        blockers.length === 0
          ? `Replay gate passed: ${gate.totalFixtures} fixtures`
          : `Replay gate blocked by ${blockingDrills.length} fixtures`,
      createdAtMs,
    }),
    {
      replayDrills: [
        ...(workflow.metadata.harness?.replayDrills ?? []),
        ...drills,
      ],
      replayGates: [...(workflow.metadata.harness?.replayGates ?? []), gate],
      promotionClusters,
    },
  );
  return {
    executed: blockers.length === 0,
    workflow: workflowWithRefreshedHarnessRevisionBinding(
      workflowWithAudit,
      createdAtMs,
    ),
    gate,
    drills,
    blockers,
  };
}

export function applyWorkflowHarnessActivationCandidate(
  workflow: WorkflowProject,
  candidate: WorkflowHarnessForkActivationCandidate | null | undefined,
  options: {
    rollbackTarget?: string | null;
    reviewedPackageSnapshot?: WorkflowHarnessReviewedPackageSnapshotFields | null;
    nowMs?: number;
  } = {},
): {
  applied: boolean;
  workflow: WorkflowProject;
  activationId?: string;
  blockers: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
  rollbackTarget?: string;
} {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const activationId =
    candidate?.activationId ?? candidate?.activationIdPreview;
  const blockers = [
    ...(candidate?.activationBlockers ?? []),
    ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ...(candidate?.decision === "mintable" ? [] : ["candidate_not_mintable"]),
    ...(activationId ? [] : ["activation_id_missing"]),
  ];
  if (blockers.length > 0 || !candidate || !activationId) {
    const createdAtMs = options.nowMs ?? Date.now();
    const uniqueBlockers = Array.from(new Set(blockers));
    const receiptRefs = activationCandidateReceiptRefs(candidate);
    const blockedWorkflow = workflowIsHarnessFork(workflow)
      ? appendWorkflowHarnessActivationAudit(
          workflow,
          makeWorkflowHarnessActivationAuditEvent({
            workflow,
            eventType: "activation_mint_blocked",
            status: "blocked",
            candidateId: candidate?.candidateId,
            activationId,
            previousActivationId: workflow.metadata.harness?.activationId,
            nextActivationId: activationId,
            previousWorkerBinding: workflow.metadata.workerHarnessBinding,
            nextWorkerBinding: candidate?.workerBindingPreview,
            previousRevisionBinding: workflow.metadata.harness?.revisionBinding,
            nextRevisionBinding: candidate?.revisionBindingPreview,
            rollbackTarget: candidate?.rollbackTarget,
            blockers: uniqueBlockers,
            evidenceRefs: candidate?.evidenceRefs ?? [],
            receiptRefs,
            summary: `Activation mint blocked by ${uniqueBlockers.length} blockers`,
            createdAtMs,
          }),
        )
      : workflow;
    return {
      applied: false,
      workflow: workflowIsHarnessFork(blockedWorkflow)
        ? withWorkflowHarnessPackageManifest(blockedWorkflow, createdAtMs)
        : blockedWorkflow,
      blockers: uniqueBlockers,
    };
  }

  const nowMs = options.nowMs ?? Date.now();
  const rollbackTarget =
    options.rollbackTarget?.trim() ||
    candidate.rollbackTarget ||
    workflow.metadata.harness?.activationRecord?.rollbackTarget ||
    DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET;
  const previousRevisionBinding =
    workflow.metadata.harness?.revisionBinding ??
    workflow.metadata.harness?.activationRecord?.revisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: workflow.metadata.harness?.activationId,
      rollbackActivationId: rollbackTarget,
      nowMs,
    });
  const requestedWorkerBinding: WorkflowHarnessWorkerBinding = {
    ...candidate.workerBindingPreview,
    harnessWorkflowId:
      candidate.workerBindingPreview.harnessWorkflowId || workflowId,
    harnessActivationId: activationId,
    harnessHash:
      candidate.workerBindingPreview.harnessHash ||
      candidate.harnessHash ||
      workflow.metadata.harness?.harnessHash ||
      DEFAULT_AGENT_HARNESS_HASH,
    executionMode:
      candidate.workerBindingPreview.executionMode ??
      workflow.metadata.harness?.executionMode ??
      DEFAULT_HARNESS_EXECUTION_MODE,
    source: "fork",
    rollbackTarget,
  };
  const revisionBinding: WorkflowRevisionBinding = {
    ...candidate.revisionBindingPreview,
    activationId,
    rollbackActivationId: rollbackTarget,
    rollbackRevision:
      previousRevisionBinding.activatedRevision ??
      previousRevisionBinding.workflowContentHash,
    createdAtMs: nowMs,
  };
  const receiptRefs = activationCandidateReceiptRefs(candidate);
  const handoffPhases = ["launch", "resume", "rollback"] as const;
  const workerId = `harness-worker:${workflowId}:${activationId}`;
  const sessionRecordId = `harness-worker-session:${workflowId}:${activationId}:${revisionBinding.workflowContentHash}:${workerId}:${workflowId}`;
  const reviewedPackageSnapshot =
    options.reviewedPackageSnapshot ??
    ({
      reviewedWorkflowContentHash: revisionBinding.workflowContentHash,
      reviewedActivationId: activationId,
      reviewedHarnessWorkflowId: workflowId,
      reviewedWorkerBindingActivationId: activationId,
      reviewedRollbackTarget: rollbackTarget,
      reviewedReplayFixtureRefs: uniqueStrings([
        ...handoffPhases.map(
          (phase) =>
            `harness-worker-handoff:fixture:${phase}:${sessionRecordId}`,
        ),
        ...(workflow.metadata.harness?.canaryExecutionBoundaries ?? []).flatMap(
          (boundary) => boundary.replayFixtureRefs,
        ),
        ...(workflow.metadata.harness?.replayGates ?? []).flatMap(
          (gate) => gate.replayFixtureRefs,
        ),
        ...(workflow.metadata.harness?.defaultRuntimeDispatchProof
          ?.replayFixtureRefs ?? []),
        ...(candidate.forkMutationCanary?.replayFixtureRefs ?? []),
      ]),
      reviewedWorkerHandoffNodeAttemptIds: handoffPhases.map(
        (phase) => `harness-worker-handoff:attempt:${phase}:${sessionRecordId}`,
      ),
      reviewedWorkerHandoffReceiptIds: handoffPhases.map(
        (phase) =>
          `harness-worker-handoff-receipt:${phase}:${sessionRecordId}`,
      ),
      reviewedForkMutationCanaryId:
        candidate.forkMutationCanary?.canaryId ?? null,
      reviewedForkMutationCanaryStatus:
        candidate.forkMutationCanary?.status ?? null,
      reviewedForkMutationCanaryDiffHash:
        candidate.forkMutationCanary?.diffHash ?? null,
      reviewedForkMutationCanaryReceiptRefs:
        candidate.forkMutationCanary?.receiptRefs ?? [],
      reviewedForkMutationCanaryReplayFixtureRefs:
        candidate.forkMutationCanary?.replayFixtureRefs ?? [],
      reviewedForkMutationCanaryNodeAttemptIds:
        candidate.forkMutationCanary?.nodeAttemptIds ?? [],
      reviewedForkMutationCanaryRollbackTarget: rollbackTarget,
      reviewedPolicyPosture: candidate.policyPosture,
      rollbackTarget,
    } satisfies WorkflowHarnessReviewedPackageSnapshotFields);
  const forkHandoffProof = makeWorkflowHarnessForkActivationHandoffProof({
    workflowId,
    activationId,
    activationHash: revisionBinding.workflowContentHash,
    harnessHash:
      requestedWorkerBinding.harnessHash ||
      candidate.harnessHash ||
      DEFAULT_AGENT_HARNESS_HASH,
    componentVersionSet: candidate.componentVersionSet,
    rollbackTarget,
    workerBinding: requestedWorkerBinding,
    policyPosture: candidate.policyPosture,
    reviewedPackageSnapshot,
    createdAtMs: nowMs,
  });
  const workerBinding = forkHandoffProof.workerBinding;
  const workerBindingRegistryRecord =
    forkHandoffProof.workerBindingRegistryRecord;
  const workerAttachReceipt = forkHandoffProof.workerAttachReceipt;
  const activationRecord = makeHarnessForkActivationRecord({
    workflowId,
    harnessWorkflowId: workerBinding.harnessWorkflowId,
    activationId,
    activationState: "validated",
    activationBlockers: [],
    componentVersionSet: candidate.componentVersionSet,
    harnessHash: candidate.harnessHash,
    policyPosture: candidate.policyPosture,
    canaryStatus: candidate.canaryStatus,
    rollbackTarget,
    rollbackAvailable: candidate.rollbackAvailable || Boolean(rollbackTarget),
    liveAuthorityTransferred: false,
    evidenceRefs: uniqueStrings([
      candidate.candidateId,
      ...receiptRefs,
      ...candidate.evidenceRefs,
      ...forkHandoffProof.workerHandoffNodeAttemptIds,
      ...forkHandoffProof.workerHandoffReplayFixtureRefs,
    ]),
    workerBinding,
    workerBindingRegistryRecord,
    workerAttachReceipt,
    workerAttachLifecycle: forkHandoffProof.workerAttachLifecycle,
    workerSessionRecord: forkHandoffProof.workerSessionRecord,
    workerLaunchEnvelopes: forkHandoffProof.workerLaunchEnvelopes,
    workerHandoffReceipts: forkHandoffProof.workerHandoffReceipts,
    workerHandoffNodeAttemptIds: forkHandoffProof.workerHandoffNodeAttemptIds,
    workerHandoffNodeAttempts: forkHandoffProof.workerHandoffNodeAttempts,
    workerHandoffReplayFixtureRefs:
      forkHandoffProof.workerHandoffReplayFixtureRefs,
    revisionBinding,
    rollbackRevisionBinding: previousRevisionBinding,
    rollbackRestoreCanary: candidate.rollbackRestoreCanary,
    forkMutationCanary: candidate.forkMutationCanary,
    mintedAtMs: nowMs,
  });
  const activatedWorkflow: WorkflowProject = {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      dirty: true,
      harness: workflow.metadata.harness
        ? {
            ...workflow.metadata.harness,
            harnessWorkflowId: workerBinding.harnessWorkflowId,
            harnessHash: workerBinding.harnessHash,
            executionMode:
              workerBinding.executionMode ??
              workflow.metadata.harness.executionMode,
            activationId,
            activationState: "validated",
            activationRecord,
            revisionBinding,
            workerBindingRegistryRecord,
            workerAttachReceipt,
            workerAttachLifecycle: forkHandoffProof.workerAttachLifecycle,
            workerSessionRecord: forkHandoffProof.workerSessionRecord,
            workerLaunchEnvelopes: forkHandoffProof.workerLaunchEnvelopes,
            workerHandoffReceipts: forkHandoffProof.workerHandoffReceipts,
            workerHandoffNodeAttemptIds:
              forkHandoffProof.workerHandoffNodeAttemptIds,
            workerHandoffNodeAttempts:
              forkHandoffProof.workerHandoffNodeAttempts,
            workerHandoffReplayFixtureRefs:
              forkHandoffProof.workerHandoffReplayFixtureRefs,
            forkMutationCanary: candidate.forkMutationCanary,
          }
        : workflow.metadata.harness,
      workerHarnessBinding: workerBinding,
      updatedAtMs: nowMs,
    },
  };
  const auditedWorkflow = appendWorkflowHarnessActivationAudit(
    activatedWorkflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: "activation_minted",
      status: "applied",
      candidateId: candidate.candidateId,
      activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: activationId,
      previousWorkerBinding: workflow.metadata.workerHarnessBinding,
      nextWorkerBinding: workerBinding,
      previousRevisionBinding,
      nextRevisionBinding: revisionBinding,
      rollbackTarget,
      evidenceRefs: uniqueStrings([
        candidate.candidateId,
        ...receiptRefs,
        ...candidate.evidenceRefs,
      ]),
      receiptRefs,
      summary: `Activation minted: ${activationId}`,
      createdAtMs: nowMs,
    }),
  );
  return {
    applied: true,
    workflow: withWorkflowHarnessPackageManifest(auditedWorkflow, nowMs),
    activationId,
    blockers: [],
    workerBinding,
    rollbackTarget,
  };
}

export function makeBlessedHarnessLiveHandoffProof(
  options: {
    selector?: WorkflowHarnessLiveHandoffProof["selector"];
    productionDefaultSelector?: WorkflowHarnessLiveHandoffProof["productionDefaultSelector"];
    canaryStatus?: WorkflowHarnessLiveHandoffProof["canaryStatus"];
    canaryTurnRoutedThroughWorkflow?: boolean;
    defaultAuthorityTransferred?: boolean;
    runtimeAuthority?: WorkflowHarnessLiveHandoffProof["runtimeAuthority"];
    rollbackAvailable?: boolean;
    policyDecision?: string;
    defaultPromotionGateEnabled?: boolean;
    defaultPromotionGateEligible?: boolean;
    defaultPromotionGateActivationBlockers?: string[];
    defaultPromotionGatePolicyDecision?: string;
    livePromotionReadinessProof?: WorkflowHarnessLivePromotionReadinessProof | null;
    requireLivePromotionReadinessProof?: boolean;
    activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof | null;
    activationIdGateProofNowMs?: number;
    activationIdGateProofMaxAgeMs?: number;
    requireActivationIdGateClickProof?: boolean;
    packageImportActivationApplyProof?: WorkflowHarnessPackageImportActivationApplyProof | null;
    packageImportActivationApplyProofNowMs?: number;
    packageImportActivationApplyProofMaxAgeMs?: number;
    requirePackageImportActivationApplyProof?: boolean;
    gatedClusterIds?: WorkflowHarnessLiveHandoffProof["gatedClusterIds"];
    executionBoundaryIds?: string[];
    executionBoundaryClusterIds?: WorkflowHarnessPromotionClusterId[];
    nodeTimelineAttemptIds?: string[];
    receiptIds?: string[];
    replayFixtureRefs?: string[];
    activationBlockers?: string[];
    evidenceRefs?: string[];
  } = {},
): WorkflowHarnessLiveHandoffProof {
  const requestedSelector = options.selector ?? "blessed_workflow_live_canary";
  const defaultAuthorityTransferred =
    options.defaultAuthorityTransferred ?? false;
  const defaultRequested =
    requestedSelector === "blessed_workflow_live_default" ||
    defaultAuthorityTransferred;
  const requireLivePromotionReadinessProof =
    options.requireLivePromotionReadinessProof ?? defaultRequested;
  const livePromotionReadinessBlockers = requireLivePromotionReadinessProof
    ? workflowHarnessLivePromotionReadinessProofBlockers(
        options.livePromotionReadinessProof,
      )
    : [];
  const livePromotionReadinessReady =
    requireLivePromotionReadinessProof &&
    livePromotionReadinessBlockers.length === 0;
  const requirePackageImportActivationApplyProof =
    options.requirePackageImportActivationApplyProof ?? defaultRequested;
  const packageImportActivationApplyProofBlockers =
    requirePackageImportActivationApplyProof
      ? workflowHarnessPackageImportActivationApplyProofBlockers(
          options.packageImportActivationApplyProof,
          {
            nowMs: options.packageImportActivationApplyProofNowMs,
            maxAgeMs: options.packageImportActivationApplyProofMaxAgeMs,
          },
        )
      : [];
  const packageImportActivationApplyProofPresent = Boolean(
    options.packageImportActivationApplyProof,
  );
  const packageImportActivationApplyProofPassed =
    packageImportActivationApplyProofPresent &&
    packageImportActivationApplyProofBlockers.length === 0;
  const defaultLivePromotionInvariantIds =
    requirePackageImportActivationApplyProof
      ? [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT]
      : [];
  const defaultLivePromotionInvariantBlockers = uniqueStrings([
    ...packageImportActivationApplyProofBlockers,
  ]);
  const effectiveDefaultAuthorityTransferred =
    defaultAuthorityTransferred &&
    livePromotionReadinessReady &&
    defaultLivePromotionInvariantBlockers.length === 0;
  const recoveryMode = effectiveDefaultAuthorityTransferred
    ? "restore_prior_workflow_activation"
    : "fail_closed";
  const selector =
    defaultRequested && !effectiveDefaultAuthorityTransferred
      ? "blessed_workflow_live_canary"
      : requestedSelector;
  const requestedProductionDefaultSelector =
    options.productionDefaultSelector ??
    (defaultAuthorityTransferred
      ? "blessed_workflow_live_default"
      : "workflow_recovery_blocked");
  const productionDefaultSelector = effectiveDefaultAuthorityTransferred
    ? requestedProductionDefaultSelector
    : "workflow_recovery_blocked";
  const defaultPromotionGateEnabled =
    options.defaultPromotionGateEnabled ?? defaultAuthorityTransferred;
  const requestedDefaultPromotionGateEligible =
    options.defaultPromotionGateEligible ?? defaultAuthorityTransferred;
  const defaultPromotionGateEligible =
    requestedDefaultPromotionGateEligible &&
    (!requireLivePromotionReadinessProof || livePromotionReadinessReady) &&
    (!requirePackageImportActivationApplyProof ||
      packageImportActivationApplyProofPassed);
  const activationIdGateProofBlockers =
    (options.requireActivationIdGateClickProof ?? defaultAuthorityTransferred)
      ? workflowHarnessActivationIdGateClickProofBlockers(
          options.activationIdGateClickProof,
          {
            nowMs: options.activationIdGateProofNowMs,
            maxAgeMs: options.activationIdGateProofMaxAgeMs,
          },
        )
      : [];
  const defaultPromotionGateActivationBlockers = uniqueStrings([
    ...(options.defaultPromotionGateActivationBlockers ??
      (requestedDefaultPromotionGateEligible
        ? []
        : ["promotion_gate_disabled"])),
    ...activationIdGateProofBlockers,
    ...livePromotionReadinessBlockers,
    ...defaultLivePromotionInvariantBlockers,
  ]);
  const activationBlockers = uniqueStrings([
    ...(options.activationBlockers ?? []),
    ...activationIdGateProofBlockers,
    ...livePromotionReadinessBlockers,
    ...defaultLivePromotionInvariantBlockers,
  ]);
  const defaultPromotionGatePolicyDecision =
    options.defaultPromotionGatePolicyDecision ??
    (defaultPromotionGateEligible
      ? "promote_blessed_workflow_default_for_non_mutating_turn"
      : "block_workflow_default_until_gates_pass");
  return {
    schemaVersion: "workflow.harness.live-handoff.v1",
    selector,
    availableSelectors: [
      "workflow_recovery_blocked",
      "blessed_workflow_gated",
      "blessed_workflow_live_canary",
      "blessed_workflow_live_default",
    ],
    productionDefaultSelector,
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    componentVersionSet: defaultHarnessComponentVersionSet(),
    canaryStatus: options.canaryStatus ?? "passed",
    canaryTurnRoutedThroughWorkflow:
      options.canaryTurnRoutedThroughWorkflow ?? true,
    executionBoundaryId:
      "harness-canary-boundary:default-agent-harness:verification_output",
    executionBoundaryIds: options.executionBoundaryIds ?? [
      "harness-canary-boundary:default-agent-harness:cognition",
      "harness-canary-boundary:default-agent-harness:routing_model",
      "harness-canary-boundary:default-agent-harness:verification_output",
      "harness-canary-boundary:default-agent-harness:authority_tooling",
    ],
    executionBoundaryClusterIds: options.executionBoundaryClusterIds ?? [
      "cognition",
      "routing_model",
      "verification_output",
      "authority_tooling",
    ],
    executionBoundaryStatus: "passed",
    executionBoundaryExecutor:
      "crate::project::execute_workflow_harness_canary_node",
    defaultAuthorityTransferred: effectiveDefaultAuthorityTransferred,
    runtimeAuthority: effectiveDefaultAuthorityTransferred
      ? (options.runtimeAuthority ?? "blessed_workflow_activation_default")
      : "blessed_workflow_activation_canary",
    recoveryMode,
    recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    recoveryAvailable: true,
    recoveryBlockers: activationBlockers,
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: options.rollbackAvailable ?? true,
    policyDecision: effectiveDefaultAuthorityTransferred
      ? (options.policyDecision ??
        "promote_blessed_workflow_default_for_non_mutating_turn")
      : "allow_blessed_workflow_live_canary",
    gatedClusterIds: options.gatedClusterIds ?? [
      "cognition",
      "routing_model",
      "verification_output",
      "authority_tooling",
    ],
    nodeTimelineAttemptIds: options.nodeTimelineAttemptIds ?? [],
    receiptIds: options.receiptIds ?? [],
    replayFixtureRefs: options.replayFixtureRefs ?? [],
    livePromotionReadinessProof: options.livePromotionReadinessProof ?? null,
    livePromotionReadinessReady,
    livePromotionReadinessBlockers,
    livePromotionReadinessPolicyDecision:
      options.livePromotionReadinessProof?.policyDecision ??
      (requireLivePromotionReadinessProof
        ? "block_default_harness_live_promotion_readiness"
        : "not_required_for_canary_handoff"),
    defaultLivePromotionInvariantIds,
    defaultLivePromotionInvariantBlockers,
    reviewedImportActivationApplyProofPresent:
      packageImportActivationApplyProofPresent,
    reviewedImportActivationApplyProofPassed:
      packageImportActivationApplyProofPassed,
    reviewedImportActivationApplyProofBlockers:
      packageImportActivationApplyProofBlockers,
    reviewedImportActivationApplyActivationId:
      options.packageImportActivationApplyProof?.activationResult
        ?.activationId ?? null,
    activationBlockers,
    defaultPromotionGate: {
      configKey: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
      enabled: defaultPromotionGateEnabled,
      eligible: defaultPromotionGateEligible,
      nonMutatingOnly: true,
      selector,
      productionDefaultSelector,
      defaultAuthorityTransferred: effectiveDefaultAuthorityTransferred,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      requiredInvariantIds: defaultLivePromotionInvariantIds,
      invariantBlockers: defaultLivePromotionInvariantBlockers,
      activationBlockers: defaultPromotionGateActivationBlockers,
      policyDecision: defaultPromotionGatePolicyDecision,
    },
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

export function makeHarnessRuntimeSelectorDecision(
  options: {
    decisionId?: string;
    requestedSelector?: WorkflowHarnessRuntimeSelectorDecision["requestedSelector"];
    selectedSelector?: WorkflowHarnessRuntimeSelectorDecision["selectedSelector"];
    productionDefaultSelector?: WorkflowHarnessRuntimeSelectorDecision["productionDefaultSelector"];
    canaryEligible?: boolean;
    canaryBlockers?: string[];
    executionMode?: WorkflowHarnessExecutionMode;
    actualRuntimeAuthority?: WorkflowHarnessRuntimeSelectorDecision["actualRuntimeAuthority"];
    policyDecision?: string;
    routeReason?: string;
    defaultPromotionGateEnabled?: boolean;
    defaultPromotionGateEligible?: boolean;
    defaultPromotionGateAuthorityTransferred?: boolean;
    defaultPromotionGateActivationBlockers?: string[];
    defaultPromotionGatePolicyDecision?: string;
    livePromotionReadinessProof?: WorkflowHarnessLivePromotionReadinessProof | null;
    requireLivePromotionReadinessProof?: boolean;
    activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof | null;
    activationIdGateProofNowMs?: number;
    activationIdGateProofMaxAgeMs?: number;
    requireActivationIdGateClickProof?: boolean;
    packageImportActivationApplyProof?: WorkflowHarnessPackageImportActivationApplyProof | null;
    packageImportActivationApplyProofNowMs?: number;
    packageImportActivationApplyProofMaxAgeMs?: number;
    requirePackageImportActivationApplyProof?: boolean;
    evidenceRefs?: string[];
  } = {},
): WorkflowHarnessRuntimeSelectorDecision {
  const requestedSelectedSelector =
    options.selectedSelector ?? "blessed_workflow_live_canary";
  const defaultRequested =
    requestedSelectedSelector === "blessed_workflow_live_default";
  const requireLivePromotionReadinessProof =
    options.requireLivePromotionReadinessProof ?? defaultRequested;
  const livePromotionReadinessBlockers = requireLivePromotionReadinessProof
    ? workflowHarnessLivePromotionReadinessProofBlockers(
        options.livePromotionReadinessProof,
      )
    : [];
  const livePromotionReadinessReady =
    requireLivePromotionReadinessProof &&
    livePromotionReadinessBlockers.length === 0;
  const requirePackageImportActivationApplyProof =
    options.requirePackageImportActivationApplyProof ?? defaultRequested;
  const packageImportActivationApplyProofBlockers =
    requirePackageImportActivationApplyProof
      ? workflowHarnessPackageImportActivationApplyProofBlockers(
          options.packageImportActivationApplyProof,
          {
            nowMs: options.packageImportActivationApplyProofNowMs,
            maxAgeMs: options.packageImportActivationApplyProofMaxAgeMs,
          },
        )
      : [];
  const packageImportActivationApplyProofPresent = Boolean(
    options.packageImportActivationApplyProof,
  );
  const packageImportActivationApplyProofPassed =
    packageImportActivationApplyProofPresent &&
    packageImportActivationApplyProofBlockers.length === 0;
  const defaultLivePromotionInvariantIds =
    requirePackageImportActivationApplyProof
      ? [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT]
      : [];
  const defaultLivePromotionInvariantBlockers = uniqueStrings([
    ...packageImportActivationApplyProofBlockers,
  ]);
  const requestedCanaryEligible =
    options.canaryEligible ??
    (requestedSelectedSelector === "blessed_workflow_live_canary" ||
      requestedSelectedSelector === "blessed_workflow_live_default");
  const requestedDefaultPromotionGateEligible =
    options.defaultPromotionGateEligible ?? defaultRequested;
  const requestedDefaultPromotionAuthorityTransferred =
    options.defaultPromotionGateAuthorityTransferred ?? defaultRequested;
  const selectedSelector =
    defaultRequested &&
    (!livePromotionReadinessReady ||
      !requestedDefaultPromotionGateEligible ||
      defaultLivePromotionInvariantBlockers.length > 0)
      ? requestedCanaryEligible
        ? "blessed_workflow_live_canary"
        : "workflow_recovery_blocked"
      : requestedSelectedSelector;
  const workflowSelected =
    selectedSelector === "blessed_workflow_live_canary" ||
    selectedSelector === "blessed_workflow_live_default";
  const defaultSelected = selectedSelector === "blessed_workflow_live_default";
  const requestedProductionDefaultSelector =
    options.productionDefaultSelector ??
    (defaultRequested ? "blessed_workflow_live_default" : "workflow_recovery_blocked");
  const productionDefaultSelector = defaultSelected
    ? requestedProductionDefaultSelector
    : "workflow_recovery_blocked";
  const defaultPromotionGateEnabled =
    options.defaultPromotionGateEnabled ?? defaultRequested;
  const defaultPromotionGateEligible =
    requestedDefaultPromotionGateEligible &&
    defaultSelected &&
    (!requireLivePromotionReadinessProof || livePromotionReadinessReady) &&
    (!requirePackageImportActivationApplyProof ||
      packageImportActivationApplyProofPassed);
  const activationIdGateProofBlockers =
    (options.requireActivationIdGateClickProof ?? defaultRequested)
      ? workflowHarnessActivationIdGateClickProofBlockers(
          options.activationIdGateClickProof,
          {
            nowMs: options.activationIdGateProofNowMs,
            maxAgeMs: options.activationIdGateProofMaxAgeMs,
          },
        )
      : [];
  const defaultPromotionGateAuthorityTransferred =
    requestedDefaultPromotionAuthorityTransferred &&
    defaultSelected &&
    (!requireLivePromotionReadinessProof || livePromotionReadinessReady) &&
    (!requirePackageImportActivationApplyProof ||
      packageImportActivationApplyProofPassed);
  const recoveryMode = defaultSelected
    ? "restore_prior_workflow_activation"
    : "fail_closed";
  const defaultPromotionGateActivationBlockers = uniqueStrings([
    ...(options.defaultPromotionGateActivationBlockers ??
      (requestedDefaultPromotionGateEligible
        ? []
        : ["promotion_gate_disabled"])),
    ...activationIdGateProofBlockers,
    ...livePromotionReadinessBlockers,
    ...defaultLivePromotionInvariantBlockers,
  ]);
  const defaultPromotionGatePolicyDecision =
    options.defaultPromotionGatePolicyDecision ??
    (defaultPromotionGateEligible
      ? "promote_blessed_workflow_default_for_non_mutating_turn"
      : "block_workflow_default_until_gates_pass");
  return {
    schemaVersion: "workflow.harness.runtime-selector.v1",
    decisionId:
      options.decisionId ?? "harness-selector:default-agent-harness:canary",
    requestedSelector: options.requestedSelector ?? "auto_canary",
    selectedSelector,
    productionDefaultSelector,
    canaryEligible: requestedCanaryEligible && workflowSelected,
    canaryBlockers: options.canaryBlockers ?? [],
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode:
      options.executionMode ?? (workflowSelected ? "live" : "gated"),
    actualRuntimeAuthority: defaultSelected
      ? (options.actualRuntimeAuthority ??
        "blessed_workflow_activation_default")
      : workflowSelected
        ? "blessed_workflow_activation_canary"
        : "workflow_recovery_fail_closed",
    recoveryMode,
    recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    recoveryAvailable: true,
    recoveryBlockers: uniqueStrings([
      ...activationIdGateProofBlockers,
      ...livePromotionReadinessBlockers,
      ...defaultLivePromotionInvariantBlockers,
      ...(options.canaryBlockers ?? []),
    ]),
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    policyDecision: defaultSelected
      ? (options.policyDecision ??
        "promote_blessed_workflow_default_for_non_mutating_turn")
      : workflowSelected
        ? "allow_blessed_workflow_live_canary"
        : "block_workflow_default_until_gates_pass",
    routeReason:
      options.routeReason ??
      (defaultSelected
        ? "Blessed workflow activation is promoted to the default runtime selector for a non-mutating turn."
        : defaultRequested && defaultLivePromotionInvariantBlockers.length > 0
          ? "Blessed workflow default promotion is blocked until reviewed import activation apply proof is present in the selected evidence bundle."
          : defaultRequested
            ? "Blessed workflow default promotion is blocked until the live-promotion readiness proof passes."
            : workflowSelected
              ? "Turn is non-mutating and eligible for blessed workflow canary routing."
              : "Turn is blocked until workflow recovery gates pass."),
    livePromotionReadinessProof: options.livePromotionReadinessProof ?? null,
    livePromotionReadinessReady,
    livePromotionReadinessBlockers,
    livePromotionReadinessPolicyDecision:
      options.livePromotionReadinessProof?.policyDecision ??
      (requireLivePromotionReadinessProof
        ? "block_default_harness_live_promotion_readiness"
        : "not_required_for_canary_selector"),
    defaultLivePromotionInvariantIds,
    defaultLivePromotionInvariantBlockers,
    reviewedImportActivationApplyProofPresent:
      packageImportActivationApplyProofPresent,
    reviewedImportActivationApplyProofPassed:
      packageImportActivationApplyProofPassed,
    reviewedImportActivationApplyProofBlockers:
      packageImportActivationApplyProofBlockers,
    reviewedImportActivationApplyActivationId:
      options.packageImportActivationApplyProof?.activationResult
        ?.activationId ?? null,
    defaultPromotionGate: {
      configKey: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
      enabled: defaultPromotionGateEnabled,
      eligible: defaultPromotionGateEligible,
      nonMutatingOnly: true,
      selector: selectedSelector,
      productionDefaultSelector,
      defaultAuthorityTransferred: defaultPromotionGateAuthorityTransferred,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      requiredInvariantIds: defaultLivePromotionInvariantIds,
      invariantBlockers: defaultLivePromotionInvariantBlockers,
      activationBlockers: defaultPromotionGateActivationBlockers,
      policyDecision: defaultPromotionGatePolicyDecision,
    },
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

const DEFAULT_COGNITION_LIVE_ADAPTER_COMPONENTS: Array<{
  kind: WorkflowHarnessComponentKind;
  attemptSlug: string;
  policyDecision: string;
}> = [
  {
    kind: "planner",
    attemptSlug: "planner_envelope",
    policyDecision: "accept_workflow_planner_objective_envelope",
  },
  {
    kind: "prompt_assembler",
    attemptSlug: "prompt_assembler_envelope",
    policyDecision: "accept_workflow_prompt_assembly_hash_envelope",
  },
  {
    kind: "task_state",
    attemptSlug: "task_state_envelope",
    policyDecision: "accept_workflow_task_state_envelope",
  },
];

const DEFAULT_COGNITION_GATE_ADAPTER_COMPONENTS: Array<{
  kind: WorkflowHarnessComponentKind;
  attemptSlug: string;
  policyDecision: string;
}> = [
  {
    kind: "uncertainty_gate",
    attemptSlug: "uncertainty_gate_envelope",
    policyDecision: "accept_workflow_uncertainty_gate_envelope",
  },
  {
    kind: "budget_gate",
    attemptSlug: "budget_gate_envelope",
    policyDecision: "accept_workflow_budget_gate_envelope",
  },
  {
    kind: "capability_sequencer",
    attemptSlug: "capability_sequencer_envelope",
    policyDecision: "accept_workflow_capability_sequence_envelope",
  },
];

const DEFAULT_ROUTING_MODEL_GATE_ADAPTER_COMPONENTS: Array<{
  kind: WorkflowHarnessComponentKind;
  attemptSlug: string;
  policyDecision: string;
}> = [
  {
    kind: "model_router",
    attemptSlug: "routing_model_model_router_envelope",
    policyDecision: "accept_routing_model_adapter_route_binding",
  },
  {
    kind: "model_call",
    attemptSlug: "routing_model_model_call_envelope",
    policyDecision: "accept_routing_model_adapter_model_call_contract",
  },
  {
    kind: "tool_router",
    attemptSlug: "routing_model_tool_router_envelope",
    policyDecision:
      "accept_routing_model_adapter_tool_route_without_live_invocation",
  },
];

const DEFAULT_VERIFICATION_OUTPUT_GATE_ADAPTER_COMPONENTS: Array<{
  kind: WorkflowHarnessComponentKind;
  attemptSlug: string;
  policyDecision: string;
}> = [
  {
    kind: "postcondition_synthesizer",
    attemptSlug: "verification_output_postcondition_synthesizer_envelope",
    policyDecision: "accept_verification_output_postcondition_envelope",
  },
  {
    kind: "verifier",
    attemptSlug: "verification_output_verifier_envelope",
    policyDecision: "accept_verification_output_verifier_envelope",
  },
  {
    kind: "completion_gate",
    attemptSlug: "verification_output_completion_gate_envelope",
    policyDecision: "accept_verification_output_completion_gate_envelope",
  },
  {
    kind: "receipt_writer",
    attemptSlug: "verification_output_receipt_writer_envelope",
    policyDecision: "accept_verification_output_receipt_writer_envelope",
  },
  {
    kind: "quality_ledger",
    attemptSlug: "verification_output_quality_ledger_envelope",
    policyDecision: "accept_verification_output_quality_ledger_envelope",
  },
  {
    kind: "output_writer",
    attemptSlug: "verification_output_output_writer_envelope",
    policyDecision: "accept_verification_output_output_writer_envelope",
  },
];

const DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS: Array<{
  kind: WorkflowHarnessComponentKind;
  attemptSlug: string;
  policyDecision: string;
}> = [
  {
    kind: "policy_gate",
    attemptSlug: "authority_tooling_policy_gate_envelope",
    policyDecision: "accept_authority_tooling_policy_gate_adapter_envelope",
  },
  {
    kind: "approval_gate",
    attemptSlug: "authority_tooling_approval_gate_envelope",
    policyDecision: "accept_authority_tooling_approval_gate_adapter_envelope",
  },
  {
    kind: "dry_run_simulator",
    attemptSlug: "authority_tooling_dry_run_simulator_envelope",
    policyDecision: "accept_authority_tooling_dry_run_adapter_envelope",
  },
  {
    kind: "mcp_provider",
    attemptSlug: "authority_tooling_mcp_provider_envelope",
    policyDecision: "accept_authority_tooling_mcp_provider_adapter_envelope",
  },
  {
    kind: "mcp_tool_call",
    attemptSlug: "authority_tooling_mcp_tool_call_envelope",
    policyDecision: "accept_authority_tooling_mcp_tool_call_adapter_envelope",
  },
  {
    kind: "tool_call",
    attemptSlug: "authority_tooling_tool_call_envelope",
    policyDecision: "accept_authority_tooling_tool_call_adapter_envelope",
  },
  {
    kind: "connector_call",
    attemptSlug: "authority_tooling_connector_call_envelope",
    policyDecision: "accept_authority_tooling_connector_call_adapter_envelope",
  },
  {
    kind: "wallet_capability",
    attemptSlug: "authority_tooling_wallet_capability_envelope",
    policyDecision:
      "retain_authority_tooling_wallet_capability_adapter_without_grant",
  },
];

function makeDefaultHarnessAdapterResult(
  kind: WorkflowHarnessComponentKind,
  attemptSlug: string,
  policyDecision: string,
  attemptIndex: number,
  executionMode: "live" | "gated" | "shadow",
  options: { hashSlug?: string } = {},
): WorkflowHarnessComponentAdapterResult {
  const component = componentFor(kind);
  const hashSlug = options.hashSlug ?? attemptSlug;
  const replay = {
    ...replayEnvelopeFor(component),
    fixtureRef: `harness-default-dispatch:fixture-${attemptSlug}`,
  };
  const actionFrame = {
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    workflowVersion: DEFAULT_AGENT_HARNESS_VERSION,
    workflowHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: executionMode as WorkflowHarnessExecutionMode,
    nodeId: `harness.${kind}`,
    componentId: component.componentId,
    componentVersion: component.version,
    componentKind: kind,
    readiness: component.readiness,
    kernelRef: component.kernelRef,
    slotIds: slotIdsFor(kind),
    deterministicEnvelope: replay.deterministicEnvelope,
    replay,
    eventKinds: component.emittedEvents,
    evidenceKeys: component.evidence,
  };
  const receiptId = `harness-default-dispatch:receipt-${attemptSlug}`;
  const outputHash = `sha256:${hashSlug}`;
  return {
    schemaVersion: "workflow.harness.component-adapter-result.v1",
    invocationId: `default-dispatch:${attemptSlug}`,
    actionFrame,
    nodeAttempt: {
      attemptId: `${actionFrame.nodeId}:default-dispatch:${attemptSlug}`,
      harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      harnessHash: DEFAULT_AGENT_HARNESS_HASH,
      workflowNodeId: actionFrame.nodeId,
      componentId: actionFrame.componentId,
      componentKind: kind,
      executionMode,
      readiness: component.readiness,
      attemptIndex,
      status: executionMode,
      inputHash: `sha256:input-${hashSlug}`,
      outputHash,
      policyDecision,
      receiptIds: [receiptId],
      evidenceRefs: [
        `runtime-evidence:default`,
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      ],
      replay,
    },
    slotIds: actionFrame.slotIds,
    resultHash: outputHash,
    readiness: component.readiness,
    receiptIds: [receiptId],
    replay,
  };
}

function makeDefaultCognitionAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_COGNITION_LIVE_ADAPTER_COMPONENTS.map((component, index) =>
    makeDefaultHarnessAdapterResult(
      component.kind,
      component.attemptSlug,
      component.policyDecision,
      index + 1,
      "live",
    ),
  );
}

function makeDefaultCognitionShadowAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_COGNITION_LIVE_ADAPTER_COMPONENTS.map((component, index) =>
    makeDefaultHarnessAdapterResult(
      component.kind,
      `${component.attemptSlug}_shadow`,
      component.policyDecision,
      index + 24,
      "shadow",
      { hashSlug: component.attemptSlug },
    ),
  );
}

function makeDefaultCognitionGateAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_COGNITION_GATE_ADAPTER_COMPONENTS.map((component, index) =>
    makeDefaultHarnessAdapterResult(
      component.kind,
      component.attemptSlug,
      component.policyDecision,
      index + 4,
      "gated",
    ),
  );
}

const DEFAULT_COGNITION_NODE_AUTHORITY_COMPONENT_KINDS: WorkflowHarnessComponentKind[] =
  ["planner", "prompt_assembler", "task_state"];

const DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS: WorkflowHarnessComponentKind[] =
  ["model_router", "model_call", "tool_router"];

const DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS: WorkflowHarnessComponentKind[] =
  [
    "postcondition_synthesizer",
    "verifier",
    "completion_gate",
    "receipt_writer",
    "quality_ledger",
    "output_writer",
  ];

const DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS: WorkflowHarnessComponentKind[] =
  [
    "policy_gate",
    "approval_gate",
    "dry_run_simulator",
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ];

function makeCognitionNodeAuthorityGate(options: {
  dispatchAccepted: boolean;
  runtimeAuthority: string;
  activationBlockers: string[];
  adapterResults: WorkflowHarnessComponentAdapterResult[];
  actionFrameIds: string[];
  liveReadyComponentKinds: WorkflowHarnessComponentKind[];
}): WorkflowHarnessCognitionNodeAuthorityGate {
  const blockers: string[] = [];
  if (!options.dispatchAccepted) {
    blockers.push("cognition_node_authority_dispatch_not_live");
  }
  if (options.runtimeAuthority !== "blessed_workflow_activation_default") {
    blockers.push("cognition_node_authority_runtime_authority_not_workflow");
  }
  for (const blocker of options.activationBlockers) {
    blockers.push(`cognition_node_authority_activation_blocked:${blocker}`);
  }
  if (options.adapterResults.length < DEFAULT_COGNITION_NODE_AUTHORITY_COMPONENT_KINDS.length) {
    blockers.push("cognition_node_authority_adapter_result_missing");
  }
  if (options.actionFrameIds.length < DEFAULT_COGNITION_NODE_AUTHORITY_COMPONENT_KINDS.length) {
    blockers.push("cognition_node_authority_action_frame_missing");
  }
  for (const componentKind of DEFAULT_COGNITION_NODE_AUTHORITY_COMPONENT_KINDS) {
    if (!options.liveReadyComponentKinds.includes(componentKind)) {
      blockers.push(`cognition_node_authority_live_ready_missing:${componentKind}`);
    }
    const result = options.adapterResults.find(
      (candidate) => candidate.actionFrame.componentKind === componentKind,
    );
    if (!result) {
      blockers.push(`cognition_node_authority_result_missing:${componentKind}`);
      continue;
    }
    if (
      result.actionFrame.executionMode !== "live" ||
      result.actionFrame.readiness !== "live_ready" ||
      result.nodeAttempt.executionMode !== "live" ||
      result.nodeAttempt.status !== "live"
    ) {
      blockers.push(`cognition_node_authority_result_not_live:${componentKind}`);
    }
    if (result.actionFrame.nodeId !== result.nodeAttempt.workflowNodeId) {
      blockers.push(`cognition_node_authority_node_mismatch:${componentKind}`);
    }
    if (!result.receiptIds.length || !result.nodeAttempt.receiptIds.length) {
      blockers.push(`cognition_node_authority_receipt_missing:${componentKind}`);
    }
    if (!result.replay.fixtureRef || !result.nodeAttempt.replay.fixtureRef) {
      blockers.push(`cognition_node_authority_replay_fixture_missing:${componentKind}`);
    }
  }

  const uniqueBlockers = uniqueStrings(blockers);
  const attemptIds = options.adapterResults.map(
    (result) => result.nodeAttempt.attemptId,
  );
  const receiptIds = options.adapterResults.flatMap(
    (result) => result.nodeAttempt.receiptIds,
  );
  const replayFixtureRefs = options.adapterResults
    .map((result) => result.nodeAttempt.replay.fixtureRef)
    .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));

  return {
    schemaVersion:
      "workflow.harness.default-runtime-dispatch.cognition-node-authority.v1",
    gateId: "cognition-node-authority",
    authorityMode: "node_authoritative",
    authoritative: uniqueBlockers.length === 0,
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    requiredExecutionMode: "live",
    runtimeAuthority: options.runtimeAuthority,
    adapterMode: "workflow_component_adapter_live",
    componentKinds: DEFAULT_COGNITION_NODE_AUTHORITY_COMPONENT_KINDS,
    liveReadyComponentKinds: options.liveReadyComponentKinds,
    actionFrameIds: options.actionFrameIds,
    attemptIds,
    receiptIds: uniqueStrings(receiptIds),
    replayFixtureRefs: uniqueStrings(replayFixtureRefs),
    recoveryMode: "fail_closed",
    recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    recoveryAvailable: true,
    recoveryBlockers: uniqueBlockers,
    blockers: uniqueBlockers,
    policyDecision:
      uniqueBlockers.length === 0
        ? "allow_node_authoritative_cognition"
        : "block_node_authoritative_cognition",
  };
}

function makeRoutingModelNodeAuthorityGate(options: {
  dispatchAccepted: boolean;
  runtimeAuthority: string;
  activationBlockers: string[];
  adapterResults: WorkflowHarnessComponentAdapterResult[];
  actionFrameIds: string[];
  componentKinds: WorkflowHarnessComponentKind[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  shadowAttemptIds: string[];
  shadowReceiptIds: string[];
  shadowReplayFixtureRefs: string[];
  shadowDivergenceClasses: WorkflowHarnessDivergenceClass[];
  providerCanaryReady: boolean;
  providerCanaryOutputHashMatches: boolean;
  providerCanaryTranscriptMatches: boolean;
  visibleOutputReady: boolean;
  visibleOutputSelected: boolean;
  visibleOutputAuthority: string;
  selectedVisibleOutputAuthorityMatchesTranscript: boolean;
  priorWorkflowVisibleOutputHashMatchesSelected: boolean;
  readOnlyCapabilityRoutingReady: boolean;
  rollbackAvailable: boolean;
}): WorkflowHarnessRoutingModelNodeAuthorityGate {
  const blockers: string[] = [];
  if (!options.dispatchAccepted) {
    blockers.push("routing_model_node_authority_dispatch_not_live");
  }
  if (options.runtimeAuthority !== "blessed_workflow_activation_default") {
    blockers.push("routing_model_node_authority_runtime_authority_not_workflow");
  }
  for (const blocker of options.activationBlockers) {
    blockers.push(`routing_model_node_authority_activation_blocked:${blocker}`);
  }
  if (
    options.adapterResults.length <
    DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("routing_model_node_authority_adapter_result_missing");
  }
  if (
    options.actionFrameIds.length <
    DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("routing_model_node_authority_action_frame_missing");
  }
  if (options.shadowAttemptIds.length < DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS.length) {
    blockers.push("routing_model_node_authority_shadow_attempt_missing");
  }
  if (options.shadowReceiptIds.length < DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS.length) {
    blockers.push("routing_model_node_authority_shadow_receipt_missing");
  }
  if (
    options.shadowReplayFixtureRefs.length <
    DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("routing_model_node_authority_shadow_replay_fixture_missing");
  }
  if (
    !options.divergenceClasses.every(
      (divergenceClass) => divergenceClass === "none",
    ) ||
    !options.shadowDivergenceClasses.every(
      (divergenceClass) => divergenceClass === "none",
    )
  ) {
    blockers.push("routing_model_node_authority_divergence_not_clear");
  }
  if (!options.providerCanaryReady) {
    blockers.push("routing_model_node_authority_provider_canary_not_ready");
  }
  if (!options.providerCanaryOutputHashMatches) {
    blockers.push("routing_model_node_authority_provider_output_hash_mismatch");
  }
  if (!options.providerCanaryTranscriptMatches) {
    blockers.push("routing_model_node_authority_provider_transcript_mismatch");
  }
  if (!options.visibleOutputReady || !options.visibleOutputSelected) {
    blockers.push("routing_model_node_authority_visible_output_not_selected");
  }
  if (options.visibleOutputAuthority !== "workflow_model_provider_call") {
    blockers.push("routing_model_node_authority_visible_output_not_workflow");
  }
  if (!options.selectedVisibleOutputAuthorityMatchesTranscript) {
    blockers.push("routing_model_node_authority_transcript_authority_mismatch");
  }
  if (!options.priorWorkflowVisibleOutputHashMatchesSelected) {
    blockers.push("routing_model_node_authority_prior_workflow_hash_mismatch");
  }
  if (!options.rollbackAvailable) {
    blockers.push("routing_model_node_authority_rollback_not_ready");
  }
  for (const componentKind of DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS) {
    if (!options.componentKinds.includes(componentKind)) {
      blockers.push(`routing_model_node_authority_component_missing:${componentKind}`);
    }
    const result = options.adapterResults.find(
      (candidate) => candidate.actionFrame.componentKind === componentKind,
    );
    if (!result) {
      blockers.push(`routing_model_node_authority_result_missing:${componentKind}`);
      continue;
    }
    if (
      result.actionFrame.executionMode !== "gated" ||
      result.actionFrame.readiness !== "shadow_ready" ||
      result.nodeAttempt.executionMode !== "gated" ||
      result.nodeAttempt.status !== "gated"
    ) {
      blockers.push(`routing_model_node_authority_result_not_gated:${componentKind}`);
    }
    if (result.actionFrame.nodeId !== result.nodeAttempt.workflowNodeId) {
      blockers.push(`routing_model_node_authority_node_mismatch:${componentKind}`);
    }
    if (!result.receiptIds.length || !result.nodeAttempt.receiptIds.length) {
      blockers.push(`routing_model_node_authority_receipt_missing:${componentKind}`);
    }
    if (!result.replay.fixtureRef || !result.nodeAttempt.replay.fixtureRef) {
      blockers.push(`routing_model_node_authority_replay_fixture_missing:${componentKind}`);
    }
  }

  const uniqueBlockers = uniqueStrings(blockers);
  const attemptIds = options.adapterResults.map(
    (result) => result.nodeAttempt.attemptId,
  );
  const receiptIds = options.adapterResults.flatMap(
    (result) => result.nodeAttempt.receiptIds,
  );
  const replayFixtureRefs = options.adapterResults
    .map((result) => result.nodeAttempt.replay.fixtureRef)
    .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));

  return {
    schemaVersion:
      "workflow.harness.default-runtime-dispatch.routing-model-node-authority.v1",
    gateId: "routing-model-node-authority",
    authorityMode: "gated_node_authoritative",
    authoritative: uniqueBlockers.length === 0,
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    requiredExecutionMode: "gated",
    runtimeAuthority: options.runtimeAuthority,
    adapterMode: "workflow_component_adapter_gated",
    componentKinds: DEFAULT_ROUTING_MODEL_NODE_AUTHORITY_COMPONENT_KINDS,
    shadowReadyComponentKinds: options.componentKinds,
    actionFrameIds: options.actionFrameIds,
    attemptIds,
    receiptIds: uniqueStrings(receiptIds),
    replayFixtureRefs: uniqueStrings(replayFixtureRefs),
    shadowAttemptIds: options.shadowAttemptIds,
    shadowReceiptIds: options.shadowReceiptIds,
    shadowReplayFixtureRefs: options.shadowReplayFixtureRefs,
    divergenceClasses: options.divergenceClasses,
    shadowDivergenceClasses: options.shadowDivergenceClasses,
    providerCanaryReady: options.providerCanaryReady,
    visibleOutputSelected: options.visibleOutputSelected,
    visibleOutputAuthority: options.visibleOutputAuthority,
    readOnlyCapabilityRoutingReady: options.readOnlyCapabilityRoutingReady,
    rollbackAvailable: options.rollbackAvailable,
    recoveryMode: "fail_closed",
    recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    recoveryAvailable: true,
    recoveryBlockers: uniqueBlockers,
    blockers: uniqueBlockers,
    policyDecision:
      uniqueBlockers.length === 0
        ? "allow_gated_node_authoritative_routing_model"
        : "block_gated_node_authoritative_routing_model",
  };
}

function makeVerificationOutputNodeAuthorityGate(options: {
  dispatchAccepted: boolean;
  runtimeAuthority: string;
  activationBlockers: string[];
  adapterResults: WorkflowHarnessComponentAdapterResult[];
  actionFrameIds: string[];
  componentKinds: WorkflowHarnessComponentKind[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  shadowAttemptIds: string[];
  shadowReceiptIds: string[];
  shadowReplayFixtureRefs: string[];
  shadowDivergenceClasses: WorkflowHarnessDivergenceClass[];
  outputWriterHandoffReady: boolean;
  outputWriterMaterializationCanaryReady: boolean;
  outputWriterStagedWriteCanaryReady: boolean;
  outputWriterVisibleWriteReady: boolean;
  outputWriterVisibleWriteCommitted: boolean;
  rollbackAvailable: boolean;
}): WorkflowHarnessVerificationOutputNodeAuthorityGate {
  const blockers: string[] = [];
  if (!options.dispatchAccepted) {
    blockers.push("verification_output_node_authority_dispatch_not_live");
  }
  if (options.runtimeAuthority !== "blessed_workflow_activation_default") {
    blockers.push("verification_output_node_authority_runtime_authority_not_workflow");
  }
  for (const blocker of options.activationBlockers) {
    blockers.push(
      `verification_output_node_authority_activation_blocked:${blocker}`,
    );
  }
  if (
    options.adapterResults.length <
    DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("verification_output_node_authority_adapter_result_missing");
  }
  if (
    options.actionFrameIds.length <
    DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("verification_output_node_authority_action_frame_missing");
  }
  if (
    options.shadowAttemptIds.length <
    DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("verification_output_node_authority_shadow_attempt_missing");
  }
  if (
    options.shadowReceiptIds.length <
    DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("verification_output_node_authority_shadow_receipt_missing");
  }
  if (
    options.shadowReplayFixtureRefs.length <
    DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push(
      "verification_output_node_authority_shadow_replay_fixture_missing",
    );
  }
  if (
    !options.divergenceClasses.every(
      (divergenceClass) => divergenceClass === "none",
    ) ||
    !options.shadowDivergenceClasses.every(
      (divergenceClass) => divergenceClass === "none",
    )
  ) {
    blockers.push("verification_output_node_authority_divergence_not_clear");
  }
  if (!options.outputWriterHandoffReady) {
    blockers.push("verification_output_node_authority_handoff_not_ready");
  }
  if (!options.outputWriterMaterializationCanaryReady) {
    blockers.push(
      "verification_output_node_authority_materialization_canary_not_ready",
    );
  }
  if (!options.outputWriterStagedWriteCanaryReady) {
    blockers.push(
      "verification_output_node_authority_staged_write_canary_not_ready",
    );
  }
  if (!options.outputWriterVisibleWriteReady) {
    blockers.push("verification_output_node_authority_visible_write_not_ready");
  }
  if (!options.outputWriterVisibleWriteCommitted) {
    blockers.push(
      "verification_output_node_authority_visible_write_not_committed",
    );
  }
  if (!options.rollbackAvailable) {
    blockers.push("verification_output_node_authority_rollback_not_ready");
  }
  for (const componentKind of DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS) {
    if (!options.componentKinds.includes(componentKind)) {
      blockers.push(
        `verification_output_node_authority_component_missing:${componentKind}`,
      );
    }
    const result = options.adapterResults.find(
      (candidate) => candidate.actionFrame.componentKind === componentKind,
    );
    if (!result) {
      blockers.push(
        `verification_output_node_authority_result_missing:${componentKind}`,
      );
      continue;
    }
    if (
      result.actionFrame.executionMode !== "gated" ||
      result.actionFrame.readiness !== "shadow_ready" ||
      result.nodeAttempt.executionMode !== "gated" ||
      result.nodeAttempt.status !== "gated"
    ) {
      blockers.push(
        `verification_output_node_authority_result_not_gated:${componentKind}`,
      );
    }
    if (result.actionFrame.nodeId !== result.nodeAttempt.workflowNodeId) {
      blockers.push(
        `verification_output_node_authority_node_mismatch:${componentKind}`,
      );
    }
    if (!result.receiptIds.length || !result.nodeAttempt.receiptIds.length) {
      blockers.push(
        `verification_output_node_authority_receipt_missing:${componentKind}`,
      );
    }
    if (!result.replay.fixtureRef || !result.nodeAttempt.replay.fixtureRef) {
      blockers.push(
        `verification_output_node_authority_replay_fixture_missing:${componentKind}`,
      );
    }
  }

  const uniqueBlockers = uniqueStrings(blockers);
  const attemptIds = options.adapterResults.map(
    (result) => result.nodeAttempt.attemptId,
  );
  const receiptIds = options.adapterResults.flatMap(
    (result) => result.nodeAttempt.receiptIds,
  );
  const replayFixtureRefs = options.adapterResults
    .map((result) => result.nodeAttempt.replay.fixtureRef)
    .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));

  return {
    schemaVersion:
      "workflow.harness.default-runtime-dispatch.verification-output-node-authority.v1",
    gateId: "verification-output-node-authority",
    authorityMode: "gated_node_authoritative",
    authoritative: uniqueBlockers.length === 0,
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    requiredExecutionMode: "gated",
    runtimeAuthority: options.runtimeAuthority,
    adapterMode: "workflow_component_adapter_gated",
    componentKinds: DEFAULT_VERIFICATION_OUTPUT_NODE_AUTHORITY_COMPONENT_KINDS,
    shadowReadyComponentKinds: options.componentKinds,
    actionFrameIds: options.actionFrameIds,
    attemptIds,
    receiptIds: uniqueStrings(receiptIds),
    replayFixtureRefs: uniqueStrings(replayFixtureRefs),
    shadowAttemptIds: options.shadowAttemptIds,
    shadowReceiptIds: options.shadowReceiptIds,
    shadowReplayFixtureRefs: options.shadowReplayFixtureRefs,
    divergenceClasses: options.divergenceClasses,
    shadowDivergenceClasses: options.shadowDivergenceClasses,
    outputWriterHandoffReady: options.outputWriterHandoffReady,
    outputWriterMaterializationCanaryReady:
      options.outputWriterMaterializationCanaryReady,
    outputWriterStagedWriteCanaryReady: options.outputWriterStagedWriteCanaryReady,
    outputWriterVisibleWriteReady: options.outputWriterVisibleWriteReady,
    outputWriterVisibleWriteCommitted: options.outputWriterVisibleWriteCommitted,
    rollbackAvailable: options.rollbackAvailable,
    recoveryMode: "fail_closed",
    recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    recoveryAvailable: true,
    recoveryBlockers: uniqueBlockers,
    blockers: uniqueBlockers,
    policyDecision:
      uniqueBlockers.length === 0
        ? "allow_gated_node_authoritative_verification_output"
        : "block_gated_node_authoritative_verification_output",
  };
}

function makeAuthorityToolingNodeAuthorityGate(options: {
  dispatchAccepted: boolean;
  runtimeAuthority: string;
  activationBlockers: string[];
  adapterResults: WorkflowHarnessComponentAdapterResult[];
  actionFrameIds: string[];
  componentKinds: WorkflowHarnessComponentKind[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  shadowAttemptIds: string[];
  shadowReceiptIds: string[];
  shadowReplayFixtureRefs: string[];
  shadowDivergenceClasses: WorkflowHarnessDivergenceClass[];
  readOnlyRouteAccepted: boolean;
  destructiveRouteDenied: boolean;
  mutatingToolCallsBlocked: boolean;
  sideEffectsExecuted: boolean;
  policyGateReady: boolean;
  toolRouterReady: boolean;
  dryRunSimulatorReady: boolean;
  approvalGateReady: boolean;
  gateLiveReady: boolean;
  readOnlyAuthorityCanaryReady: boolean;
  rollbackAvailable: boolean;
}): WorkflowHarnessAuthorityToolingNodeAuthorityGate {
  const blockers: string[] = [];
  if (!options.dispatchAccepted) {
    blockers.push("authority_tooling_node_authority_dispatch_not_live");
  }
  if (options.runtimeAuthority !== "blessed_workflow_activation_default") {
    blockers.push("authority_tooling_node_authority_runtime_authority_not_workflow");
  }
  for (const blocker of options.activationBlockers) {
    blockers.push(
      `authority_tooling_node_authority_activation_blocked:${blocker}`,
    );
  }
  if (
    options.adapterResults.length <
    DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("authority_tooling_node_authority_adapter_result_missing");
  }
  if (
    options.actionFrameIds.length <
    DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("authority_tooling_node_authority_action_frame_missing");
  }
  if (
    options.shadowAttemptIds.length <
    DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("authority_tooling_node_authority_shadow_attempt_missing");
  }
  if (
    options.shadowReceiptIds.length <
    DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push("authority_tooling_node_authority_shadow_receipt_missing");
  }
  if (
    options.shadowReplayFixtureRefs.length <
    DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS.length
  ) {
    blockers.push(
      "authority_tooling_node_authority_shadow_replay_fixture_missing",
    );
  }
  if (
    !options.divergenceClasses.every(
      (divergenceClass) => divergenceClass === "none",
    ) ||
    !options.shadowDivergenceClasses.every(
      (divergenceClass) => divergenceClass === "none",
    )
  ) {
    blockers.push("authority_tooling_node_authority_divergence_not_clear");
  }
  if (!options.readOnlyRouteAccepted) {
    blockers.push("authority_tooling_node_authority_read_only_route_not_accepted");
  }
  if (!options.destructiveRouteDenied) {
    blockers.push("authority_tooling_node_authority_destructive_route_not_denied");
  }
  if (!options.mutatingToolCallsBlocked) {
    blockers.push("authority_tooling_node_authority_mutating_tools_not_blocked");
  }
  if (options.sideEffectsExecuted) {
    blockers.push("authority_tooling_node_authority_side_effects_executed");
  }
  if (!options.policyGateReady) {
    blockers.push("authority_tooling_node_authority_policy_gate_not_ready");
  }
  if (!options.toolRouterReady) {
    blockers.push("authority_tooling_node_authority_tool_router_not_ready");
  }
  if (!options.dryRunSimulatorReady) {
    blockers.push("authority_tooling_node_authority_dry_run_not_ready");
  }
  if (!options.approvalGateReady) {
    blockers.push("authority_tooling_node_authority_approval_gate_not_ready");
  }
  if (!options.gateLiveReady) {
    blockers.push("authority_tooling_node_authority_gate_live_not_ready");
  }
  if (!options.readOnlyAuthorityCanaryReady) {
    blockers.push(
      "authority_tooling_node_authority_read_only_canary_not_ready",
    );
  }
  if (!options.rollbackAvailable) {
    blockers.push("authority_tooling_node_authority_rollback_not_ready");
  }
  for (const componentKind of DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS) {
    if (!options.componentKinds.includes(componentKind)) {
      blockers.push(
        `authority_tooling_node_authority_component_missing:${componentKind}`,
      );
    }
    const result = options.adapterResults.find(
      (candidate) => candidate.actionFrame.componentKind === componentKind,
    );
    if (!result) {
      blockers.push(
        `authority_tooling_node_authority_result_missing:${componentKind}`,
      );
      continue;
    }
    if (
      result.actionFrame.executionMode !== "gated" ||
      result.actionFrame.readiness !== "shadow_ready" ||
      result.nodeAttempt.executionMode !== "gated" ||
      result.nodeAttempt.status !== "gated"
    ) {
      blockers.push(
        `authority_tooling_node_authority_result_not_gated:${componentKind}`,
      );
    }
    if (result.actionFrame.nodeId !== result.nodeAttempt.workflowNodeId) {
      blockers.push(
        `authority_tooling_node_authority_node_mismatch:${componentKind}`,
      );
    }
    if (!result.receiptIds.length || !result.nodeAttempt.receiptIds.length) {
      blockers.push(
        `authority_tooling_node_authority_receipt_missing:${componentKind}`,
      );
    }
    if (!result.replay.fixtureRef || !result.nodeAttempt.replay.fixtureRef) {
      blockers.push(
        `authority_tooling_node_authority_replay_fixture_missing:${componentKind}`,
      );
    }
  }

  const uniqueBlockers = uniqueStrings(blockers);
  const attemptIds = options.adapterResults.map(
    (result) => result.nodeAttempt.attemptId,
  );
  const receiptIds = options.adapterResults.flatMap(
    (result) => result.nodeAttempt.receiptIds,
  );
  const replayFixtureRefs = options.adapterResults
    .map((result) => result.nodeAttempt.replay.fixtureRef)
    .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));

  return {
    schemaVersion:
      "workflow.harness.default-runtime-dispatch.authority-tooling-node-authority.v1",
    gateId: "authority-tooling-node-authority",
    authorityMode: "gated_node_authoritative",
    authoritative: uniqueBlockers.length === 0,
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    requiredExecutionMode: "gated",
    runtimeAuthority: options.runtimeAuthority,
    adapterMode: "workflow_component_adapter_gated",
    componentKinds: DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS,
    shadowReadyComponentKinds: options.componentKinds,
    actionFrameIds: options.actionFrameIds,
    attemptIds,
    receiptIds: uniqueStrings(receiptIds),
    replayFixtureRefs: uniqueStrings(replayFixtureRefs),
    shadowAttemptIds: options.shadowAttemptIds,
    shadowReceiptIds: options.shadowReceiptIds,
    shadowReplayFixtureRefs: options.shadowReplayFixtureRefs,
    divergenceClasses: options.divergenceClasses,
    shadowDivergenceClasses: options.shadowDivergenceClasses,
    readOnlyRouteAccepted: options.readOnlyRouteAccepted,
    destructiveRouteDenied: options.destructiveRouteDenied,
    mutatingToolCallsBlocked: options.mutatingToolCallsBlocked,
    sideEffectsExecuted: options.sideEffectsExecuted,
    policyGateReady: options.policyGateReady,
    toolRouterReady: options.toolRouterReady,
    dryRunSimulatorReady: options.dryRunSimulatorReady,
    approvalGateReady: options.approvalGateReady,
    gateLiveReady: options.gateLiveReady,
    readOnlyAuthorityCanaryReady: options.readOnlyAuthorityCanaryReady,
    rollbackAvailable: options.rollbackAvailable,
    recoveryMode: "fail_closed",
    recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    recoveryAvailable: true,
    recoveryBlockers: uniqueBlockers,
    blockers: uniqueBlockers,
    policyDecision:
      uniqueBlockers.length === 0
        ? "allow_gated_node_authoritative_authority_tooling"
        : "block_gated_node_authoritative_authority_tooling",
  };
}

function makeDefaultRoutingModelGateAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_ROUTING_MODEL_GATE_ADAPTER_COMPONENTS.map((component, index) =>
    makeDefaultHarnessAdapterResult(
      component.kind,
      component.attemptSlug,
      component.policyDecision,
      index + 7,
      "gated",
    ),
  );
}

function makeDefaultRoutingModelShadowAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_ROUTING_MODEL_GATE_ADAPTER_COMPONENTS.map((component, index) =>
    makeDefaultHarnessAdapterResult(
      component.kind,
      `${component.attemptSlug}_shadow`,
      component.policyDecision,
      index + 27,
      "shadow",
      { hashSlug: component.attemptSlug },
    ),
  );
}

function makeDefaultVerificationOutputGateAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_VERIFICATION_OUTPUT_GATE_ADAPTER_COMPONENTS.map(
    (component, index) =>
      makeDefaultHarnessAdapterResult(
        component.kind,
        component.attemptSlug,
        component.policyDecision,
        index + 10,
        "gated",
      ),
  );
}

function makeDefaultVerificationOutputShadowAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_VERIFICATION_OUTPUT_GATE_ADAPTER_COMPONENTS.map(
    (component, index) =>
      makeDefaultHarnessAdapterResult(
        component.kind,
        `${component.attemptSlug}_shadow`,
        component.policyDecision,
        index + 30,
        "shadow",
        { hashSlug: component.attemptSlug },
      ),
  );
}

function makeDefaultAuthorityToolingGateAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS.map(
    (component, index) =>
      makeDefaultHarnessAdapterResult(
        component.kind,
        component.attemptSlug,
        component.policyDecision,
        index + 16,
        "gated",
      ),
  );
}

function makeDefaultAuthorityToolingShadowAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS.map(
    (component, index) =>
      makeDefaultHarnessAdapterResult(
        component.kind,
        `${component.attemptSlug}_shadow`,
        component.policyDecision,
        index + 36,
        "shadow",
        { hashSlug: component.attemptSlug },
      ),
  );
}

function makeHarnessLivePromotionClusterReadiness(options: {
  clusterId: WorkflowHarnessPromotionClusterId;
  currentStatus?: WorkflowHarnessClusterPromotionStatus;
  componentKinds: WorkflowHarnessComponentKind[];
  readinessReady: boolean;
  receiptRefs: string[];
  replayFixtureRefs: string[];
  actionFrameIds: string[];
  attemptIds: string[];
  divergenceClasses: WorkflowHarnessLivePromotionClusterReadiness["divergenceClasses"];
  canaryReady: boolean;
  rollbackReady: boolean;
  rollbackTarget: string;
  blockers?: string[];
}): WorkflowHarnessLivePromotionClusterReadiness {
  const receiptRefs = uniqueStrings(options.receiptRefs);
  const replayFixtureRefs = uniqueStrings(options.replayFixtureRefs);
  const attemptIds = uniqueStrings(options.attemptIds);
  const actionFrameIds = uniqueStrings(options.actionFrameIds);
  const blockingDivergenceCount = options.divergenceClasses.filter(
    (divergenceClass) =>
      divergenceClass !== "none" && divergenceClass !== "harmless_metadata",
  ).length;
  const unclassifiedDivergenceCount = options.divergenceClasses.filter(
    (divergenceClass) => divergenceClass === "unclassified",
  ).length;
  const receiptReady = receiptRefs.length > 0;
  const replayGateReady =
    replayFixtureRefs.length > 0 && blockingDivergenceCount === 0;
  const divergenceReady =
    blockingDivergenceCount === 0 && unclassifiedDivergenceCount === 0;
  const blockers = uniqueStrings([
    ...(options.blockers ?? []),
    ...(options.readinessReady
      ? []
      : [`${options.clusterId}_readiness_not_ready`]),
    ...(receiptReady ? [] : [`${options.clusterId}_receipts_missing`]),
    ...(replayGateReady ? [] : [`${options.clusterId}_replay_gate_not_ready`]),
    ...(options.canaryReady ? [] : [`${options.clusterId}_canary_not_ready`]),
    ...(options.rollbackReady
      ? []
      : [`${options.clusterId}_rollback_not_ready`]),
    ...(divergenceReady ? [] : [`${options.clusterId}_divergence_not_ready`]),
  ]);

  return {
    clusterId: options.clusterId,
    label: HARNESS_PROMOTION_CLUSTER_LABELS[options.clusterId],
    currentStatus: options.currentStatus ?? "gated",
    targetExecutionMode: "live",
    componentKinds: options.componentKinds,
    readinessReady: options.readinessReady,
    receiptReady,
    replayGateReady,
    canaryReady: options.canaryReady,
    rollbackReady: options.rollbackReady,
    divergenceReady,
    blockingDivergenceCount,
    unclassifiedDivergenceCount,
    attemptIds,
    receiptRefs,
    replayFixtureRefs,
    actionFrameIds,
    divergenceClasses: options.divergenceClasses,
    rollbackTarget: options.rollbackTarget,
    blockers,
    decision:
      blockers.length === 0
        ? "allow_default_harness_live_cluster_promotion"
        : "block_default_harness_live_cluster_promotion",
  };
}

export function makeHarnessLiveShadowComparisonGate(options: {
  comparisons?: WorkflowHarnessShadowComparison[];
  dispatchId?: string;
  receiptRefs?: string[];
  replayFixtureRefs?: string[];
  evidenceRefs?: string[];
} = {}): WorkflowHarnessLiveShadowComparisonGate {
  const requiredComponentKinds =
    HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS;
  const comparisons = options.comparisons ?? [];
  const componentKinds = uniqueStrings(
    comparisons.map((comparison) => comparison.componentKind),
  ) as WorkflowHarnessComponentKind[];
  const blockingDivergenceCount = comparisons.filter(
    (comparison) => comparison.blocking,
  ).length;
  const unclassifiedDivergenceCount = comparisons.filter(
    (comparison) => comparison.divergence === "unclassified",
  ).length;
  const receiptReady =
    (options.receiptRefs ?? []).length > 0 ||
    (comparisons.length > 0 &&
      comparisons.every(
        (comparison) =>
          (comparison.liveReceiptRefs?.length ?? 0) > 0 &&
          (comparison.shadowReceiptRefs?.length ?? 0) > 0,
      ));
  const replayReady =
    (options.replayFixtureRefs ?? []).length > 0 ||
    (comparisons.length > 0 &&
      comparisons.every(
        (comparison) =>
          Boolean(comparison.liveReplayFixtureRef) &&
          Boolean(comparison.shadowReplayFixtureRef),
      ));
  const allRequiredComponentsPresent = requiredComponentKinds.every(
    (componentKind) => componentKinds.includes(componentKind),
  );
  const divergenceReady =
    blockingDivergenceCount === 0 && unclassifiedDivergenceCount === 0;
  const blockers = uniqueStrings([
    ...(allRequiredComponentsPresent
      ? []
      : ["live_shadow_comparison_required_components_missing"]),
    ...(comparisons.length >= requiredComponentKinds.length
      ? []
      : ["live_shadow_comparison_required_count_missing"]),
    ...(receiptReady ? [] : ["live_shadow_comparison_receipts_missing"]),
    ...(replayReady ? [] : ["live_shadow_comparison_replay_missing"]),
    ...(divergenceReady ? [] : ["live_shadow_comparison_divergence_not_ready"]),
  ]);
  const ready = blockers.length === 0;

  return {
    schemaVersion: "workflow.harness.live-shadow-comparison-gate.v1",
    gateId: "p0-live-shadow-comparison-gate",
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    targetExecutionMode: "live",
    requiredComponentKinds,
    componentKinds,
    comparisonCount: comparisons.length,
    requiredComparisonCount: requiredComponentKinds.length,
    allRequiredComponentsPresent,
    receiptReady,
    replayReady,
    divergenceReady,
    blockingDivergenceCount,
    unclassifiedDivergenceCount,
    ready,
    policyDecision: ready
      ? "allow_default_harness_live_shadow_comparison_gate"
      : "block_default_harness_live_shadow_comparison_gate",
    blockers,
    evidenceRefs: uniqueStrings([
      options.dispatchId,
      `harness-live-shadow-comparison-gate:${DEFAULT_AGENT_HARNESS_WORKFLOW_ID}`,
      ...(options.receiptRefs ?? []),
      ...(options.replayFixtureRefs ?? []),
      ...comparisons.flatMap((comparison) => comparison.evidenceRefs ?? []),
      ...(options.evidenceRefs ?? []),
    ]),
  };
}

export function makeHarnessLivePromotionReadinessProof(options: {
  proofId?: string;
  dispatchId: string;
  workflowId?: string;
  activationId?: string;
  harnessHash?: string;
  clusterReadiness: WorkflowHarnessLivePromotionClusterReadiness[];
  liveShadowComparisonGate?: WorkflowHarnessLiveShadowComparisonGate;
  activationBlockers?: string[];
  invalidForkLiveActivationBlocked?: boolean;
  rollbackAvailable?: boolean;
  rollbackTarget?: string;
  evidenceRefs?: string[];
}): WorkflowHarnessLivePromotionReadinessProof {
  const workflowId = options.workflowId ?? DEFAULT_AGENT_HARNESS_WORKFLOW_ID;
  const activationId =
    options.activationId ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
  const harnessHash = options.harnessHash ?? DEFAULT_AGENT_HARNESS_HASH;
  const requiredClusterIds: WorkflowHarnessPromotionClusterId[] = [
    "cognition",
    "routing_model",
    "verification_output",
    "authority_tooling",
  ];
  const clusterReadiness = requiredClusterIds.map(
    (clusterId) =>
      options.clusterReadiness.find(
        (cluster) => cluster.clusterId === clusterId,
      ) ??
      makeHarnessLivePromotionClusterReadiness({
        clusterId,
        currentStatus: "blocked",
        componentKinds: HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId],
        readinessReady: false,
        receiptRefs: [],
        replayFixtureRefs: [],
        actionFrameIds: [],
        attemptIds: [],
        divergenceClasses: ["unclassified"],
        canaryReady: false,
        rollbackReady: false,
        rollbackTarget:
          options.rollbackTarget ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        blockers: [`${clusterId}_readiness_record_missing`],
      }),
  );
  const activationBlockers = uniqueStrings(options.activationBlockers ?? []);
  const allClustersReady = clusterReadiness.every(
    (cluster) => cluster.blockers.length === 0,
  );
  const invalidForkLiveActivationBlocked =
    options.invalidForkLiveActivationBlocked ?? true;
  const rollbackAvailable = options.rollbackAvailable ?? true;
  const rollbackTarget =
    options.rollbackTarget ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
  const liveShadowComparisonGate =
    options.liveShadowComparisonGate ??
    makeHarnessLiveShadowComparisonGate({
      dispatchId: options.dispatchId,
      comparisons: HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS.map(
        (componentKind) => ({
          workflowNodeId: `harness.${componentKind}`,
          componentKind,
          liveAttemptId: `harness-default-dispatch:attempt-${componentKind}`,
          shadowAttemptId: `harness-default-dispatch:attempt-${componentKind}_shadow`,
          divergence: "none",
          blocking: false,
          summary:
            "Canonical default promotion readiness includes a retained P0 live/shadow comparison.",
          evidenceRefs: [
            `harness-default-dispatch:receipt-${componentKind}`,
            `harness-default-dispatch:fixture-${componentKind}`,
          ],
          liveReceiptRefs: [`harness-default-dispatch:receipt-${componentKind}`],
          shadowReceiptRefs: [
            `harness-default-dispatch:receipt-${componentKind}_shadow`,
          ],
          liveReplayFixtureRef: `harness-default-dispatch:fixture-${componentKind}`,
          shadowReplayFixtureRef: `harness-default-dispatch:fixture-${componentKind}_shadow`,
          liveInputHash: `sha256:${componentKind}`,
          shadowInputHash: `sha256:${componentKind}`,
          liveOutputHash: `sha256:${componentKind}`,
          shadowOutputHash: `sha256:${componentKind}`,
        }),
      ),
    });
  const liveShadowComparisonGateReady = liveShadowComparisonGate.ready;
  const promotionEligible =
    allClustersReady &&
    liveShadowComparisonGateReady &&
    activationBlockers.length === 0 &&
    invalidForkLiveActivationBlocked &&
    rollbackAvailable &&
    Boolean(rollbackTarget);

  return {
    schemaVersion: "workflow.harness.live-promotion-readiness.v1",
    proofId:
      options.proofId ??
      `harness-live-promotion-readiness:${workflowId}:${activationId}`,
    dispatchId: options.dispatchId,
    workflowId,
    activationId,
    harnessHash,
    targetExecutionMode: "live",
    requiredClusterIds,
    clusterReadiness,
    liveShadowComparisonGate,
    liveShadowComparisonGateReady,
    allClustersReady,
    promotionEligible,
    defaultLiveActivationReady: promotionEligible,
    invalidForkLiveActivationBlocked,
    rollbackAvailable,
    rollbackTarget,
    activationBlockers,
    policyDecision: promotionEligible
      ? "allow_default_harness_live_promotion_readiness"
      : "block_default_harness_live_promotion_readiness",
    evidenceRefs: uniqueStrings([
      options.dispatchId,
      `harness-live-promotion-readiness:${workflowId}`,
      ...liveShadowComparisonGate.evidenceRefs,
      ...clusterReadiness.flatMap((cluster) => [
        ...cluster.attemptIds,
        ...cluster.receiptRefs,
        ...cluster.replayFixtureRefs,
      ]),
      ...(options.evidenceRefs ?? []),
    ]),
  };
}

export function workflowHarnessLivePromotionReadinessProofBlockers(
  proof?: WorkflowHarnessLivePromotionReadinessProof | null,
): string[] {
  if (!proof) {
    return ["live_promotion_readiness_proof_missing"];
  }
  const blockers: string[] = [];
  const requiredClusterIds: WorkflowHarnessPromotionClusterId[] = [
    "cognition",
    "routing_model",
    "verification_output",
    "authority_tooling",
  ];

  if (proof.schemaVersion !== "workflow.harness.live-promotion-readiness.v1") {
    blockers.push("live_promotion_readiness_schema_mismatch");
  }
  if (proof.workflowId !== DEFAULT_AGENT_HARNESS_WORKFLOW_ID) {
    blockers.push("live_promotion_readiness_workflow_mismatch");
  }
  if (proof.activationId !== DEFAULT_AGENT_HARNESS_ACTIVATION_ID) {
    blockers.push("live_promotion_readiness_activation_mismatch");
  }
  if (proof.harnessHash !== DEFAULT_AGENT_HARNESS_HASH) {
    blockers.push("live_promotion_readiness_hash_mismatch");
  }
  if (proof.targetExecutionMode !== "live") {
    blockers.push("live_promotion_readiness_target_not_live");
  }
  if (!proof.allClustersReady) {
    blockers.push("live_promotion_readiness_clusters_not_ready");
  }
  if (!proof.promotionEligible) {
    blockers.push("live_promotion_readiness_not_eligible");
  }
  if (!proof.defaultLiveActivationReady) {
    blockers.push("live_promotion_readiness_default_activation_not_ready");
  }
  if (!proof.invalidForkLiveActivationBlocked) {
    blockers.push("live_promotion_readiness_invalid_fork_not_blocked");
  }
  if (!proof.rollbackAvailable || !proof.rollbackTarget) {
    blockers.push("live_promotion_readiness_rollback_unavailable");
  }
  if (
    proof.policyDecision !== "allow_default_harness_live_promotion_readiness"
  ) {
    blockers.push("live_promotion_readiness_policy_blocked");
  }
  const gate = proof.liveShadowComparisonGate;
  if (gate?.schemaVersion !== "workflow.harness.live-shadow-comparison-gate.v1") {
    blockers.push("live_promotion_readiness_live_shadow_gate_schema_mismatch");
  }
  if (!proof.liveShadowComparisonGateReady || gate?.ready !== true) {
    blockers.push("live_promotion_readiness_live_shadow_gate_not_ready");
  }
  if (gate?.targetExecutionMode !== "live") {
    blockers.push("live_promotion_readiness_live_shadow_gate_not_live");
  }
  for (const componentKind of HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS) {
    if (!gate?.componentKinds?.includes(componentKind)) {
      blockers.push(
        `live_promotion_readiness_live_shadow_gate_component_missing:${componentKind}`,
      );
    }
  }
  if (
    !gate ||
    gate.comparisonCount < HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS.length
  ) {
    blockers.push("live_promotion_readiness_live_shadow_gate_count_missing");
  }
  if (gate?.receiptReady !== true) {
    blockers.push("live_promotion_readiness_live_shadow_gate_receipts_missing");
  }
  if (gate?.replayReady !== true) {
    blockers.push("live_promotion_readiness_live_shadow_gate_replay_missing");
  }
  if (
    gate?.divergenceReady !== true ||
    (gate?.blockingDivergenceCount ?? 1) > 0 ||
    (gate?.unclassifiedDivergenceCount ?? 1) > 0
  ) {
    blockers.push(
      "live_promotion_readiness_live_shadow_gate_divergence_not_ready",
    );
  }
  if (
    gate?.policyDecision !==
    "allow_default_harness_live_shadow_comparison_gate"
  ) {
    blockers.push("live_promotion_readiness_live_shadow_gate_policy_blocked");
  }

  for (const blocker of proof.activationBlockers ?? []) {
    blockers.push(`live_promotion_readiness_activation_blocker:${blocker}`);
  }

  for (const clusterId of requiredClusterIds) {
    if (!proof.requiredClusterIds.includes(clusterId)) {
      blockers.push(
        `live_promotion_readiness_required_cluster_missing:${clusterId}`,
      );
    }
    const cluster = proof.clusterReadiness.find(
      (candidate) => candidate.clusterId === clusterId,
    );
    if (!cluster) {
      blockers.push(`live_promotion_readiness_cluster_missing:${clusterId}`);
      continue;
    }
    if (cluster.targetExecutionMode !== "live") {
      blockers.push(`live_promotion_readiness_cluster_not_live:${clusterId}`);
    }
    if (!cluster.readinessReady) {
      blockers.push(
        `live_promotion_readiness_cluster_readiness_not_ready:${clusterId}`,
      );
    }
    if (!cluster.receiptReady || cluster.receiptRefs.length === 0) {
      blockers.push(
        `live_promotion_readiness_cluster_receipts_missing:${clusterId}`,
      );
    }
    if (!cluster.replayGateReady || cluster.replayFixtureRefs.length === 0) {
      blockers.push(
        `live_promotion_readiness_cluster_replay_missing:${clusterId}`,
      );
    }
    if (!cluster.canaryReady) {
      blockers.push(
        `live_promotion_readiness_cluster_canary_not_ready:${clusterId}`,
      );
    }
    if (!cluster.rollbackReady) {
      blockers.push(
        `live_promotion_readiness_cluster_rollback_not_ready:${clusterId}`,
      );
    }
    if (
      !cluster.divergenceReady ||
      cluster.blockingDivergenceCount > 0 ||
      cluster.unclassifiedDivergenceCount > 0
    ) {
      blockers.push(
        `live_promotion_readiness_cluster_divergence_not_ready:${clusterId}`,
      );
    }
    for (const blocker of cluster.blockers ?? []) {
      blockers.push(
        `live_promotion_readiness_cluster_blocker:${clusterId}:${blocker}`,
      );
    }
  }

  return uniqueStrings(blockers);
}

export function makeHarnessDefaultRuntimeDispatchProof(
  options: {
    dispatchId?: string;
    selectorDecisionId?: string;
    acceptedClusterIds?: WorkflowHarnessPromotionClusterId[];
    sourceBoundaryIds?: string[];
    dispatchNodeAttemptIds?: string[];
    outputWriterHandoffAttemptIds?: string[];
    acceptedNodeAttemptIds?: string[];
    nodeAttemptIds?: string[];
    receiptIds?: string[];
    replayFixtureRefs?: string[];
    activationBlockers?: string[];
    activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof | null;
    activationIdGateProofNowMs?: number;
    activationIdGateProofMaxAgeMs?: number;
    activationIdGateWorkerBindingActivationId?: string;
    requireActivationIdGateClickProof?: boolean;
    packageImportActivationApplyProof?: WorkflowHarnessPackageImportActivationApplyProof | null;
    packageImportActivationApplyProofNowMs?: number;
    packageImportActivationApplyProofMaxAgeMs?: number;
    requirePackageImportActivationApplyProof?: boolean;
    evidenceRefs?: string[];
  } = {},
): WorkflowHarnessDefaultRuntimeDispatchProof {
  const acceptedClusterIds = options.acceptedClusterIds ?? [
    "cognition",
    "routing_model",
    "verification_output",
    "authority_tooling",
  ];
  const deferredComponentKinds: WorkflowHarnessComponentKind[] = [
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ];
  const authorityToolingReadOnlyComponentKinds: WorkflowHarnessComponentKind[] =
    [
      "mcp_provider",
      "mcp_tool_call",
      "tool_call",
      "connector_call",
      "wallet_capability",
    ];
  const authorityToolingMutationDeferredComponentKinds: WorkflowHarnessComponentKind[] =
    [
      "mcp_provider",
      "mcp_tool_call",
      "tool_call",
      "connector_call",
      "wallet_capability",
    ];
  const proposedVisibleOutputHash = "sha256:visible-output";
  const actualVisibleOutputHash = "sha256:visible-output";
  const promptAssemblyPromptHash = "sha256:prompt-final";
  const modelExecutionBindingId =
    "model-binding:default-agent-harness:workflow-default-model-route";
  const modelExecutionPromptHash = promptAssemblyPromptHash;
  const modelExecutionOutputHash = actualVisibleOutputHash;
  const cognitionExecutionAdapterResults = makeDefaultCognitionAdapterResults();
  const cognitionExecutionActionFrameIds = cognitionExecutionAdapterResults.map(
    (result) =>
      `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
  );
  const cognitionExecutionLiveReadyComponentKinds =
    cognitionExecutionAdapterResults.map(
      (result) => result.actionFrame.componentKind,
    );
  const cognitionExecutionShadowAdapterResults =
    makeDefaultCognitionShadowAdapterResults();
  const cognitionExecutionShadowActionFrameIds =
    cognitionExecutionShadowAdapterResults.map(
      (result) =>
        `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
    );
  const cognitionExecutionShadowComponentKinds =
    cognitionExecutionShadowAdapterResults.map(
      (result) => result.actionFrame.componentKind,
    );
  const cognitionExecutionShadowAttemptIds =
    cognitionExecutionShadowAdapterResults.map(
      (result) => result.nodeAttempt.attemptId,
    );
  const cognitionExecutionShadowReceiptIds =
    cognitionExecutionShadowAdapterResults.flatMap(
      (result) => result.receiptIds,
    );
  const cognitionExecutionShadowReplayFixtureRefs =
    cognitionExecutionShadowAdapterResults
      .map((result) => result.replay.fixtureRef)
      .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const cognitionLiveShadowComparisons: WorkflowHarnessShadowComparison[] =
    cognitionExecutionAdapterResults.flatMap((liveResult, index) => {
      const shadowResult = cognitionExecutionShadowAdapterResults[index];
      if (!shadowResult) return [];
      return [
        {
          workflowNodeId: liveResult.nodeAttempt.workflowNodeId,
          componentKind: liveResult.nodeAttempt.componentKind,
          liveAttemptId: liveResult.nodeAttempt.attemptId,
          shadowAttemptId: shadowResult.nodeAttempt.attemptId,
          divergence: "none",
          blocking: false,
          summary:
            "Live and shadow cognition adapter envelopes match for the default harness turn.",
          evidenceRefs: uniqueStrings([
            ...liveResult.nodeAttempt.receiptIds,
            ...shadowResult.nodeAttempt.receiptIds,
            liveResult.replay.fixtureRef,
            shadowResult.replay.fixtureRef,
          ]),
          liveReceiptRefs: liveResult.nodeAttempt.receiptIds,
          shadowReceiptRefs: shadowResult.nodeAttempt.receiptIds,
          liveReplayFixtureRef: liveResult.replay.fixtureRef,
          shadowReplayFixtureRef: shadowResult.replay.fixtureRef,
          liveInputHash: liveResult.nodeAttempt.inputHash,
          shadowInputHash: shadowResult.nodeAttempt.inputHash,
          liveOutputHash: liveResult.nodeAttempt.outputHash,
          shadowOutputHash: shadowResult.nodeAttempt.outputHash,
        },
      ];
    });
  const cognitionExecutionShadowDivergenceClasses =
    cognitionLiveShadowComparisons.map(
      (comparison) => comparison.divergence,
    );
  const cognitionExecutionGateAdapterResults =
    makeDefaultCognitionGateAdapterResults();
  const cognitionExecutionGateActionFrameIds =
    cognitionExecutionGateAdapterResults.map(
      (result) =>
        `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
    );
  const cognitionExecutionGateComponentKinds =
    cognitionExecutionGateAdapterResults.map(
      (result) => result.actionFrame.componentKind,
    );
  const cognitionExecutionGateAttemptIds = [
    "harness-default-dispatch:attempt-uncertainty_gate_envelope",
    "harness-default-dispatch:attempt-budget_gate_envelope",
    "harness-default-dispatch:attempt-capability_sequencer_envelope",
  ];
  const cognitionExecutionGateReceiptIds = [
    "harness-default-dispatch:receipt-uncertainty_gate_envelope",
    "harness-default-dispatch:receipt-budget_gate_envelope",
    "harness-default-dispatch:receipt-capability_sequencer_envelope",
  ];
  const cognitionExecutionGateReplayFixtureRefs = [
    "harness-default-dispatch:fixture-uncertainty_gate_envelope",
    "harness-default-dispatch:fixture-budget_gate_envelope",
    "harness-default-dispatch:fixture-capability_sequencer_envelope",
  ];
  const cognitionExecutionGateDivergenceClasses = ["none" as const];
  const routingModelAdapterResults =
    makeDefaultRoutingModelGateAdapterResults();
  const routingModelActionFrameIds = routingModelAdapterResults.map(
    (result) =>
      `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
  );
  const routingModelComponentKinds = routingModelAdapterResults.map(
    (result) => result.actionFrame.componentKind,
  );
  const routingModelAttemptIds = [
    "harness-default-dispatch:attempt-routing_model_model_router_envelope",
    "harness-default-dispatch:attempt-routing_model_model_call_envelope",
    "harness-default-dispatch:attempt-routing_model_tool_router_envelope",
  ];
  const routingModelReceiptIds = [
    "harness-default-dispatch:receipt-routing_model_model_router_envelope",
    "harness-default-dispatch:receipt-routing_model_model_call_envelope",
    "harness-default-dispatch:receipt-routing_model_tool_router_envelope",
  ];
  const routingModelReplayFixtureRefs = [
    "harness-default-dispatch:fixture-routing_model_model_router_envelope",
    "harness-default-dispatch:fixture-routing_model_model_call_envelope",
    "harness-default-dispatch:fixture-routing_model_tool_router_envelope",
  ];
  const routingModelDivergenceClasses = ["none" as const];
  const routingModelShadowAdapterResults =
    makeDefaultRoutingModelShadowAdapterResults();
  const routingModelShadowActionFrameIds =
    routingModelShadowAdapterResults.map(
      (result) =>
        `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
    );
  const routingModelShadowComponentKinds =
    routingModelShadowAdapterResults.map(
      (result) => result.actionFrame.componentKind,
    );
  const routingModelShadowAttemptIds = routingModelShadowAdapterResults.map(
    (result) => result.nodeAttempt.attemptId,
  );
  const routingModelShadowReceiptIds =
    routingModelShadowAdapterResults.flatMap((result) => result.receiptIds);
  const routingModelShadowReplayFixtureRefs =
    routingModelShadowAdapterResults
      .map((result) => result.replay.fixtureRef)
      .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const routingModelLiveShadowComparisons: WorkflowHarnessShadowComparison[] =
    routingModelAdapterResults.flatMap((liveResult, index) => {
      const shadowResult = routingModelShadowAdapterResults[index];
      if (!shadowResult) return [];
      return [
        {
          workflowNodeId: liveResult.nodeAttempt.workflowNodeId,
          componentKind: liveResult.nodeAttempt.componentKind,
          liveAttemptId: liveResult.nodeAttempt.attemptId,
          shadowAttemptId: shadowResult.nodeAttempt.attemptId,
          divergence: "none",
          blocking: false,
          summary:
            "Gated and shadow routing/model adapter envelopes match for the default harness turn.",
          evidenceRefs: uniqueStrings([
            ...liveResult.nodeAttempt.receiptIds,
            ...shadowResult.nodeAttempt.receiptIds,
            liveResult.replay.fixtureRef,
            shadowResult.replay.fixtureRef,
          ]),
          liveReceiptRefs: liveResult.nodeAttempt.receiptIds,
          shadowReceiptRefs: shadowResult.nodeAttempt.receiptIds,
          liveReplayFixtureRef: liveResult.replay.fixtureRef,
          shadowReplayFixtureRef: shadowResult.replay.fixtureRef,
          liveInputHash: liveResult.nodeAttempt.inputHash,
          shadowInputHash: shadowResult.nodeAttempt.inputHash,
          liveOutputHash: liveResult.nodeAttempt.outputHash,
          shadowOutputHash: shadowResult.nodeAttempt.outputHash,
        },
      ];
    });
  const routingModelShadowDivergenceClasses =
    routingModelLiveShadowComparisons.map(
      (comparison) => comparison.divergence,
    );
  const verificationOutputAdapterResults =
    makeDefaultVerificationOutputGateAdapterResults();
  const verificationOutputActionFrameIds = verificationOutputAdapterResults.map(
    (result) =>
      `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
  );
  const verificationOutputComponentKinds = verificationOutputAdapterResults.map(
    (result) => result.actionFrame.componentKind,
  );
  const verificationOutputAttemptIds = [
    "harness-default-dispatch:attempt-verification_output_postcondition_synthesizer_envelope",
    "harness-default-dispatch:attempt-verification_output_verifier_envelope",
    "harness-default-dispatch:attempt-verification_output_completion_gate_envelope",
    "harness-default-dispatch:attempt-verification_output_receipt_writer_envelope",
    "harness-default-dispatch:attempt-verification_output_quality_ledger_envelope",
    "harness-default-dispatch:attempt-verification_output_output_writer_envelope",
  ];
  const verificationOutputReceiptIds = [
    "harness-default-dispatch:receipt-verification_output_postcondition_synthesizer_envelope",
    "harness-default-dispatch:receipt-verification_output_verifier_envelope",
    "harness-default-dispatch:receipt-verification_output_completion_gate_envelope",
    "harness-default-dispatch:receipt-verification_output_receipt_writer_envelope",
    "harness-default-dispatch:receipt-verification_output_quality_ledger_envelope",
    "harness-default-dispatch:receipt-verification_output_output_writer_envelope",
  ];
  const verificationOutputReplayFixtureRefs = [
    "harness-default-dispatch:fixture-verification_output_postcondition_synthesizer_envelope",
    "harness-default-dispatch:fixture-verification_output_verifier_envelope",
    "harness-default-dispatch:fixture-verification_output_completion_gate_envelope",
    "harness-default-dispatch:fixture-verification_output_receipt_writer_envelope",
    "harness-default-dispatch:fixture-verification_output_quality_ledger_envelope",
    "harness-default-dispatch:fixture-verification_output_output_writer_envelope",
  ];
  const verificationOutputDivergenceClasses = ["none" as const];
  const verificationOutputShadowAdapterResults =
    makeDefaultVerificationOutputShadowAdapterResults();
  const verificationOutputShadowActionFrameIds =
    verificationOutputShadowAdapterResults.map(
      (result) =>
        `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
    );
  const verificationOutputShadowComponentKinds =
    verificationOutputShadowAdapterResults.map(
      (result) => result.actionFrame.componentKind,
    );
  const verificationOutputShadowAttemptIds =
    verificationOutputShadowAdapterResults.map(
      (result) => result.nodeAttempt.attemptId,
    );
  const verificationOutputShadowReceiptIds =
    verificationOutputShadowAdapterResults.flatMap(
      (result) => result.receiptIds,
    );
  const verificationOutputShadowReplayFixtureRefs =
    verificationOutputShadowAdapterResults
      .map((result) => result.replay.fixtureRef)
      .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const verificationOutputLiveShadowComparisons: WorkflowHarnessShadowComparison[] =
    verificationOutputAdapterResults.flatMap((liveResult, index) => {
      const shadowResult = verificationOutputShadowAdapterResults[index];
      if (!shadowResult) return [];
      return [
        {
          workflowNodeId: liveResult.nodeAttempt.workflowNodeId,
          componentKind: liveResult.nodeAttempt.componentKind,
          liveAttemptId: liveResult.nodeAttempt.attemptId,
          shadowAttemptId: shadowResult.nodeAttempt.attemptId,
          divergence: "none",
          blocking: false,
          summary:
            "Gated and shadow verification/output adapter envelopes match for the default harness turn.",
          evidenceRefs: uniqueStrings([
            ...liveResult.nodeAttempt.receiptIds,
            ...shadowResult.nodeAttempt.receiptIds,
            liveResult.replay.fixtureRef,
            shadowResult.replay.fixtureRef,
          ]),
          liveReceiptRefs: liveResult.nodeAttempt.receiptIds,
          shadowReceiptRefs: shadowResult.nodeAttempt.receiptIds,
          liveReplayFixtureRef: liveResult.replay.fixtureRef,
          shadowReplayFixtureRef: shadowResult.replay.fixtureRef,
          liveInputHash: liveResult.nodeAttempt.inputHash,
          shadowInputHash: shadowResult.nodeAttempt.inputHash,
          liveOutputHash: liveResult.nodeAttempt.outputHash,
          shadowOutputHash: shadowResult.nodeAttempt.outputHash,
        },
      ];
    });
  const verificationOutputShadowDivergenceClasses =
    verificationOutputLiveShadowComparisons.map(
      (comparison) => comparison.divergence,
    );
  const authorityToolingAdapterResults =
    makeDefaultAuthorityToolingGateAdapterResults();
  const authorityToolingActionFrameIds = authorityToolingAdapterResults.map(
    (result) =>
      `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
  );
  const authorityToolingComponentKinds = authorityToolingAdapterResults.map(
    (result) => result.actionFrame.componentKind,
  );
  const authorityToolingAttemptIds =
    DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS.map(
      (component) =>
        `harness-default-dispatch:attempt-${component.attemptSlug}`,
    );
  const authorityToolingReceiptIds =
    DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS.map(
      (component) =>
        `harness-default-dispatch:receipt-${component.attemptSlug}`,
    );
  const authorityToolingReplayFixtureRefs =
    DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS.map(
      (component) =>
        `harness-default-dispatch:fixture-${component.attemptSlug}`,
    );
  const authorityToolingDivergenceClasses = ["none" as const];
  const authorityToolingShadowAdapterResults =
    makeDefaultAuthorityToolingShadowAdapterResults();
  const authorityToolingShadowActionFrameIds =
    authorityToolingShadowAdapterResults.map(
      (result) =>
        `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
    );
  const authorityToolingShadowComponentKinds =
    authorityToolingShadowAdapterResults.map(
      (result) => result.actionFrame.componentKind,
    );
  const authorityToolingShadowAttemptIds =
    authorityToolingShadowAdapterResults.map(
      (result) => result.nodeAttempt.attemptId,
    );
  const authorityToolingShadowReceiptIds =
    authorityToolingShadowAdapterResults.flatMap(
      (result) => result.receiptIds,
    );
  const authorityToolingShadowReplayFixtureRefs =
    authorityToolingShadowAdapterResults
      .map((result) => result.replay.fixtureRef)
      .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const authorityToolingLiveShadowComparisons: WorkflowHarnessShadowComparison[] =
    authorityToolingAdapterResults.flatMap((liveResult, index) => {
      const shadowResult = authorityToolingShadowAdapterResults[index];
      if (!shadowResult) return [];
      return [
        {
          workflowNodeId: liveResult.nodeAttempt.workflowNodeId,
          componentKind: liveResult.nodeAttempt.componentKind,
          liveAttemptId: liveResult.nodeAttempt.attemptId,
          shadowAttemptId: shadowResult.nodeAttempt.attemptId,
          divergence: "none",
          blocking: false,
          summary:
            "Gated and shadow authority/tooling adapter envelopes match for the default harness turn.",
          evidenceRefs: uniqueStrings([
            ...liveResult.nodeAttempt.receiptIds,
            ...shadowResult.nodeAttempt.receiptIds,
            liveResult.replay.fixtureRef,
            shadowResult.replay.fixtureRef,
          ]),
          liveReceiptRefs: liveResult.nodeAttempt.receiptIds,
          shadowReceiptRefs: shadowResult.nodeAttempt.receiptIds,
          liveReplayFixtureRef: liveResult.replay.fixtureRef,
          shadowReplayFixtureRef: shadowResult.replay.fixtureRef,
          liveInputHash: liveResult.nodeAttempt.inputHash,
          shadowInputHash: shadowResult.nodeAttempt.inputHash,
          liveOutputHash: liveResult.nodeAttempt.outputHash,
          shadowOutputHash: shadowResult.nodeAttempt.outputHash,
        },
      ];
    });
  const authorityToolingShadowDivergenceClasses =
    authorityToolingLiveShadowComparisons.map(
      (comparison) => comparison.divergence,
    );
  const liveShadowComparisons = [
    ...cognitionLiveShadowComparisons,
    ...routingModelLiveShadowComparisons,
    ...verificationOutputLiveShadowComparisons,
    ...authorityToolingLiveShadowComparisons,
  ];
  const liveShadowComparisonGate = makeHarnessLiveShadowComparisonGate({
    comparisons: liveShadowComparisons,
    receiptRefs: [
      "harness-default-dispatch:receipt-planner_envelope",
      "harness-default-dispatch:receipt-prompt_assembler_envelope",
      "harness-default-dispatch:receipt-task_state_envelope",
      ...cognitionExecutionShadowReceiptIds,
      ...routingModelReceiptIds,
      ...routingModelShadowReceiptIds,
      ...verificationOutputReceiptIds,
      ...verificationOutputShadowReceiptIds,
      ...authorityToolingReceiptIds,
      ...authorityToolingShadowReceiptIds,
    ],
    replayFixtureRefs: [
      "harness-default-dispatch:fixture-planner_envelope",
      "harness-default-dispatch:fixture-prompt_assembler_envelope",
      "harness-default-dispatch:fixture-task_state_envelope",
      ...cognitionExecutionShadowReplayFixtureRefs,
      ...routingModelReplayFixtureRefs,
      ...routingModelShadowReplayFixtureRefs,
      ...verificationOutputReplayFixtureRefs,
      ...verificationOutputShadowReplayFixtureRefs,
      ...authorityToolingReplayFixtureRefs,
      ...authorityToolingShadowReplayFixtureRefs,
    ],
  });
  const activationIdGateProofBlockers =
    (options.requireActivationIdGateClickProof ?? true)
      ? workflowHarnessActivationIdGateClickProofBlockers(
          options.activationIdGateClickProof,
          {
            nowMs: options.activationIdGateProofNowMs,
            maxAgeMs: options.activationIdGateProofMaxAgeMs,
          },
        )
      : [];
  const requirePackageImportActivationApplyProof =
    options.requirePackageImportActivationApplyProof ?? true;
  const packageImportActivationApplyProofBlockers =
    requirePackageImportActivationApplyProof
      ? workflowHarnessPackageImportActivationApplyProofBlockers(
          options.packageImportActivationApplyProof,
          {
            nowMs: options.packageImportActivationApplyProofNowMs,
            maxAgeMs: options.packageImportActivationApplyProofMaxAgeMs,
          },
        )
      : [];
  const packageImportActivationApplyProofPresent = Boolean(
    options.packageImportActivationApplyProof,
  );
  const packageImportActivationApplyProofPassed =
    packageImportActivationApplyProofPresent &&
    packageImportActivationApplyProofBlockers.length === 0;
  const defaultLivePromotionInvariantIds =
    requirePackageImportActivationApplyProof
      ? [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT]
      : [];
  const defaultLivePromotionInvariantBlockers = uniqueStrings([
    ...packageImportActivationApplyProofBlockers,
  ]);
  const activationBlockers = uniqueStrings([
    ...(options.activationBlockers ?? []),
    ...activationIdGateProofBlockers,
    ...defaultLivePromotionInvariantBlockers,
  ]);
  const dispatchAccepted =
    activationBlockers.length === 0 && liveShadowComparisonGate.ready;
  const dispatchRuntimeAuthority = dispatchAccepted
    ? "blessed_workflow_activation_default"
    : "workflow_recovery_fail_closed";
  const activationIdGateClickProofPresent = Boolean(
    options.activationIdGateClickProof,
  );
  const activationIdGateClickProofPassed =
    activationIdGateClickProofPresent &&
    activationIdGateProofBlockers.length === 0;
  const activationIdGateWorkerBindingActivationId =
    activationIdGateClickProofPassed
      ? (options.activationIdGateWorkerBindingActivationId ??
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
      : "";
  const dispatchId =
    options.dispatchId ??
    "harness-default-dispatch:default-agent-harness:readonly";
  const selectorDecisionId =
    options.selectorDecisionId ??
    "harness-selector:default-agent-harness:default";
  const sourceBoundaryIds =
    options.sourceBoundaryIds ??
    acceptedClusterIds.map(
      (clusterId) =>
        `harness-canary-boundary:default-agent-harness:${clusterId}`,
    );
  const cognitionNodeAuthorityGate = makeCognitionNodeAuthorityGate({
    dispatchAccepted,
    runtimeAuthority: dispatchRuntimeAuthority,
    activationBlockers,
    adapterResults: cognitionExecutionAdapterResults,
    actionFrameIds: cognitionExecutionActionFrameIds,
    liveReadyComponentKinds: cognitionExecutionLiveReadyComponentKinds,
  });
  const routingModelNodeAuthorityGate = makeRoutingModelNodeAuthorityGate({
    dispatchAccepted,
    runtimeAuthority: dispatchRuntimeAuthority,
    activationBlockers,
    adapterResults: routingModelAdapterResults,
    actionFrameIds: routingModelActionFrameIds,
    componentKinds: routingModelComponentKinds,
    divergenceClasses: routingModelDivergenceClasses,
    shadowAttemptIds: routingModelShadowAttemptIds,
    shadowReceiptIds: routingModelShadowReceiptIds,
    shadowReplayFixtureRefs: routingModelShadowReplayFixtureRefs,
    shadowDivergenceClasses: routingModelShadowDivergenceClasses,
    providerCanaryReady: true,
    providerCanaryOutputHashMatches: true,
    providerCanaryTranscriptMatches: true,
    visibleOutputReady: true,
    visibleOutputSelected: true,
    visibleOutputAuthority: "workflow_model_provider_call",
    selectedVisibleOutputAuthorityMatchesTranscript: true,
    priorWorkflowVisibleOutputHashMatchesSelected: true,
    readOnlyCapabilityRoutingReady: true,
    rollbackAvailable: true,
  });
  const verificationOutputNodeAuthorityGate =
    makeVerificationOutputNodeAuthorityGate({
      dispatchAccepted,
      runtimeAuthority: dispatchRuntimeAuthority,
      activationBlockers,
      adapterResults: verificationOutputAdapterResults,
      actionFrameIds: verificationOutputActionFrameIds,
      componentKinds: verificationOutputComponentKinds,
      divergenceClasses: verificationOutputDivergenceClasses,
      shadowAttemptIds: verificationOutputShadowAttemptIds,
      shadowReceiptIds: verificationOutputShadowReceiptIds,
      shadowReplayFixtureRefs: verificationOutputShadowReplayFixtureRefs,
      shadowDivergenceClasses: verificationOutputShadowDivergenceClasses,
      outputWriterHandoffReady: true,
      outputWriterMaterializationCanaryReady: true,
      outputWriterStagedWriteCanaryReady: true,
      outputWriterVisibleWriteReady: true,
      outputWriterVisibleWriteCommitted: true,
      rollbackAvailable: true,
    });
  const authorityToolingNodeAuthorityGate =
    makeAuthorityToolingNodeAuthorityGate({
      dispatchAccepted,
      runtimeAuthority: dispatchRuntimeAuthority,
      activationBlockers,
      adapterResults: authorityToolingAdapterResults,
      actionFrameIds: authorityToolingActionFrameIds,
      componentKinds: authorityToolingComponentKinds,
      divergenceClasses: authorityToolingDivergenceClasses,
      shadowAttemptIds: authorityToolingShadowAttemptIds,
      shadowReceiptIds: authorityToolingShadowReceiptIds,
      shadowReplayFixtureRefs: authorityToolingShadowReplayFixtureRefs,
      shadowDivergenceClasses: authorityToolingShadowDivergenceClasses,
      readOnlyRouteAccepted: true,
      destructiveRouteDenied: true,
      mutatingToolCallsBlocked: true,
      sideEffectsExecuted: false,
      policyGateReady: true,
      toolRouterReady: true,
      dryRunSimulatorReady: true,
      approvalGateReady: true,
      gateLiveReady: true,
      readOnlyAuthorityCanaryReady: true,
      rollbackAvailable: true,
    });
  const livePromotionReadinessProof = makeHarnessLivePromotionReadinessProof({
    dispatchId,
    liveShadowComparisonGate,
    activationBlockers,
    invalidForkLiveActivationBlocked: true,
    rollbackAvailable: true,
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    evidenceRefs: uniqueStrings([
      ...(options.evidenceRefs ?? []),
      ...sourceBoundaryIds,
    ]),
    clusterReadiness: [
      makeHarnessLivePromotionClusterReadiness({
        clusterId: "cognition",
        componentKinds: cognitionExecutionLiveReadyComponentKinds,
        readinessReady:
          cognitionExecutionAdapterResults.length >= 3 &&
          cognitionExecutionShadowAdapterResults.length >= 3 &&
          cognitionExecutionGateAdapterResults.length >= 3,
        receiptRefs: [
          "harness-default-dispatch:receipt-planner_envelope",
          "harness-default-dispatch:receipt-prompt_assembler_envelope",
          "harness-default-dispatch:receipt-task_state_envelope",
          ...cognitionExecutionShadowReceiptIds,
          ...cognitionExecutionGateReceiptIds,
        ],
        replayFixtureRefs: [
          "harness-default-dispatch:fixture-planner_envelope",
          "harness-default-dispatch:fixture-prompt_assembler_envelope",
          "harness-default-dispatch:fixture-task_state_envelope",
          ...cognitionExecutionShadowReplayFixtureRefs,
          ...cognitionExecutionGateReplayFixtureRefs,
        ],
        actionFrameIds: [
          ...cognitionExecutionActionFrameIds,
          ...cognitionExecutionShadowActionFrameIds,
          ...cognitionExecutionGateActionFrameIds,
        ],
        attemptIds: [
          "harness-default-dispatch:attempt-planner_envelope",
          "harness-default-dispatch:attempt-prompt_assembler_envelope",
          "harness-default-dispatch:attempt-task_state_envelope",
          ...cognitionExecutionShadowAttemptIds,
          ...cognitionExecutionGateAttemptIds,
        ],
        divergenceClasses: [
          ...cognitionExecutionShadowDivergenceClasses,
          ...cognitionExecutionGateDivergenceClasses,
        ],
        canaryReady: true,
        rollbackReady: true,
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      }),
      makeHarnessLivePromotionClusterReadiness({
        clusterId: "routing_model",
        componentKinds: routingModelComponentKinds,
        readinessReady:
          routingModelAdapterResults.length >= 3 &&
          routingModelShadowAdapterResults.length >= 3 &&
          routingModelDivergenceClasses.every(
            (divergenceClass) => divergenceClass === "none",
          ) &&
          routingModelShadowDivergenceClasses.every(
            (divergenceClass) => divergenceClass === "none",
          ),
        receiptRefs: [
          ...routingModelReceiptIds,
          ...routingModelShadowReceiptIds,
          "harness-default-dispatch:receipt-model_provider_call_canary",
          "harness-default-dispatch:receipt-model_provider_gated_visible_output",
          "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
        ],
        replayFixtureRefs: [
          ...routingModelReplayFixtureRefs,
          ...routingModelShadowReplayFixtureRefs,
          "harness-default-dispatch:fixture-model_provider_call_canary",
          "harness-default-dispatch:fixture-model_provider_gated_visible_output",
          "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
        ],
        actionFrameIds: [
          ...routingModelActionFrameIds,
          ...routingModelShadowActionFrameIds,
        ],
        attemptIds: [
          ...routingModelAttemptIds,
          ...routingModelShadowAttemptIds,
          "harness-default-dispatch:attempt-model_provider_call_canary",
          "harness-default-dispatch:attempt-model_provider_gated_visible_output",
          "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
        ],
        divergenceClasses: [
          ...routingModelDivergenceClasses,
          ...routingModelShadowDivergenceClasses,
        ],
        canaryReady: true,
        rollbackReady: true,
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      }),
      makeHarnessLivePromotionClusterReadiness({
        clusterId: "verification_output",
        componentKinds: verificationOutputComponentKinds,
        readinessReady:
          verificationOutputAdapterResults.length >= 6 &&
          verificationOutputShadowAdapterResults.length >= 6 &&
          verificationOutputDivergenceClasses.every(
            (divergenceClass) => divergenceClass === "none",
          ) &&
          verificationOutputShadowDivergenceClasses.every(
            (divergenceClass) => divergenceClass === "none",
          ),
        receiptRefs: [
          ...verificationOutputReceiptIds,
          ...verificationOutputShadowReceiptIds,
        ],
        replayFixtureRefs: [
          ...verificationOutputReplayFixtureRefs,
          ...verificationOutputShadowReplayFixtureRefs,
        ],
        actionFrameIds: [
          ...verificationOutputActionFrameIds,
          ...verificationOutputShadowActionFrameIds,
        ],
        attemptIds: [
          ...verificationOutputAttemptIds,
          ...verificationOutputShadowAttemptIds,
        ],
        divergenceClasses: [
          ...verificationOutputDivergenceClasses,
          ...verificationOutputShadowDivergenceClasses,
        ],
        canaryReady: true,
        rollbackReady: true,
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      }),
      makeHarnessLivePromotionClusterReadiness({
        clusterId: "authority_tooling",
        componentKinds: authorityToolingComponentKinds,
        readinessReady:
          authorityToolingAdapterResults.length >= 8 &&
          authorityToolingShadowAdapterResults.length >= 8 &&
          authorityToolingDivergenceClasses.every(
            (divergenceClass) => divergenceClass === "none",
          ) &&
          authorityToolingShadowDivergenceClasses.every(
            (divergenceClass) => divergenceClass === "none",
          ),
        receiptRefs: [
          ...authorityToolingReceiptIds,
          ...authorityToolingShadowReceiptIds,
        ],
        replayFixtureRefs: [
          ...authorityToolingReplayFixtureRefs,
          ...authorityToolingShadowReplayFixtureRefs,
        ],
        actionFrameIds: [
          ...authorityToolingActionFrameIds,
          ...authorityToolingShadowActionFrameIds,
        ],
        attemptIds: [
          ...authorityToolingAttemptIds,
          ...authorityToolingShadowAttemptIds,
        ],
        divergenceClasses: [
          ...authorityToolingDivergenceClasses,
          ...authorityToolingShadowDivergenceClasses,
        ],
        canaryReady: true,
        rollbackReady: true,
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      }),
    ],
  });
  const workflowTranscriptWriteCandidate = {
    target: "checkpoint_transcript_messages",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: proposedVisibleOutputHash,
    receiptBindingRef:
      "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeAuthority: "blessed_workflow_activation_default",
    committed: false,
    commitMode: "candidate_only",
  };
  const workflowTranscriptRecoveryRecord = {
    target: "checkpoint_transcript_messages",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: proposedVisibleOutputHash,
    receiptBindingRef:
      "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeIdentityHash: "sha256:workflow-visible-transcript-write",
    writeAuthority: "blessed_workflow_activation_default",
    committed: true,
    visible: true,
    visibleTranscriptCommit: true,
    commitMode: "workflow_visible_transcript_write",
  };
  const workflowTranscriptWriteRecord = {
    target: "checkpoint_transcript_messages",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: actualVisibleOutputHash,
    receiptBindingRef:
      "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeAuthority: "workflow_recovery_fail_closed",
    committed: false,
    suppressedByIdempotency: true,
    commitMode: "idempotent_noop",
  };
  const stagedTranscriptWriteRecord = {
    target: "checkpoint_transcript_messages",
    stagingSurface: "checkpoint_blobs",
    checkpointName: "autopilot.workflow_output_writer_transcript_staging.v1",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: proposedVisibleOutputHash,
    receiptBindingRef:
      "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeAuthority: "blessed_workflow_activation_default",
    committed: true,
    stagingCommitted: true,
    visible: false,
    visibleTranscriptCommit: false,
    commitMode: "staged_non_visible",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  };
  const stagedTranscriptWriteProof = {
    schemaVersion: "workflow.output_writer.transcript-staging-proof.v1",
    surface: "checkpoint_blobs",
    checkpointName: "autopilot.workflow_output_writer_transcript_staging.v1",
    record: stagedTranscriptWriteRecord,
    persisted: true,
    loadedBeforeRollback: true,
    visibleBeforeCount: 1,
    visibleAfterCount: 1,
    excludedFromVisibleTranscript: true,
    rollbackAction: "delete_checkpoint_blob",
    rollbackExecuted: true,
    rollbackVerified: true,
    rollbackStatus: "deleted",
  };
  const visibleTranscriptWriteProof = {
    schemaVersion: "workflow.output_writer.visible-transcript-write-proof.v1",
    mode: "workflow_visible_transcript_write",
    target: "checkpoint_transcript_messages",
    record: workflowTranscriptWriteRecord,
    persisted: true,
    committed: true,
    created: true,
    visible: true,
    visibleRowsDelta: 1,
    idempotencyGuard:
      "session_role_timestamp_order_content_hash_receipt_binding",
    duplicateSuppressionReady: true,
    identityCheckpointPersisted: true,
    rollbackAvailable: true,
    rollbackMode:
      "workflow_fail_closed_with_idempotent_duplicate_suppression",
  };
  const workflowTranscriptRecoveryProof = {
    schemaVersion: "workflow.output_writer.transcript-recovery.v1",
    phase: "workflow_recovery_after_workflow_output",
    writeAuthority: "workflow_recovery_fail_closed",
    appendedCount: 0,
    duplicateSuppressedCount: 1,
    latestAgentDuplicateSuppressed: true,
    idempotencyGuard: "role_timestamp_content_hash",
  };
  const workerBindingRegistryRecord =
    makeWorkflowHarnessWorkerBindingRegistryRecord({
      selectorDecisionId,
      defaultDispatchId: dispatchId,
      readinessProofId: livePromotionReadinessProof.proofId,
      reviewedPackageSnapshotHash:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedPackageSnapshotHash,
      reviewedWorkflowContentHash:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkflowContentHash,
      reviewedActivationId:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedActivationId,
      reviewedHarnessWorkflowId:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedHarnessWorkflowId,
      reviewedWorkerBindingActivationId:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkerBindingActivationId,
      reviewedRollbackTarget:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedRollbackTarget,
      reviewedReplayFixtureRefs:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedReplayFixtureRefs,
      reviewedWorkerHandoffNodeAttemptIds:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkerHandoffNodeAttemptIds,
      reviewedWorkerHandoffReceiptIds:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkerHandoffReceiptIds,
      reviewedForkMutationCanaryId:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryId,
      reviewedForkMutationCanaryStatus:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryStatus,
      reviewedForkMutationCanaryDiffHash:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryDiffHash,
      reviewedForkMutationCanaryReceiptRefs:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryReceiptRefs,
      reviewedForkMutationCanaryReplayFixtureRefs:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryReplayFixtureRefs,
      reviewedForkMutationCanaryNodeAttemptIds:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryNodeAttemptIds,
      reviewedForkMutationCanaryRollbackTarget:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryRollbackTarget,
      reviewedPolicyPosture:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedPolicyPosture,
      componentVersionSet: defaultHarnessComponentVersionSet(),
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      canaryResultId: "harness-canary-result:default-agent-harness:passed",
      policyDecision: dispatchAccepted
        ? "promote_blessed_workflow_default_for_non_mutating_turn"
        : "block_workflow_default_until_gates_pass",
      bindingStatus: dispatchAccepted ? "bound" : "blocked",
      blockers: activationBlockers,
      requiredInvariantIds: defaultLivePromotionInvariantIds,
      invariantBlockers: defaultLivePromotionInvariantBlockers,
    });
  const workerAttachLifecycle = dispatchAccepted
    ? makeWorkflowHarnessWorkerAttachLifecycle(workerBindingRegistryRecord)
    : (() => {
        const receipt = resolveWorkflowHarnessWorkerBinding(
          workerBindingRegistryRecord,
          makeWorkflowHarnessWorkerAttachRequest(
            workerBindingRegistryRecord,
            "blocked",
          ),
        );
        return [
          {
            schemaVersion: "workflow.harness.worker-attach-lifecycle.v1",
            eventId: `harness-worker-attach-lifecycle:blocked:${DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:${DEFAULT_AGENT_HARNESS_ACTIVATION_ID}`,
            sequence: 0,
            phase: "attach",
            attemptId: `harness-worker-attach:attempt:blocked:${DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:${DEFAULT_AGENT_HARNESS_ACTIVATION_ID}`,
            workflowNodeId: "harness.handoff_bridge",
            componentKind: "handoff_bridge",
            attachStatus: "blocked",
            receiptId: receipt.receiptId,
            receipt,
            registryRecordId: workerBindingRegistryRecord.registryRecordId,
            accepted: false,
            rollbackAvailable: false,
            rollbackReadinessProofId: receipt.rollbackReadinessProofId,
            rollbackLiveShadowComparisonGateId:
              receipt.rollbackLiveShadowComparisonGateId,
            rollbackLiveShadowComparisonGateReady:
              receipt.rollbackLiveShadowComparisonGateReady,
            rollbackActivationId: receipt.rollbackActivationId,
            rollbackHarnessHash: receipt.rollbackHarnessHash,
            rollbackPolicyDecision: receipt.rollbackPolicyDecision,
            policyDecision: "block_harness_worker_attach",
            requiredInvariantIds: receipt.requiredInvariantIds,
            invariantBlockers: receipt.invariantBlockers,
            blockers: activationBlockers,
            evidenceRefs: [workerBindingRegistryRecord.registryRecordId],
          } satisfies WorkflowHarnessWorkerAttachLifecycleEvent,
        ];
      })();
  const workerAttachReceipt =
    workerAttachLifecycle.find((event) => event.phase === "attach")?.receipt ??
    resolveWorkflowHarnessWorkerBinding(
      workerBindingRegistryRecord,
      makeWorkflowHarnessWorkerAttachRequest(workerBindingRegistryRecord),
    );
  const workerAttachResumeReceipt =
    workerAttachLifecycle.find((event) => event.phase === "resume")?.receipt ??
    workerAttachReceipt;
  const workerAttachRollbackReceipt =
    workerAttachLifecycle.find((event) => event.phase === "rollback")
      ?.receipt ?? workerAttachReceipt;
  const workerAttachLifecycleAttemptIds = workerAttachLifecycle.map(
    (event) => event.attemptId,
  );
  const workerAttachLifecycleStatuses = workerAttachLifecycle.map(
    (event) => event.attachStatus,
  );
  const workerAttachLifecycleComplete =
    workflowHarnessWorkerAttachLifecycleComplete(workerAttachLifecycle);
  const workerSessionRecord = makeWorkflowHarnessWorkerSessionRecord(
    workerBindingRegistryRecord,
    workerAttachLifecycle,
  );
  const workerLaunchEnvelopes = (["launch", "resume", "rollback"] as const).map(
    (phase) =>
      makeWorkflowHarnessWorkerLaunchEnvelope(workerSessionRecord, phase),
  );
  const workerHandoffReceipts = workerLaunchEnvelopes.map((envelope) =>
    resolveWorkflowHarnessWorkerHandoffReceipt(workerSessionRecord, envelope),
  );
  const workerLaunchEnvelopeIds = workerLaunchEnvelopes.map(
    (envelope) => envelope.envelopeId,
  );
  const workerHandoffReceiptIds = workerHandoffReceipts.map(
    (receipt) => receipt.receiptId,
  );
  const workerHandoffNodeAttempts =
    makeWorkflowHarnessWorkerHandoffNodeAttempts(workerHandoffReceipts, {
      executionMode: dispatchAccepted ? "live" : "gated",
    });
  const workerHandoffNodeAttemptIds = workerHandoffNodeAttempts.map(
    (attempt) => attempt.attemptId,
  );
  const workerHandoffReplayFixtureRefs = workerHandoffNodeAttempts
    .map((attempt) => attempt.replay.fixtureRef)
    .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const defaultNodeAttemptIds = uniqueStrings([
    ...(options.nodeAttemptIds ?? []),
    ...cognitionExecutionShadowAttemptIds,
    ...routingModelShadowAttemptIds,
    ...verificationOutputShadowAttemptIds,
    ...authorityToolingShadowAttemptIds,
    ...workerHandoffNodeAttemptIds,
  ]);
  const defaultReceiptIds = uniqueStrings([
    ...(options.receiptIds ?? []),
    ...cognitionExecutionShadowReceiptIds,
    ...routingModelShadowReceiptIds,
    ...verificationOutputShadowReceiptIds,
    ...authorityToolingShadowReceiptIds,
    ...workerHandoffReceiptIds,
  ]);
  const defaultReplayFixtureRefs = uniqueStrings([
    ...(options.replayFixtureRefs ?? []),
    ...cognitionExecutionShadowReplayFixtureRefs,
    ...routingModelShadowReplayFixtureRefs,
    ...verificationOutputShadowReplayFixtureRefs,
    ...authorityToolingShadowReplayFixtureRefs,
    ...workerHandoffReplayFixtureRefs,
  ]);
  return {
    schemaVersion: "workflow.harness.default-runtime-dispatch.v1",
    dispatchId,
    selectorDecisionId,
    selectedSelector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: dispatchAccepted ? "live" : "gated",
    runtimeAuthority: dispatchRuntimeAuthority,
    dispatchScope:
      "read_only_cognition_routing_verification_completion_authority_tooling",
    acceptedClusterIds,
    componentKinds: acceptedClusterIds
      .flatMap((clusterId) => HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId])
      .filter(
        (componentKind) => !deferredComponentKinds.includes(componentKind),
      ),
    deferredComponentKinds,
    handoffValidatedComponentKinds: ["output_writer"],
    materializationCanaryComponentKinds: ["output_writer"],
    sourceBoundaryIds,
    dispatchNodeAttemptIds: options.dispatchNodeAttemptIds ?? [
      ...acceptedClusterIds.map(
        (clusterId) => `harness-default-dispatch:attempt-${clusterId}`,
      ),
      "harness-default-dispatch:attempt-planner_envelope",
      "harness-default-dispatch:attempt-prompt_assembler_envelope",
      "harness-default-dispatch:attempt-task_state_envelope",
      ...cognitionExecutionShadowAttemptIds,
      ...cognitionExecutionGateAttemptIds,
      "harness-default-dispatch:attempt-model_router_envelope",
      "harness-default-dispatch:attempt-model_call_envelope",
      ...routingModelAttemptIds,
      ...verificationOutputAttemptIds,
      ...authorityToolingAttemptIds,
      "harness-default-dispatch:attempt-model_provider_call_canary",
      "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      "harness-default-dispatch:attempt-read_only_source_router",
      "harness-default-dispatch:attempt-read_only_capability_sequencer",
      "harness-default-dispatch:attempt-read_only_tool_router",
      "harness-default-dispatch:attempt-read_only_no_mutation_drill",
      "harness-default-dispatch:attempt-output_writer_handoff",
      "harness-default-dispatch:attempt-output_writer_materialization_canary",
      "harness-default-dispatch:attempt-output_writer_staged_write_canary",
      "harness-default-dispatch:attempt-output_writer_visible_write_commit",
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      "harness-default-dispatch:attempt-authority_tooling_tool_router",
      "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator",
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
      ...workerAttachLifecycleAttemptIds,
      ...workerHandoffNodeAttemptIds,
    ],
    dispatchNodeAttempts: workerHandoffNodeAttempts,
    cognitionExecutionAttemptIds: [
      "harness-default-dispatch:attempt-planner_envelope",
      "harness-default-dispatch:attempt-prompt_assembler_envelope",
      "harness-default-dispatch:attempt-task_state_envelope",
      ...cognitionExecutionGateAttemptIds,
    ],
    cognitionExecutionReceiptIds: [
      "harness-default-dispatch:receipt-planner_envelope",
      "harness-default-dispatch:receipt-prompt_assembler_envelope",
      "harness-default-dispatch:receipt-task_state_envelope",
      ...cognitionExecutionGateReceiptIds,
    ],
    cognitionExecutionReplayFixtureRefs: [
      "harness-default-dispatch:fixture-planner_envelope",
      "harness-default-dispatch:fixture-prompt_assembler_envelope",
      "harness-default-dispatch:fixture-task_state_envelope",
      ...cognitionExecutionGateReplayFixtureRefs,
    ],
    cognitionExecutionAdapterMode: "workflow_component_adapter_live",
    cognitionExecutionAdapterResults,
    cognitionExecutionActionFrameIds,
    cognitionExecutionLiveReadyComponentKinds,
    cognitionExecutionShadowAdapterMode: "workflow_component_adapter_shadow",
    cognitionExecutionShadowAttemptIds,
    cognitionExecutionShadowReceiptIds,
    cognitionExecutionShadowReplayFixtureRefs,
    cognitionExecutionShadowAdapterResults,
    cognitionExecutionShadowActionFrameIds,
    cognitionExecutionShadowComponentKinds,
    cognitionExecutionShadowDivergenceClasses,
    liveShadowComparisons,
    liveShadowComparisonCount: liveShadowComparisons.length,
    liveShadowComparisonGate,
    liveShadowComparisonGateReady: liveShadowComparisonGate.ready,
    liveShadowBlockingDivergenceCount: liveShadowComparisons.filter(
      (comparison) => comparison.blocking,
    ).length,
    liveShadowUnclassifiedDivergenceCount: liveShadowComparisons.filter(
      (comparison) => comparison.divergence === "unclassified",
    ).length,
    cognitionExecutionGateAdapterMode: "workflow_component_adapter_gated",
    cognitionExecutionGateAttemptIds,
    cognitionExecutionGateReceiptIds,
    cognitionExecutionGateReplayFixtureRefs,
    cognitionExecutionGateAdapterResults,
    cognitionExecutionGateActionFrameIds,
    cognitionExecutionGateComponentKinds,
    cognitionExecutionGateDivergenceClasses,
    routingModelAdapterMode: "workflow_component_adapter_gated",
    routingModelAttemptIds,
    routingModelReceiptIds,
    routingModelReplayFixtureRefs,
    routingModelAdapterResults,
    routingModelActionFrameIds,
    routingModelComponentKinds,
    routingModelDivergenceClasses,
    routingModelShadowAdapterMode: "workflow_component_adapter_shadow",
    routingModelShadowAttemptIds,
    routingModelShadowReceiptIds,
    routingModelShadowReplayFixtureRefs,
    routingModelShadowAdapterResults,
    routingModelShadowActionFrameIds,
    routingModelShadowComponentKinds,
    routingModelShadowDivergenceClasses,
    verificationOutputAdapterMode: "workflow_component_adapter_gated",
    verificationOutputAttemptIds,
    verificationOutputReceiptIds,
    verificationOutputReplayFixtureRefs,
    verificationOutputAdapterResults,
    verificationOutputActionFrameIds,
    verificationOutputComponentKinds,
    verificationOutputDivergenceClasses,
    verificationOutputShadowAdapterMode: "workflow_component_adapter_shadow",
    verificationOutputShadowAttemptIds,
    verificationOutputShadowReceiptIds,
    verificationOutputShadowReplayFixtureRefs,
    verificationOutputShadowAdapterResults,
    verificationOutputShadowActionFrameIds,
    verificationOutputShadowComponentKinds,
    verificationOutputShadowDivergenceClasses,
    authorityToolingAdapterMode: "workflow_component_adapter_gated",
    authorityToolingAttemptIds,
    authorityToolingReceiptIds,
    authorityToolingReplayFixtureRefs,
    authorityToolingAdapterResults,
    authorityToolingActionFrameIds,
    authorityToolingComponentKinds,
    authorityToolingDivergenceClasses,
    authorityToolingShadowAdapterMode: "workflow_component_adapter_shadow",
    authorityToolingShadowAttemptIds,
    authorityToolingShadowReceiptIds,
    authorityToolingShadowReplayFixtureRefs,
    authorityToolingShadowAdapterResults,
    authorityToolingShadowActionFrameIds,
    authorityToolingShadowComponentKinds,
    authorityToolingShadowDivergenceClasses,
    modelExecutionAttemptIds: [
      "harness-default-dispatch:attempt-model_router_envelope",
      "harness-default-dispatch:attempt-model_call_envelope",
      "harness-default-dispatch:attempt-model_provider_call_canary",
      "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelExecutionReceiptIds: [
      "harness-default-dispatch:receipt-model_router_envelope",
      "harness-default-dispatch:receipt-model_call_envelope",
      "harness-default-dispatch:receipt-model_provider_call_canary",
      "harness-default-dispatch:receipt-model_provider_gated_visible_output",
      "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelExecutionReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_router_envelope",
      "harness-default-dispatch:fixture-model_call_envelope",
      "harness-default-dispatch:fixture-model_provider_call_canary",
      "harness-default-dispatch:fixture-model_provider_gated_visible_output",
      "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
    ],
    modelProviderCanaryAttemptIds: [
      "harness-default-dispatch:attempt-model_provider_call_canary",
    ],
    modelProviderCanaryReceiptIds: [
      "harness-default-dispatch:receipt-model_provider_call_canary",
    ],
    modelProviderCanaryReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_provider_call_canary",
    ],
    modelProviderGatedVisibleOutputAttemptIds: [
      "harness-default-dispatch:attempt-model_provider_gated_visible_output",
    ],
    modelProviderGatedVisibleOutputReceiptIds: [
      "harness-default-dispatch:receipt-model_provider_gated_visible_output",
    ],
    modelProviderGatedVisibleOutputReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_provider_gated_visible_output",
    ],
    modelProviderGatedVisibleOutputRollbackDrillAttemptIds: [
      "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelProviderGatedVisibleOutputRollbackDrillReceiptIds: [
      "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
    ],
    readOnlyCapabilityRoutingAttemptIds: [
      "harness-default-dispatch:attempt-read_only_source_router",
      "harness-default-dispatch:attempt-read_only_capability_sequencer",
      "harness-default-dispatch:attempt-read_only_tool_router",
      "harness-default-dispatch:attempt-read_only_no_mutation_drill",
    ],
    readOnlyCapabilityRoutingReceiptIds: [
      "harness-default-dispatch:receipt-read_only_source_router",
      "harness-default-dispatch:receipt-read_only_capability_sequencer",
      "harness-default-dispatch:receipt-read_only_tool_router",
      "harness-default-dispatch:receipt-read_only_no_mutation_drill",
    ],
    readOnlyCapabilityRoutingReplayFixtureRefs: [
      "harness-default-dispatch:fixture-read_only_source_router",
      "harness-default-dispatch:fixture-read_only_capability_sequencer",
      "harness-default-dispatch:fixture-read_only_tool_router",
      "harness-default-dispatch:fixture-read_only_no_mutation_drill",
    ],
    outputWriterHandoffAttemptIds: options.outputWriterHandoffAttemptIds ?? [
      "harness-default-dispatch:attempt-output_writer_handoff",
    ],
    outputWriterMaterializationCanaryAttemptIds: [
      "harness-default-dispatch:attempt-output_writer_materialization_canary",
    ],
    outputWriterStagedWriteCanaryAttemptIds: [
      "harness-default-dispatch:attempt-output_writer_staged_write_canary",
    ],
    outputWriterVisibleWriteAttemptIds: [
      "harness-default-dispatch:attempt-output_writer_visible_write_commit",
    ],
    authorityToolingLiveDryRunAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      "harness-default-dispatch:attempt-authority_tooling_tool_router",
      "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator",
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingGateLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
    ],
    authorityToolingGateLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_policy_gate",
      "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      "harness-default-dispatch:receipt-authority_tooling_approval_gate",
    ],
    authorityToolingGateLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_policy_gate",
      "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
      "harness-default-dispatch:fixture-authority_tooling_approval_gate",
    ],
    authorityToolingPolicyGateLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
    ],
    authorityToolingPolicyGateLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_policy_gate",
    ],
    authorityToolingPolicyGateLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_policy_gate",
    ],
    authorityToolingDestructiveDenialLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
    ],
    authorityToolingDestructiveDenialLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
    ],
    authorityToolingDestructiveDenialLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
    ],
    authorityToolingApprovalGateLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
    ],
    authorityToolingApprovalGateLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_approval_gate",
    ],
    authorityToolingApprovalGateLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_approval_gate",
    ],
    authorityToolingReadOnlyLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingReadOnlyReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingReadOnlyReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingProviderCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
    ],
    authorityToolingProviderCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
    ],
    authorityToolingProviderCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
    ],
    authorityToolingMcpToolCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
    ],
    authorityToolingMcpToolCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
    ],
    authorityToolingMcpToolCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
    ],
    authorityToolingNativeToolCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
    ],
    authorityToolingNativeToolCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
    ],
    authorityToolingNativeToolCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
    ],
    authorityToolingConnectorCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
    ],
    authorityToolingConnectorCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
    ],
    authorityToolingConnectorCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
    ],
    authorityToolingWalletCapabilityLiveDryRunAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingWalletCapabilityLiveDryRunReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingReadOnlyComponentKinds,
    authorityToolingMutationDeferredComponentKinds,
    authorityToolingDenialReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
    ],
    acceptedNodeAttemptIds: options.acceptedNodeAttemptIds ?? [],
    nodeAttemptIds: defaultNodeAttemptIds,
    receiptIds: defaultReceiptIds,
    replayFixtureRefs: defaultReplayFixtureRefs,
    executorKind: "workflow_node_executor",
    executorRef: "crate::project::execute_workflow_harness_live_default_node",
    synchronous: true,
    drivesRuntimeDecision: dispatchAccepted,
    activationIdGateClickProofPresent,
    activationIdGateClickProofPassed,
    activationIdGateClickProofBlockers: activationIdGateProofBlockers,
    defaultLivePromotionInvariantIds,
    defaultLivePromotionInvariantBlockers,
    reviewedImportActivationApplyProofPresent:
      packageImportActivationApplyProofPresent,
    reviewedImportActivationApplyProofPassed:
      packageImportActivationApplyProofPassed,
    reviewedImportActivationApplyProofBlockers:
      packageImportActivationApplyProofBlockers,
    reviewedImportActivationApplyActivationId:
      options.packageImportActivationApplyProof?.activationResult
        ?.activationId ?? null,
    defaultDispatchActivationBlockers: activationBlockers,
    activationIdGate: {
      schemaVersion:
        "workflow.harness.default-runtime-dispatch.activation-id-gate.v1",
      gateId: "activation-id",
      proofPresent: activationIdGateClickProofPresent,
      proofPassed: activationIdGateClickProofPassed,
      proofBlockers: activationIdGateProofBlockers,
      workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      workerBindingActivationId: activationIdGateWorkerBindingActivationId,
      defaultDispatchActivationBlockers: activationBlockers,
    },
    reviewedImportActivationApplyGate: {
      schemaVersion:
        "workflow.harness.default-runtime-dispatch.reviewed-import-activation-apply-gate.v1",
      gateId: "reviewed-import-activation-apply",
      invariantId:
        DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
      proofPresent: packageImportActivationApplyProofPresent,
      proofPassed: packageImportActivationApplyProofPassed,
      proofBlockers: packageImportActivationApplyProofBlockers,
      activationId:
        options.packageImportActivationApplyProof?.activationResult
          ?.activationId ?? null,
      workerBindingActivationId:
        options.packageImportActivationApplyProof?.activationResult
          ?.workerBindingActivationId ?? null,
      rollbackTarget:
        options.packageImportActivationApplyProof?.activationResult
          ?.rollbackTarget ?? null,
      reviewedPackageSnapshotHash:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedPackageSnapshotHash ?? null,
      reviewedWorkflowContentHash:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkflowContentHash ?? null,
      reviewedHarnessWorkflowId:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedHarnessWorkflowId ?? null,
      reviewedReplayFixtureRefs:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedReplayFixtureRefs ?? [],
      reviewedWorkerHandoffNodeAttemptIds:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkerHandoffNodeAttemptIds ?? [],
      reviewedWorkerHandoffReceiptIds:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedWorkerHandoffReceiptIds ?? [],
      reviewedForkMutationCanaryId:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryId ?? null,
      reviewedForkMutationCanaryStatus:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryStatus ?? null,
      reviewedForkMutationCanaryDiffHash:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryDiffHash ?? null,
      reviewedForkMutationCanaryReceiptRefs:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryReceiptRefs ?? [],
      reviewedForkMutationCanaryReplayFixtureRefs:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryReplayFixtureRefs ?? [],
      reviewedForkMutationCanaryNodeAttemptIds:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryNodeAttemptIds ?? [],
      reviewedForkMutationCanaryRollbackTarget:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedForkMutationCanaryRollbackTarget ?? null,
      reviewedPolicyPosture:
        options.packageImportActivationApplyProof?.activationResult
          ?.reviewedPolicyPosture ?? null,
      defaultDispatchActivationBlockers: activationBlockers,
    },
    cognitionNodeAuthorityGate,
    routingModelNodeAuthorityGate,
    verificationOutputNodeAuthorityGate,
    authorityToolingNodeAuthorityGate,
    cognitionExecutionMode: "workflow_synchronous_envelope",
    cognitionExecutionReady: true,
    promptAssemblyMode: "workflow_synchronous_envelope",
    promptAssemblyPromptHash,
    promptAssemblyPromptHashMatches: true,
    cognitionExecutionProof: {
      schemaVersion: "workflow.harness.cognition-execution-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_live",
      adapterResultCount: cognitionExecutionAdapterResults.length,
      actionFrameIds: cognitionExecutionActionFrameIds,
      liveReadyComponentKinds: cognitionExecutionLiveReadyComponentKinds,
      shadowAdapterMode: "workflow_component_adapter_shadow",
      shadowAdapterResultCount: cognitionExecutionShadowAdapterResults.length,
      shadowAttemptIds: cognitionExecutionShadowAttemptIds,
      shadowReceiptIds: cognitionExecutionShadowReceiptIds,
      shadowReplayFixtureRefs: cognitionExecutionShadowReplayFixtureRefs,
      shadowActionFrameIds: cognitionExecutionShadowActionFrameIds,
      shadowComponentKinds: cognitionExecutionShadowComponentKinds,
      shadowDivergenceClasses: cognitionExecutionShadowDivergenceClasses,
      liveShadowComparisonCount: liveShadowComparisons.length,
      liveShadowBlockingDivergenceCount: liveShadowComparisons.filter(
        (comparison) => comparison.blocking,
      ).length,
      liveShadowUnclassifiedDivergenceCount: liveShadowComparisons.filter(
        (comparison) => comparison.divergence === "unclassified",
      ).length,
      gateAdapterMode: "workflow_component_adapter_gated",
      gateAdapterResultCount: cognitionExecutionGateAdapterResults.length,
      gateAttemptIds: cognitionExecutionGateAttemptIds,
      gateReceiptIds: cognitionExecutionGateReceiptIds,
      gateReplayFixtureRefs: cognitionExecutionGateReplayFixtureRefs,
      gateActionFrameIds: cognitionExecutionGateActionFrameIds,
      gateComponentKinds: cognitionExecutionGateComponentKinds,
      gateDivergenceClasses: cognitionExecutionGateDivergenceClasses,
      nodeAuthorityGate: cognitionNodeAuthorityGate,
      authorityMode: cognitionNodeAuthorityGate.authorityMode,
      authoritative: cognitionNodeAuthorityGate.authoritative,
      nodeAuthorityBlockers: cognitionNodeAuthorityGate.blockers,
      promptAssemblyMode: "workflow_synchronous_envelope",
      promptHash: promptAssemblyPromptHash,
      promptHashMatches: true,
      ready: true,
      attemptIds: [
        "harness-default-dispatch:attempt-planner_envelope",
        "harness-default-dispatch:attempt-prompt_assembler_envelope",
        "harness-default-dispatch:attempt-task_state_envelope",
        ...cognitionExecutionShadowAttemptIds,
        ...cognitionExecutionGateAttemptIds,
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-planner_envelope",
        "harness-default-dispatch:receipt-prompt_assembler_envelope",
        "harness-default-dispatch:receipt-task_state_envelope",
        ...cognitionExecutionShadowReceiptIds,
        ...cognitionExecutionGateReceiptIds,
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-planner_envelope",
        "harness-default-dispatch:fixture-prompt_assembler_envelope",
        "harness-default-dispatch:fixture-task_state_envelope",
        ...cognitionExecutionShadowReplayFixtureRefs,
        ...cognitionExecutionGateReplayFixtureRefs,
      ],
      policyDecision: "accept_workflow_prompt_assembly_hash_envelope",
    },
    routingModelAuthorityProof: {
      schemaVersion: "workflow.harness.routing-model-authority-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_gated",
      adapterResultCount: routingModelAdapterResults.length,
      actionFrameIds: routingModelActionFrameIds,
      componentKinds: routingModelComponentKinds,
      divergenceClasses: routingModelDivergenceClasses,
      shadowAdapterMode: "workflow_component_adapter_shadow",
      shadowAdapterResultCount: routingModelShadowAdapterResults.length,
      shadowAttemptIds: routingModelShadowAttemptIds,
      shadowReceiptIds: routingModelShadowReceiptIds,
      shadowReplayFixtureRefs: routingModelShadowReplayFixtureRefs,
      shadowActionFrameIds: routingModelShadowActionFrameIds,
      shadowComponentKinds: routingModelShadowComponentKinds,
      shadowDivergenceClasses: routingModelShadowDivergenceClasses,
      nodeAuthorityGate: routingModelNodeAuthorityGate,
      authorityMode: routingModelNodeAuthorityGate.authorityMode,
      authoritative: routingModelNodeAuthorityGate.authoritative,
      nodeAuthorityBlockers: routingModelNodeAuthorityGate.blockers,
      visibleOutputAuthority:
        routingModelNodeAuthorityGate.visibleOutputAuthority,
      readOnlyCapabilityRoutingReady:
        routingModelNodeAuthorityGate.readOnlyCapabilityRoutingReady,
      rollbackAvailable: routingModelNodeAuthorityGate.rollbackAvailable,
      ready: routingModelNodeAuthorityGate.authoritative,
      attemptIds: routingModelAttemptIds,
      receiptIds: routingModelReceiptIds,
      replayFixtureRefs: routingModelReplayFixtureRefs,
      policyDecision: routingModelNodeAuthorityGate.policyDecision,
    },
    verificationOutputAuthorityProof: {
      schemaVersion: "workflow.harness.verification-output-authority-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_gated",
      adapterResultCount: verificationOutputAdapterResults.length,
      actionFrameIds: verificationOutputActionFrameIds,
      componentKinds: verificationOutputComponentKinds,
      divergenceClasses: verificationOutputDivergenceClasses,
      shadowAdapterMode: "workflow_component_adapter_shadow",
      shadowAdapterResultCount: verificationOutputShadowAdapterResults.length,
      shadowAttemptIds: verificationOutputShadowAttemptIds,
      shadowReceiptIds: verificationOutputShadowReceiptIds,
      shadowReplayFixtureRefs: verificationOutputShadowReplayFixtureRefs,
      shadowActionFrameIds: verificationOutputShadowActionFrameIds,
      shadowComponentKinds: verificationOutputShadowComponentKinds,
      shadowDivergenceClasses: verificationOutputShadowDivergenceClasses,
      nodeAuthorityGate: verificationOutputNodeAuthorityGate,
      authorityMode: verificationOutputNodeAuthorityGate.authorityMode,
      authoritative: verificationOutputNodeAuthorityGate.authoritative,
      nodeAuthorityBlockers: verificationOutputNodeAuthorityGate.blockers,
      outputWriterHandoffReady:
        verificationOutputNodeAuthorityGate.outputWriterHandoffReady,
      outputWriterVisibleWriteReady:
        verificationOutputNodeAuthorityGate.outputWriterVisibleWriteReady,
      outputWriterVisibleWriteCommitted:
        verificationOutputNodeAuthorityGate.outputWriterVisibleWriteCommitted,
      rollbackAvailable: verificationOutputNodeAuthorityGate.rollbackAvailable,
      ready: verificationOutputNodeAuthorityGate.authoritative,
      attemptIds: verificationOutputAttemptIds,
      receiptIds: verificationOutputReceiptIds,
      replayFixtureRefs: verificationOutputReplayFixtureRefs,
      policyDecision: verificationOutputNodeAuthorityGate.policyDecision,
    },
    authorityToolingAuthorityProof: {
      schemaVersion: "workflow.harness.authority-tooling-authority-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_gated",
      adapterResultCount: authorityToolingAdapterResults.length,
      actionFrameIds: authorityToolingActionFrameIds,
      componentKinds: authorityToolingComponentKinds,
      divergenceClasses: authorityToolingDivergenceClasses,
      shadowAdapterMode: "workflow_component_adapter_shadow",
      shadowAdapterResultCount: authorityToolingShadowAdapterResults.length,
      shadowAttemptIds: authorityToolingShadowAttemptIds,
      shadowReceiptIds: authorityToolingShadowReceiptIds,
      shadowReplayFixtureRefs: authorityToolingShadowReplayFixtureRefs,
      shadowActionFrameIds: authorityToolingShadowActionFrameIds,
      shadowComponentKinds: authorityToolingShadowComponentKinds,
      shadowDivergenceClasses: authorityToolingShadowDivergenceClasses,
      nodeAuthorityGate: authorityToolingNodeAuthorityGate,
      authorityMode: authorityToolingNodeAuthorityGate.authorityMode,
      authoritative: authorityToolingNodeAuthorityGate.authoritative,
      nodeAuthorityBlockers: authorityToolingNodeAuthorityGate.blockers,
      readOnlyRouteAccepted:
        authorityToolingNodeAuthorityGate.readOnlyRouteAccepted,
      destructiveRouteDenied:
        authorityToolingNodeAuthorityGate.destructiveRouteDenied,
      mutatingToolCallsBlocked:
        authorityToolingNodeAuthorityGate.mutatingToolCallsBlocked,
      sideEffectsExecuted: authorityToolingNodeAuthorityGate.sideEffectsExecuted,
      gateLiveReady: authorityToolingNodeAuthorityGate.gateLiveReady,
      readOnlyAuthorityCanaryReady:
        authorityToolingNodeAuthorityGate.readOnlyAuthorityCanaryReady,
      rollbackAvailable: authorityToolingNodeAuthorityGate.rollbackAvailable,
      ready: authorityToolingNodeAuthorityGate.authoritative,
      attemptIds: authorityToolingAttemptIds,
      receiptIds: authorityToolingReceiptIds,
      replayFixtureRefs: authorityToolingReplayFixtureRefs,
      policyDecision: authorityToolingNodeAuthorityGate.policyDecision,
    },
    modelExecutionMode: "workflow_synchronous_envelope",
    modelExecutionEnvelopeReady: true,
    modelExecutionBindingId,
    modelExecutionBindingReady: true,
    modelExecutionPromptHash,
    modelExecutionPromptHashMatches: true,
    modelExecutionOutputHash,
    modelExecutionOutputHashMatches: true,
    modelExecutionProviderInvocationMode: "workflow_provider_canary",
    modelExecutionLowLevelInvocationDeferred: false,
    modelExecutionRecoveryMode: "fail_closed",
    modelExecutionLatencyMs: 0,
    modelProviderCanaryMode: "workflow_provider_canary",
    modelProviderCanaryReady: true,
    modelProviderCanaryCandidateOutputHash: actualVisibleOutputHash,
    modelProviderCanaryPriorWorkflowOutputHash: actualVisibleOutputHash,
    modelProviderCanaryOutputHashMatches: true,
    modelProviderCanaryTranscriptMatches: true,
    modelProviderCanaryRecoveryReady: true,
    modelProviderCanaryRollbackAvailable: true,
    modelProviderGatedVisibleOutputMode:
      "workflow_provider_gated_visible_output",
    modelProviderGatedVisibleOutputEnabled: true,
    modelProviderGatedVisibleOutputReady: true,
    modelProviderGatedVisibleOutputSelected: true,
    modelProviderGatedVisibleOutputEligible: true,
    modelProviderGatedVisibleOutputScenario: "retained_no_tool_answer",
    modelProviderGatedVisibleOutputCohort: "retained_read_only_no_tool",
    modelProviderGatedVisibleOutputRetainedReadOnlyNoTool: true,
    modelProviderGatedVisibleOutputRequiredScenarioSet: [
      "retained_no_tool_answer",
      "retained_repo_grounded_answer",
      "retained_planning_without_mutation",
      "retained_mermaid_rendering",
      "retained_source_heavy_synthesis",
      "retained_probe_behavior",
      "retained_harness_dogfooding",
    ],
    modelProviderGatedVisibleOutputScenarioCoverageKey:
      "retained_no_tool_answer",
    modelProviderGatedVisibleOutputActivationFlag:
      "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT",
    modelProviderGatedVisibleOutputActivationId:
      DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    modelProviderGatedVisibleOutputAuthority: "workflow_model_provider_call",
    modelProviderGatedVisibleOutputRollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    modelProviderGatedVisibleOutputRollbackAvailable: true,
    selectedVisibleOutputAuthority: "workflow_model_provider_call",
    selectedVisibleOutputHash: actualVisibleOutputHash,
    workflowProviderVisibleOutputHash: actualVisibleOutputHash,
    priorWorkflowVisibleOutputHash: actualVisibleOutputHash,
    priorWorkflowVisibleOutputComputed: true,
    priorWorkflowVisibleOutputHashMatchesSelected: true,
    selectedVisibleOutputAuthorityMatchesTranscript: true,
    visibleOutputDivergenceClass: null,
    modelProviderGatedVisibleOutputRollbackDrillEnabled: true,
    modelProviderGatedVisibleOutputRollbackDrillReady: true,
    modelProviderGatedVisibleOutputRollbackDrillFailureInjected: true,
    modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash:
      "sha256:provider-output-divergence",
    modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges: true,
    modelProviderGatedVisibleOutputRollbackDrillDivergenceClass:
      "provider_output_hash_divergence",
    modelProviderGatedVisibleOutputRollbackDrillRecoveryMode: "fail_closed",
    modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority:
      "workflow_model_recovery_fail_closed",
    modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged: true,
    modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted: true,
    modelProviderGatedVisibleOutputRollbackDrillActivationBlockers: [
      "model_provider_output_hash_divergence",
    ],
    readOnlyCapabilityRoutingMode: "workflow_read_only_capability_routing",
    readOnlyCapabilityRoutingReady: true,
    readOnlyCapabilityRoutingSelected: true,
    readOnlyCapabilityRoutingEligible: true,
    readOnlyCapabilityRoutingScenario: "retained_repo_grounded_answer",
    readOnlyCapabilityRoutingRequiredScenarioSet: [
      "retained_repo_grounded_answer",
      "retained_source_heavy_synthesis",
      "retained_probe_behavior",
    ],
    readOnlyCapabilityRoutingScenarioCoverageKey:
      "retained_repo_grounded_answer",
    readOnlyCapabilityRoutingSourceMaterialReady: true,
    readOnlyCapabilityRoutingNoMutationReady: true,
    readOnlyCapabilityRoutingWorkflowOwnedNodeKinds: [
      "memory_read",
      "capability_sequencer",
      "tool_router",
      "dry_run_simulator",
    ],
    modelProviderCanaryProof: {
      schemaVersion: "workflow.harness.model-provider-call-canary.v1",
      mode: "workflow_provider_canary",
      candidateOutputHash: actualVisibleOutputHash,
      priorWorkflowOutputHash: actualVisibleOutputHash,
      outputHashMatches: true,
      transcriptMatches: true,
      recoveryReady: true,
      rollbackAvailable: true,
      attemptIds: [
        "harness-default-dispatch:attempt-model_provider_call_canary",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_provider_call_canary",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_call_canary",
      ],
      policyDecision:
        "accept_workflow_model_provider_call_canary_with_workflow_recovery",
    },
    modelProviderGatedVisibleOutputProof: {
      schemaVersion: "workflow.harness.model-provider-gated-visible-output.v1",
      mode: "workflow_provider_gated_visible_output",
      enabled: true,
      ready: true,
      selected: true,
      eligible: true,
      scope: "retained_no_tool_answer",
      cohort: "retained_read_only_no_tool",
      retainedReadOnlyNoTool: true,
      requiredScenarioSet: [
        "retained_no_tool_answer",
        "retained_repo_grounded_answer",
        "retained_planning_without_mutation",
        "retained_mermaid_rendering",
        "retained_source_heavy_synthesis",
        "retained_probe_behavior",
        "retained_harness_dogfooding",
      ],
      scenarioCoverageKey: "retained_no_tool_answer",
      activationFlag: "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT",
      activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      selectedVisibleOutputAuthority: "workflow_model_provider_call",
      selectedVisibleOutputHash: actualVisibleOutputHash,
      workflowProviderOutputHash: actualVisibleOutputHash,
      priorWorkflowVisibleOutputHash: actualVisibleOutputHash,
      priorWorkflowVisibleOutputComputed: true,
      priorWorkflowVisibleOutputHashMatchesSelected: true,
      selectedAuthorityMatchesTranscript: true,
      divergenceClass: null,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      rollbackAvailable: true,
      attemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output",
      ],
      policyDecision:
        "accept_workflow_provider_gated_visible_output_with_workflow_recovery",
    },
    modelProviderGatedVisibleOutputRollbackDrillProof: {
      schemaVersion:
        "workflow.harness.model-provider-gated-visible-output-rollback-drill.v1",
      drillId:
        "harness-provider-gated-visible-output-rollback-drill:default-agent-harness:turn-default",
      enabled: true,
      ready: true,
      failureInjected: true,
      workflowProviderOutputHash: actualVisibleOutputHash,
      injectedWorkflowProviderOutputHash: "sha256:provider-output-divergence",
      priorWorkflowVisibleOutputHash: actualVisibleOutputHash,
      actualVisibleOutputHash,
      outputHashDiverges: true,
      divergenceClass: "provider_output_hash_divergence",
      recoveryMode: "fail_closed",
      selectedAuthorityAfterRollback: "workflow_model_recovery_fail_closed",
      transcriptUnchanged: true,
      rollbackExecuted: true,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      rollbackAvailable: true,
      activationBlockers: ["model_provider_output_hash_divergence"],
      attemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
      ],
      policyDecision:
        "fail_closed_workflow_model_recovery_on_provider_output_hash_divergence",
    },
    readOnlyCapabilityRoutingProof: {
      schemaVersion: "workflow.harness.read-only-capability-routing.v1",
      mode: "workflow_read_only_capability_routing",
      ready: true,
      selected: true,
      eligible: true,
      scenario: "retained_repo_grounded_answer",
      requiredScenarioSet: [
        "retained_repo_grounded_answer",
        "retained_source_heavy_synthesis",
        "retained_probe_behavior",
      ],
      scenarioCoverageKey: "retained_repo_grounded_answer",
      sourceMaterialReady: true,
      workflowOwnedNodeKinds: [
        "memory_read",
        "capability_sequencer",
        "tool_router",
        "dry_run_simulator",
      ],
      toolUseMode: "read_only_or_dry_run",
      sideEffectsExecuted: false,
      mutationExecuted: false,
      noMutationReady: true,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      rollbackAvailable: true,
      attemptIds: [
        "harness-default-dispatch:attempt-read_only_source_router",
        "harness-default-dispatch:attempt-read_only_capability_sequencer",
        "harness-default-dispatch:attempt-read_only_tool_router",
        "harness-default-dispatch:attempt-read_only_no_mutation_drill",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-read_only_source_router",
        "harness-default-dispatch:receipt-read_only_capability_sequencer",
        "harness-default-dispatch:receipt-read_only_tool_router",
        "harness-default-dispatch:receipt-read_only_no_mutation_drill",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-read_only_source_router",
        "harness-default-dispatch:fixture-read_only_capability_sequencer",
        "harness-default-dispatch:fixture-read_only_tool_router",
        "harness-default-dispatch:fixture-read_only_no_mutation_drill",
      ],
      policyDecision:
        "accept_workflow_read_only_capability_routing_without_side_effects",
    },
    verificationOutputProof: {
      schemaVersion: "workflow.harness.verification-output-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_gated",
      adapterResultCount: verificationOutputAdapterResults.length,
      attemptIds: verificationOutputAttemptIds,
      receiptIds: verificationOutputReceiptIds,
      replayFixtureRefs: verificationOutputReplayFixtureRefs,
      actionFrameIds: verificationOutputActionFrameIds,
      componentKinds: verificationOutputComponentKinds,
      divergenceClasses: verificationOutputDivergenceClasses,
      shadowAdapterMode: "workflow_component_adapter_shadow",
      shadowAdapterResultCount: verificationOutputShadowAdapterResults.length,
      shadowAttemptIds: verificationOutputShadowAttemptIds,
      shadowReceiptIds: verificationOutputShadowReceiptIds,
      shadowReplayFixtureRefs: verificationOutputShadowReplayFixtureRefs,
      shadowActionFrameIds: verificationOutputShadowActionFrameIds,
      shadowComponentKinds: verificationOutputShadowComponentKinds,
      shadowDivergenceClasses: verificationOutputShadowDivergenceClasses,
      completionDecision: "objective_satisfied",
      receiptProjectionAuthority: "blessed_workflow_activation_default",
      qualityLedgerAuthority: "blessed_workflow_activation_default",
      outputWriterAuthority: "blessed_workflow_activation_default",
      selectedVisibleOutputAuthority: "workflow_model_provider_call",
      selectedVisibleOutputHash: actualVisibleOutputHash,
      outputHashMatches: true,
      nodeAuthorityGate: verificationOutputNodeAuthorityGate,
      authorityMode: verificationOutputNodeAuthorityGate.authorityMode,
      authoritative: verificationOutputNodeAuthorityGate.authoritative,
      nodeAuthorityBlockers: verificationOutputNodeAuthorityGate.blockers,
      ready: true,
      policyDecision: verificationOutputNodeAuthorityGate.policyDecision,
    },
    authorityToolingAdapterProof: {
      schemaVersion: "workflow.harness.authority-tooling-adapter-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_gated",
      adapterResultCount: authorityToolingAdapterResults.length,
      attemptIds: authorityToolingAttemptIds,
      receiptIds: authorityToolingReceiptIds,
      replayFixtureRefs: authorityToolingReplayFixtureRefs,
      actionFrameIds: authorityToolingActionFrameIds,
      componentKinds: authorityToolingComponentKinds,
      divergenceClasses: authorityToolingDivergenceClasses,
      shadowAdapterMode: "workflow_component_adapter_shadow",
      shadowAdapterResultCount: authorityToolingShadowAdapterResults.length,
      shadowAttemptIds: authorityToolingShadowAttemptIds,
      shadowReceiptIds: authorityToolingShadowReceiptIds,
      shadowReplayFixtureRefs: authorityToolingShadowReplayFixtureRefs,
      shadowActionFrameIds: authorityToolingShadowActionFrameIds,
      shadowComponentKinds: authorityToolingShadowComponentKinds,
      shadowDivergenceClasses: authorityToolingShadowDivergenceClasses,
      readOnlyRouteAccepted: true,
      destructiveRouteDenied: true,
      mutatingToolCallsBlocked: true,
      sideEffectsExecuted: false,
      mutationExecuted: false,
      authorityTransferred: false,
      nodeAuthorityGate: authorityToolingNodeAuthorityGate,
      authorityMode: authorityToolingNodeAuthorityGate.authorityMode,
      authoritative: authorityToolingNodeAuthorityGate.authoritative,
      nodeAuthorityBlockers: authorityToolingNodeAuthorityGate.blockers,
      readOnlyCatalogReady: true,
      mutationDeferredComponentKinds:
        authorityToolingMutationDeferredComponentKinds,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      ready: authorityToolingNodeAuthorityGate.authoritative,
      policyDecision: authorityToolingNodeAuthorityGate.policyDecision,
    },
    livePromotionReadinessProof,
    workerBindingRegistryRecord,
    workerAttachReceipt,
    workerAttachResumeReceipt,
    workerAttachRollbackReceipt,
    workerAttachLifecycle,
    workerAttachLifecycleAttemptIds,
    workerAttachLifecycleStatuses,
    workerAttachLifecycleComplete,
    workerSessionRecord,
    workerLaunchEnvelopes,
    workerHandoffReceipts,
    workerLaunchEnvelopeIds,
    workerHandoffReceiptIds,
    workerHandoffNodeAttemptIds,
    workerHandoffNodeAttempts,
    workerHandoffReplayFixtureRefs,
    modelExecutionProof: {
      schemaVersion: "workflow.harness.model-execution-envelope.v1",
      mode: "workflow_synchronous_envelope",
      bindingId: modelExecutionBindingId,
      bindingReady: true,
      promptHash: modelExecutionPromptHash,
      promptHashMatches: true,
      outputHash: modelExecutionOutputHash,
      outputHashMatches: true,
      providerInvocationMode: "workflow_provider_canary",
      lowLevelInvocationDeferred: false,
      recoveryMode: "fail_closed",
      latencyMs: 0,
      routingModelAdapterMode: "workflow_component_adapter_gated",
      routingModelAdapterResultCount: routingModelAdapterResults.length,
      routingModelAttemptIds,
      routingModelReceiptIds,
      routingModelReplayFixtureRefs,
      routingModelActionFrameIds,
      routingModelComponentKinds,
      routingModelDivergenceClasses,
      routingModelShadowAdapterMode: "workflow_component_adapter_shadow",
      routingModelShadowAdapterResultCount:
        routingModelShadowAdapterResults.length,
      routingModelShadowAttemptIds,
      routingModelShadowReceiptIds,
      routingModelShadowReplayFixtureRefs,
      routingModelShadowActionFrameIds,
      routingModelShadowComponentKinds,
      routingModelShadowDivergenceClasses,
      providerCanaryReady: true,
      providerCanaryAttemptIds: [
        "harness-default-dispatch:attempt-model_provider_call_canary",
      ],
      providerCanaryReceiptIds: [
        "harness-default-dispatch:receipt-model_provider_call_canary",
      ],
      providerCanaryReplayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_call_canary",
      ],
      providerGatedVisibleOutputReady: true,
      providerGatedVisibleOutputSelected: true,
      providerGatedVisibleOutputAttemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      ],
      providerGatedVisibleOutputReceiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output",
      ],
      providerGatedVisibleOutputReplayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output",
      ],
      providerGatedVisibleOutputRollbackDrillReady: true,
      providerGatedVisibleOutputRollbackDrillAttemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      ],
      providerGatedVisibleOutputRollbackDrillReceiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
      ],
      providerGatedVisibleOutputRollbackDrillReplayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
      ],
      selectedVisibleOutputAuthority: "workflow_model_provider_call",
      attemptIds: [
        "harness-default-dispatch:attempt-model_router_envelope",
        "harness-default-dispatch:attempt-model_call_envelope",
        "harness-default-dispatch:attempt-model_provider_call_canary",
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_router_envelope",
        "harness-default-dispatch:receipt-model_call_envelope",
        "harness-default-dispatch:receipt-model_provider_call_canary",
        "harness-default-dispatch:receipt-model_provider_gated_visible_output",
        "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_router_envelope",
        "harness-default-dispatch:fixture-model_call_envelope",
        "harness-default-dispatch:fixture-model_provider_call_canary",
        "harness-default-dispatch:fixture-model_provider_gated_visible_output",
        "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
      ],
      policyDecision:
        "accept_workflow_model_provider_call_canary_with_workflow_recovery",
    },
    outputAuthority: "blessed_workflow_activation_default",
    outputWriterDeferred: false,
    outputWriterStatus: "visible_write_committed",
    outputWriterHandoffReady: true,
    outputWriterAuthorityTransferred: true,
    outputWriterMaterializationMode: "workflow_visible_transcript_write",
    outputWriterMaterializationCanaryReady: true,
    outputWriterMaterializationCommitted: true,
    outputWriterStagedWriteMode: "isolated_checkpoint_blob",
    outputWriterStagedWriteCanaryReady: true,
    outputWriterStagedWritePersisted: true,
    outputWriterStagedWriteCommitted: true,
    outputWriterStagedWriteVisible: false,
    outputWriterStagedWriteExcludedFromVisibleTranscript: true,
    outputWriterStagedWriteRollbackStatus: "deleted",
    outputWriterStagedWriteRollbackVerified: true,
    outputWriterVisibleWriteMode: "workflow_visible_transcript_write",
    outputWriterVisibleWriteReady: true,
    outputWriterVisibleWritePersisted: true,
    outputWriterVisibleWriteCommitted: true,
    outputWriterVisibleWriteVisible: true,
    outputWriterVisibleWriteIdentityCheckpointPersisted: true,
    outputWriterVisibleWriteRecoveryDuplicateSuppressed: true,
    authorityToolingMode: "workflow_live_dry_run",
    authorityToolingReady: true,
    authorityToolingPolicyGateReady: true,
    authorityToolingToolRouterReady: true,
    authorityToolingDryRunSimulatorReady: true,
    authorityToolingApprovalGateReady: true,
    authorityToolingGateLiveReady: true,
    authorityToolingPolicyGateLiveReady: true,
    authorityToolingDestructiveDenialLiveReady: true,
    authorityToolingApprovalGateLiveReady: true,
    authorityToolingReadOnlyAuthorityCanaryReady: true,
    authorityToolingProviderCatalogLiveReady: true,
    authorityToolingProviderCatalogLiveComponentKind: "mcp_provider",
    authorityToolingMcpToolCatalogLiveReady: true,
    authorityToolingMcpToolCatalogLiveComponentKind: "mcp_tool_call",
    authorityToolingNativeToolCatalogLiveReady: true,
    authorityToolingNativeToolCatalogLiveComponentKind: "tool_call",
    authorityToolingConnectorCatalogLiveReady: true,
    authorityToolingConnectorCatalogLiveComponentKind: "connector_call",
    authorityToolingWalletCapabilityLiveDryRunReady: true,
    authorityToolingWalletCapabilityLiveDryRunComponentKind:
      "wallet_capability",
    authorityToolingReadOnlyRouteAccepted: true,
    authorityToolingDestructiveRouteDenied: true,
    authorityToolingMutatingToolCallsBlocked: true,
    authorityToolingSideEffectsExecuted: false,
    authorityToolingRollbackAvailable: true,
    authorityToolingProof: {
      schemaVersion: "workflow.harness.authority-tooling-live-dry-run.v1",
      mode: "workflow_live_dry_run",
      readOnlyRouteAccepted: true,
      destructiveRouteDenied: true,
      mutatingToolCallsBlocked: true,
      sideEffectsExecuted: false,
      policyGateReady: true,
      toolRouterReady: true,
      dryRunSimulatorReady: true,
      approvalGateReady: true,
      rollbackAvailable: true,
      gateLiveReady: true,
      gateLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_policy_gate",
        "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
        "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      ],
      gateLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_policy_gate",
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
        "harness-default-dispatch:receipt-authority_tooling_approval_gate",
      ],
      gateLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_policy_gate",
        "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
        "harness-default-dispatch:fixture-authority_tooling_approval_gate",
      ],
      policyGateLiveReady: true,
      policyGateLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      ],
      policyGateLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_policy_gate",
      ],
      policyGateLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_policy_gate",
      ],
      destructiveDenialLiveReady: true,
      destructiveDenialLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      ],
      destructiveDenialLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      ],
      destructiveDenialLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
      ],
      approvalGateLiveReady: true,
      approvalGateLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      ],
      approvalGateLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_approval_gate",
      ],
      approvalGateLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_approval_gate",
      ],
      readOnlyAuthorityCanaryReady: true,
      providerCatalogLiveReady: true,
      providerCatalogLiveComponentKind: "mcp_provider",
      providerCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      ],
      providerCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
      ],
      providerCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
      ],
      mcpToolCatalogLiveReady: true,
      mcpToolCatalogLiveComponentKind: "mcp_tool_call",
      mcpToolCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      ],
      mcpToolCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
      ],
      mcpToolCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
      ],
      nativeToolCatalogLiveReady: true,
      nativeToolCatalogLiveComponentKind: "tool_call",
      nativeToolCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      ],
      nativeToolCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
      ],
      nativeToolCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
      ],
      connectorCatalogLiveReady: true,
      connectorCatalogLiveComponentKind: "connector_call",
      connectorCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      ],
      connectorCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
      ],
      connectorCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
      ],
      walletCapabilityLiveDryRunReady: true,
      walletCapabilityLiveDryRunComponentKind: "wallet_capability",
      walletCapabilityLiveDryRunAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
      ],
      walletCapabilityLiveDryRunReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
      ],
      walletCapabilityLiveDryRunReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
      ],
      readOnlyComponentKinds: authorityToolingReadOnlyComponentKinds,
      readOnlyAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
      ],
      readOnlyReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
      ],
      readOnlyReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
      ],
      denialReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      ],
      deferredMutationComponentKinds:
        authorityToolingMutationDeferredComponentKinds,
      mutationDeferredComponentKinds:
        authorityToolingMutationDeferredComponentKinds,
      policyDecision:
        "allow_read_only_route_and_deny_destructive_tooling_without_side_effect",
    },
    workflowTranscriptRecoveryAuthorityRetained: false,
    workflowTranscriptRecoveryAvailable: true,
    proposedVisibleOutputHash,
    actualVisibleOutputHash,
    outputHashAlgorithm: "runtime_prompt_hash:v1",
    outputHashMatches: proposedVisibleOutputHash === actualVisibleOutputHash,
    outputHashDivergence: false,
    outputHashDivergenceCount: 0,
    workflowTranscriptWriteCandidate,
    workflowTranscriptWriteRecord,
    visibleTranscriptWriteProof,
    workflowTranscriptRecoveryProof,
    workflowTranscriptRecoveryRecord,
    stagedTranscriptWriteRecord,
    stagedTranscriptWriteProof,
    transcriptMaterializationContentHashMatches: true,
    transcriptMaterializationOrderMatches: true,
    transcriptMaterializationReceiptBindingMatches: true,
    transcriptMaterializationTargetMatches: true,
    transcriptMaterializationMatches: true,
    transcriptMaterializationDivergenceCount: 0,
    stagedTranscriptWriteContentHashMatches: true,
    stagedTranscriptWriteOrderMatches: true,
    stagedTranscriptWriteReceiptBindingMatches: true,
    stagedTranscriptWriteTargetMatches: true,
    stagedTranscriptWriteMatches: true,
    stagedTranscriptWriteDivergenceCount: 0,
    visibleTranscriptWriteContentHashMatches: true,
    visibleTranscriptWriteOrderMatches: true,
    visibleTranscriptWriteReceiptBindingMatches: true,
    visibleTranscriptWriteTargetMatches: true,
    visibleTranscriptWriteMatches: true,
    visibleTranscriptWriteDivergenceCount: 0,
    stagedTranscriptWriteComparison: {
      contentHashMatches: true,
      orderMatches: true,
      receiptBindingMatches: true,
      targetMatches: true,
      stagedWritePersisted: true,
      stagedWriteCommitted: true,
      stagedWriteVisible: false,
      excludedFromVisibleTranscript: true,
      rollbackStatus: "deleted",
      rollbackVerified: true,
      matches: true,
      divergenceClass: null,
    },
    transcriptMaterializationComparison: {
      contentHashMatches: true,
      orderMatches: true,
      receiptBindingMatches: true,
      targetMatches: true,
      candidateCommitted: false,
      priorWorkflowCommitted: false,
      recoveryDuplicateSuppressed: true,
      matches: true,
      divergenceClass: null,
    },
    visibleTranscriptWriteComparison: {
      contentHashMatches: true,
      orderMatches: true,
      receiptBindingMatches: true,
      targetMatches: true,
      workflowWritePersisted: true,
      workflowWriteCommitted: true,
      workflowWriteVisible: true,
      identityCheckpointPersisted: true,
      recoveryDuplicateSuppressed: true,
      matches: true,
      divergenceClass: null,
    },
    outputHashComparison: {
      proposedVisibleOutputHash,
      actualVisibleOutputHash,
      hashAlgorithm: "runtime_prompt_hash:v1",
      matches: proposedVisibleOutputHash === actualVisibleOutputHash,
      divergenceClass: null,
    },
    workflowOutputRecoveryAuthorityRetained: false,
    workflowOutputRecoveryAvailable: true,
    mutatingTurnsBlocked: true,
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    activationBlockers,
    policyDecision: dispatchAccepted
      ? "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write"
      : "block_workflow_default_until_gates_pass",
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

export function makeHarnessCanaryExecutionBoundary(
  options: {
    boundaryId?: string;
    clusterId?: WorkflowHarnessPromotionClusterId;
    selectorDecisionId?: string;
    status?: WorkflowHarnessCanaryExecutionBoundary["status"];
    executionMode?: WorkflowHarnessExecutionMode;
    runtimeAuthority?: WorkflowHarnessCanaryExecutionBoundary["runtimeAuthority"];
    activationBlockers?: string[];
    rollbackDrillStatus?: WorkflowHarnessCanaryExecutionBoundary["rollbackDrill"]["drillStatus"];
  } = {},
): WorkflowHarnessCanaryExecutionBoundary {
  const clusterId = options.clusterId ?? "verification_output";
  const componentKinds: WorkflowHarnessCanaryExecutionBoundary["componentKinds"] =
    HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId];
  const failedNodeKind =
    clusterId === "cognition"
      ? "task_state"
      : clusterId === "routing_model"
        ? "model_router"
        : clusterId === "authority_tooling"
          ? "policy_gate"
          : "verifier";
  const passed =
    options.status !== "blocked" && options.status !== "rolled_back";
  return {
    schemaVersion: "workflow.harness.canary-execution-boundary.v1",
    boundaryId:
      options.boundaryId ??
      `harness-canary-boundary:default-agent-harness:${clusterId}`,
    clusterId,
    clusterLabel: HARNESS_PROMOTION_CLUSTER_LABELS[clusterId],
    selectorDecisionId:
      options.selectorDecisionId ??
      "harness-selector:default-agent-harness:canary",
    selectedSelector: passed
      ? "blessed_workflow_live_canary"
      : "workflow_recovery_blocked",
    productionDefaultSelector: "workflow_recovery_blocked",
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: options.executionMode ?? (passed ? "live" : "gated"),
    runtimeAuthority:
      options.runtimeAuthority ??
      (passed
        ? "blessed_workflow_activation_canary"
        : "workflow_recovery_fail_closed"),
    executorKind: "workflow_node_executor",
    executorRef: "crate::project::execute_workflow_harness_canary_node",
    synchronous: true,
    enforcedBeforeVisibleOutput: true,
    canaryEligible: passed,
    status: options.status ?? "passed",
    componentKinds,
    executedComponentKinds: passed ? componentKinds : [],
    workflowNodeIds: componentKinds.map((kind) => `harness.${kind}`),
    nodeAttemptIds: componentKinds.map(
      (kind, index) =>
        `harness-canary:default:turn-1:${kind}:attempt-${index + 1}`,
    ),
    receiptIds: componentKinds.map(
      (kind) => `default:harness.${kind}:workflow-node-execution`,
    ),
    replayFixtureRefs: componentKinds.map(
      (kind) => `runtime-evidence:default:canary-fixture:${kind}`,
    ),
    activationBlockers: options.activationBlockers ?? [],
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    rollbackDrill: {
      schemaVersion: "workflow.harness.canary-rollback-drill.v1",
      drillId: "harness-canary-rollback-drill:default",
      selectorDecisionId:
        options.selectorDecisionId ??
        "harness-selector:default-agent-harness:canary",
      failureInjected: passed,
      failedNodeId: `harness.${failedNodeKind}.rollback_drill`,
      clusterId,
      failureClass: "deterministic_executor_failure",
      observedFailure: passed,
      rollbackExecuted: passed,
      rollbackSelector: "workflow_recovery_blocked",
      recoveryMode: passed ? "fail_closed" : "restore_prior_workflow_activation",
      recoveryTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      recoveryAvailable: true,
      recoveryBlockers: options.activationBlockers ?? [],
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      rollbackAvailable: true,
      drillStatus:
        options.rollbackDrillStatus ?? (passed ? "passed" : "not_run"),
      policyDecision: passed
        ? "fail_closed_workflow_recovery_on_workflow_executor_failure"
        : "block_workflow_default_until_gates_pass",
      evidenceRefs: ["runtime-evidence:default"],
    },
    policyDecision: passed
      ? "allow_synchronous_workflow_node_canary_boundary"
      : "block_workflow_default_until_gates_pass",
    evidenceRefs: [`runtime-evidence:canary-boundary:${clusterId}`],
  };
}

export function makeHarnessCanaryExecutionBoundaries(): WorkflowHarnessCanaryExecutionBoundary[] {
  return [
    makeHarnessCanaryExecutionBoundary({ clusterId: "cognition" }),
    makeHarnessCanaryExecutionBoundary({ clusterId: "routing_model" }),
    makeHarnessCanaryExecutionBoundary({ clusterId: "verification_output" }),
    makeHarnessCanaryExecutionBoundary({ clusterId: "authority_tooling" }),
  ];
}

const DEFAULT_HARNESS_EXECUTION_MODE: WorkflowHarnessExecutionMode =
  "projection";
const DEFAULT_HARNESS_COMPONENT_READINESS: WorkflowHarnessComponentReadiness =
  "projection_only";
const LIVE_READY_HARNESS_COMPONENTS = new Set<WorkflowHarnessComponentKind>([
  "planner",
  "prompt_assembler",
  "task_state",
]);
const SHADOW_READY_HARNESS_COMPONENTS = new Set<WorkflowHarnessComponentKind>([
  "uncertainty_gate",
  "runtime_doctor",
  "skill_registry",
  "hook_registry",
  "budget_gate",
  "capability_sequencer",
  "model_router",
  "model_call",
  "tool_router",
  "tool_call",
  "dry_run_simulator",
  "mcp_provider",
  "mcp_tool_call",
  "connector_call",
  "policy_gate",
  "approval_gate",
  "wallet_capability",
  "postcondition_synthesizer",
  "verifier",
  "completion_gate",
  "receipt_writer",
  "quality_ledger",
  "output_writer",
]);

const HARNESS_PROMOTION_CLUSTER_COMPONENTS: Record<
  WorkflowHarnessPromotionClusterId,
  WorkflowHarnessComponentKind[]
> = {
  cognition: [
    "planner",
    "prompt_assembler",
    "task_state",
    "runtime_doctor",
    "skill_registry",
    "hook_registry",
    "uncertainty_gate",
    "budget_gate",
    "capability_sequencer",
  ],
  routing_model: ["model_router", "model_call", "tool_router"],
  verification_output: [
    "postcondition_synthesizer",
    "verifier",
    "completion_gate",
    "receipt_writer",
    "quality_ledger",
    "output_writer",
  ],
  authority_tooling: [
    "policy_gate",
    "approval_gate",
    "dry_run_simulator",
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ],
};

const HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS: WorkflowHarnessComponentKind[] =
  [
    "planner",
    "prompt_assembler",
    "task_state",
    "model_router",
    "model_call",
    "tool_router",
    "postcondition_synthesizer",
    "verifier",
    "completion_gate",
    "receipt_writer",
    "quality_ledger",
    "output_writer",
    "policy_gate",
    "approval_gate",
    "dry_run_simulator",
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ];

const HARNESS_PROMOTION_CLUSTER_LABELS: Record<
  WorkflowHarnessPromotionClusterId,
  string
> = {
  cognition: "Cognition",
  routing_model: "Routing and model",
  verification_output: "Verification and output",
  authority_tooling: "Authority and tooling",
};

type ComponentSeed = {
  kind: WorkflowHarnessComponentKind;
  label: string;
  description: string;
  kernelRef: string;
  readiness?: WorkflowHarnessComponentReadiness;
  capabilityScope: string[];
  approvalMode?: WorkflowHarnessComponentSpec["approval"]["mode"];
  approvalRequired?: boolean;
  eventKinds: string[];
  evidence: string[];
  group: string;
  icon: string;
  timeoutMs?: number;
  maxAttempts?: number;
};

function componentId(kind: WorkflowHarnessComponentKind): string {
  return `ioi.agent-harness.${kind}.v1`;
}

function defaultReadinessForKind(
  kind: WorkflowHarnessComponentKind,
): WorkflowHarnessComponentReadiness {
  if (LIVE_READY_HARNESS_COMPONENTS.has(kind)) {
    return "live_ready";
  }
  return SHADOW_READY_HARNESS_COMPONENTS.has(kind)
    ? "shadow_ready"
    : DEFAULT_HARNESS_COMPONENT_READINESS;
}

function makeComponent(seed: ComponentSeed): WorkflowHarnessComponentSpec {
  const approvalRequired = seed.approvalRequired ?? false;
  return {
    componentId: componentId(seed.kind),
    version: "1.0.0",
    kind: seed.kind,
    readiness: seed.readiness ?? defaultReadinessForKind(seed.kind),
    label: seed.label,
    description: seed.description,
    kernelRef: seed.kernelRef,
    inputSchema: HARNESS_INPUT_SCHEMA,
    outputSchema: HARNESS_OUTPUT_SCHEMA,
    errorSchema: HARNESS_ERROR_SCHEMA,
    timeout: {
      timeoutMs: seed.timeoutMs ?? 30000,
      cancellation: "cooperative",
    },
    retry: {
      maxAttempts: seed.maxAttempts ?? 1,
      backoffMs: seed.maxAttempts && seed.maxAttempts > 1 ? 250 : 0,
      retryableErrors: ["timeout", "rate_limit", "transient_provider_error"],
    },
    requiredCapabilityScope: seed.capabilityScope,
    approval: {
      required: approvalRequired,
      mode: seed.approvalMode ?? (approvalRequired ? "policy_gate" : "none"),
      reason: approvalRequired
        ? "Component may cross a privileged runtime boundary."
        : "Component is governed by workflow and node policy.",
    },
    emittedEvents: seed.eventKinds,
    evidence: seed.evidence,
    ui: {
      icon: seed.icon,
      group: seed.group,
      summary: seed.description,
    },
  };
}

export const DEFAULT_AGENT_HARNESS_COMPONENTS: WorkflowHarnessComponentSpec[] =
  [
    makeComponent({
      kind: "planner",
      label: "Planner",
      description:
        "Produces the next plan step from session state, user input, and available capabilities.",
      kernelRef: "crates/services/src/agentic/runtime/service/planning/planner",
      capabilityScope: ["reasoning.read", "session.state.read"],
      eventKinds: ["PlanReceipt", "KernelEvent::PlanReceipt"],
      evidence: ["plan_id", "planner_policy_hash", "chosen_step_reason"],
      group: "Planning",
      icon: "list-checks",
    }),
    makeComponent({
      kind: "prompt_assembler",
      label: "Prompt assembler",
      description:
        "Builds the runtime prompt envelope from session state, policy, tools, evidence, and truncation diagnostics.",
      kernelRef:
        "crates/types/src/app/runtime_contracts.rs::PromptAssemblyContract",
      capabilityScope: [
        "prompt.assemble",
        "session.state.read",
        "evidence.read",
      ],
      eventKinds: ["PromptAssemblyContract", "AgentRuntimeEvent"],
      evidence: [
        "sections",
        "final_prompt_hash",
        "conflict_resolutions",
        "truncation_diagnostics",
      ],
      group: "Planning",
      icon: "panel-top",
    }),
    makeComponent({
      kind: "task_state",
      label: "Task state",
      description:
        "Projects the current objective, known facts, uncertainty, blockers, stale facts, and evidence references.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["session.state.read", "evidence.read"],
      eventKinds: ["AgentRuntimeEvent", "TaskStateModel"],
      evidence: ["task_state_id", "evidence_refs", "stale_fact_refs"],
      group: "Cognition",
      icon: "map",
    }),
    makeComponent({
      kind: "runtime_doctor",
      label: "Runtime doctor",
      description:
        "Reads the daemon doctor report so workflow activation can block on required runtime readiness failures.",
      kernelRef: "packages/runtime-daemon/src/index.mjs::doctorReport",
      capabilityScope: ["runtime.doctor.read", "workflow.activation.read"],
      eventKinds: ["RuntimeDoctorReport"],
      evidence: ["runtime.doctor", "doctor.blockers", "doctor.redaction"],
      group: "Governance",
      icon: "activity",
    }),
    makeComponent({
      kind: "skill_registry",
      label: "Skill registry",
      description:
        "Discovers governed runtime skills from IOI, Agents, Cursor, Claude, and global skill directories.",
      kernelRef: "packages/runtime-daemon/src/index.mjs::listSkills",
      capabilityScope: ["skill.catalog.read", "workflow.context.read"],
      eventKinds: ["SkillRegistryProjection"],
      evidence: ["runtime.skills", "skill.hashes", "skill.provenance"],
      group: "State",
      icon: "book-open",
    }),
    makeComponent({
      kind: "hook_registry",
      label: "Hook registry",
      description:
        "Discovers governed runtime hooks, event subscriptions, failure policy, and authority declarations.",
      kernelRef: "packages/runtime-daemon/src/index.mjs::listHooks",
      capabilityScope: ["hook.catalog.read", "workflow.activation.read"],
      eventKinds: ["HookRegistryProjection"],
      evidence: ["runtime.hooks", "hook.failurePolicy", "hook.authorityScopes"],
      group: "Governance",
      icon: "webhook",
    }),
    makeComponent({
      kind: "uncertainty_gate",
      label: "Uncertainty gate",
      description:
        "Chooses whether to ask, retrieve, probe, dry-run, execute, verify, escalate, or stop.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["reasoning.route", "session.state.read"],
      eventKinds: ["UncertaintyAssessment", "RuntimeStrategyDecision"],
      evidence: ["ambiguity_level", "value_of_information", "selected_action"],
      group: "Cognition",
      icon: "circle-help",
    }),
    makeComponent({
      kind: "probe_runner",
      label: "Probe runner",
      description:
        "Runs the cheapest bounded validation action for a stated hypothesis.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/tool_execution/probe.rs",
      capabilityScope: ["probe.run", "verification.read"],
      eventKinds: ["ProbeStarted", "ProbeCompleted"],
      evidence: ["hypothesis", "expected_observation", "probe_result"],
      group: "Cognition",
      icon: "radar",
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "budget_gate",
      label: "Cognitive budget",
      description:
        "Bounds reasoning tokens, tool calls, retries, verification spend, and wall time.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["budget.evaluate", "session.state.read"],
      eventKinds: ["CognitiveBudget", "RuntimeStrategyDecision"],
      evidence: ["remaining_tokens", "remaining_tool_calls", "stop_threshold"],
      group: "Cognition",
      icon: "gauge",
    }),
    makeComponent({
      kind: "capability_sequencer",
      label: "Capability sequencer",
      description:
        "Separates capability discovery, selection, sequencing, and retirement decisions.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["capability.read", "tool.route"],
      eventKinds: ["CapabilitySequence", "RoutingReceipt"],
      evidence: [
        "discovered_capabilities",
        "selected_sequence",
        "retired_capabilities",
      ],
      group: "Routing",
      icon: "waypoints",
    }),
    makeComponent({
      kind: "model_router",
      label: "Model router",
      description: "Selects a model binding under workflow-level model policy.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/model_router",
      capabilityScope: ["model.route"],
      eventKinds: [
        "ModelRouteDecision",
        "RoutingReceipt",
        "KernelEvent::RoutingReceipt",
      ],
      evidence: [
        "selected_model",
        "provider",
        "reasoning_effort",
        "privacy_posture",
        "cost_estimate",
        "fallback_model",
        "model_policy_slot",
        "candidate_models",
        "routing_reason",
      ],
      group: "Routing",
      icon: "brain",
    }),
    makeComponent({
      kind: "model_call",
      label: "Model call",
      description:
        "Invokes the selected model with deterministic request and response capture.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/model_call",
      capabilityScope: ["model.invoke"],
      eventKinds: ["ModelInvocationStarted", "ModelInvocationCompleted"],
      evidence: ["request_hash", "response_hash", "model_binding"],
      group: "Execution",
      icon: "message-square",
      timeoutMs: 120000,
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "tool_router",
      label: "Tool router",
      description:
        "Chooses native, workflow, MCP, or connector tools under grant policy.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/action_execution.rs",
      capabilityScope: ["tool.route", "capability.read"],
      eventKinds: ["RoutingReceipt", "ActionDispatchPrepared"],
      evidence: ["tool_grant_slot", "candidate_tools", "routing_reason"],
      group: "Routing",
      icon: "route",
    }),
    makeComponent({
      kind: "tool_call",
      label: "Tool call",
      description:
        "Executes a native or workflow tool through the action execution envelope.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution",
      capabilityScope: ["tool.invoke"],
      approvalRequired: true,
      eventKinds: ["AgentActionResult", "WorkloadReceipt"],
      evidence: ["action_request_id", "tool_ref", "result_hash"],
      group: "Execution",
      icon: "wrench",
      timeoutMs: 60000,
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "dry_run_simulator",
      label: "Dry-run simulator",
      description:
        "Previews side effects and policy outcomes before file, shell, connector, or commerce actions execute.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["dry_run.preview", "policy.evaluate"],
      eventKinds: ["DryRunPreview", "PolicyPreview"],
      evidence: ["side_effect_preview", "policy_preview", "preview_artifact"],
      group: "Governance",
      icon: "scan-search",
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "mcp_provider",
      label: "MCP provider",
      description:
        "Represents an MCP server as a capability provider with reviewed grants.",
      kernelRef: "crates/services/src/mcp",
      capabilityScope: ["mcp.provider.read", "mcp.catalog.read"],
      eventKinds: ["McpServerCatalogued", "CapabilityLease"],
      evidence: ["server_id", "catalog_hash", "grant_scope"],
      group: "MCP",
      icon: "server",
    }),
    makeComponent({
      kind: "mcp_tool_call",
      label: "MCP tool invocation",
      description:
        "Invokes an MCP tool as a componentized callable unit with receipts.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/dynamic_native_tool.rs",
      capabilityScope: ["mcp.tool.invoke"],
      approvalRequired: true,
      eventKinds: ["AgentActionResult", "ExecutionContractReceipt"],
      evidence: ["server_id", "tool_name", "argument_hash", "result_hash"],
      group: "MCP",
      icon: "plug",
      timeoutMs: 60000,
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "connector_call",
      label: "Connector call",
      description:
        "Calls a connector operation through policy and capability grants.",
      kernelRef: "crates/services/src/connectors",
      capabilityScope: ["connector.invoke"],
      approvalRequired: true,
      eventKinds: ["ConnectorInvocation", "WorkloadReceipt"],
      evidence: ["connector_id", "operation", "request_hash", "result_hash"],
      group: "Connectors",
      icon: "cable",
      timeoutMs: 60000,
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "policy_gate",
      label: "Policy and firewall gate",
      description:
        "Evaluates firewall policy, deterministic commitments, and capability leases.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs",
      capabilityScope: ["policy.evaluate", "capability.lease"],
      eventKinds: ["FirewallDecisionReceipt", "DeterminismCommit"],
      evidence: ["policy_hash", "decision", "lease_id", "determinism_commit"],
      group: "Governance",
      icon: "shield",
    }),
    makeComponent({
      kind: "approval_gate",
      label: "Approval gate",
      description:
        "Pauses privileged actions until approval semantics are satisfied.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/tool_execution/approval",
      capabilityScope: ["approval.request"],
      approvalRequired: true,
      approvalMode: "human_gate",
      eventKinds: ["ApprovalRequested", "ApprovalSatisfied"],
      evidence: ["approval_id", "approval_scope", "approver"],
      group: "Governance",
      icon: "badge-check",
    }),
    makeComponent({
      kind: "wallet_capability",
      label: "Wallet capability request",
      description:
        "Requests runtime capability scope before spend, connector write, or external effect.",
      kernelRef: "crates/services/src/capabilities/wallet",
      capabilityScope: ["wallet.request", "capability.grant"],
      approvalRequired: true,
      approvalMode: "wallet_capability",
      eventKinds: ["CapabilityLease", "WalletRequestReceipt"],
      evidence: ["capability_scope", "lease_id", "budget"],
      group: "Governance",
      icon: "wallet",
    }),
    makeComponent({
      kind: "memory_read",
      label: "Memory read",
      description:
        "Reads session, workflow, or worker memory through scoped state access.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/memory",
      capabilityScope: ["memory.read"],
      eventKinds: ["MemoryRead"],
      evidence: ["memory_key", "state_hash", "memory.scope", "memory.injectionEnabled"],
      group: "State",
      icon: "database",
    }),
    makeComponent({
      kind: "memory_search",
      label: "Memory search",
      description:
        "Filters governed memory by scope, key, query, limit, and redaction before model injection.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/memory",
      capabilityScope: ["memory.read", "memory.search"],
      eventKinds: ["MemoryRead", "MemorySearch"],
      evidence: ["memory_key", "memory.scope", "memory.query", "memory.limit", "memory.redaction"],
      group: "State",
      icon: "database",
    }),
    makeComponent({
      kind: "memory_list",
      label: "Memory list",
      description:
        "Lists governed memory records by declared scope and memory key for workflow state attachments.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/memory",
      capabilityScope: ["memory.read", "memory.list"],
      eventKinds: ["MemoryRead", "MemoryList"],
      evidence: ["memory_key", "memory.scope", "memory.limit", "memory.redaction"],
      group: "State",
      icon: "database",
    }),
    makeComponent({
      kind: "memory_write",
      label: "Memory write",
      description:
        "Writes, edits, or deletes memory through policy-checked reducers and receipt-backed updates.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/memory",
      capabilityScope: ["memory.write"],
      approvalRequired: true,
      eventKinds: ["MemoryWrite", "StateUpdate"],
      evidence: ["memory_key", "previous_hash", "next_hash", "memory.readOnly", "memory.writeRequiresApproval"],
      group: "State",
      icon: "database",
    }),
    makeComponent({
      kind: "memory_subagent_inheritance",
      label: "Subagent memory inheritance",
      description:
        "Projects parent memory into subagent handoffs through none, explicit, read-only, or full inheritance policy.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/handler/execution/memory",
      capabilityScope: ["memory.read", "subagent.spawn"],
      approvalRequired: true,
      eventKinds: ["SubagentMemoryInheritance"],
      evidence: [
        "memory.subagentInheritance",
        "memory.inheritedRecordIds",
        "memory.effectivePolicy",
        "memory.writeBlockReason",
      ],
      group: "State",
      icon: "database",
    }),
    makeComponent({
      kind: "verifier",
      label: "Verifier",
      description:
        "Checks component outputs, schemas, contract receipts, and completion claims.",
      kernelRef: "crates/services/src/agentic/runtime/service/verifier",
      capabilityScope: ["verification.run"],
      eventKinds: ["ExecutionContractReceipt", "VerificationReceipt"],
      evidence: ["schema_hash", "contract_key", "verification_result"],
      group: "Verification",
      icon: "check-circle",
    }),
    makeComponent({
      kind: "semantic_impact_analyzer",
      label: "Semantic impact",
      description:
        "Classifies changed symbols, APIs, schemas, policies, call sites, tests, docs, and migration implications.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["impact.analyze", "evidence.read"],
      eventKinds: ["SemanticImpactAnalysis"],
      evidence: ["changed_symbols", "affected_tests", "risk_class"],
      group: "Verification",
      icon: "git-branch-plus",
    }),
    makeComponent({
      kind: "postcondition_synthesizer",
      label: "Postcondition synthesizer",
      description:
        "Derives success criteria, required receipts, and minimum verification evidence from the objective.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["verification.plan", "evidence.read"],
      eventKinds: ["PostconditionSynthesis"],
      evidence: ["postcondition_checks", "minimum_evidence", "unknowns"],
      group: "Verification",
      icon: "list-checks",
    }),
    makeComponent({
      kind: "drift_detector",
      label: "Drift detector",
      description:
        "Detects plan, file, branch, connector, requirement, policy, model, and projection drift.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["drift.detect", "session.state.read"],
      eventKinds: ["DriftSignal"],
      evidence: ["drift_flags", "drift_evidence_refs"],
      group: "Verification",
      icon: "activity",
    }),
    makeComponent({
      kind: "quality_ledger",
      label: "Quality ledger",
      description:
        "Records strategy, tool sequence, costs, failures, stop reason, scorecards, and promotion decisions.",
      kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
      capabilityScope: ["quality.write", "scorecard.read"],
      eventKinds: ["AgentQualityLedger", "BenchmarkScorecard"],
      evidence: ["quality_ledger_id", "scorecard_metrics", "stop_condition"],
      group: "Verification",
      icon: "badge-check",
    }),
    makeComponent({
      kind: "handoff_bridge",
      label: "Handoff bridge",
      description:
        "Preserves objective, current state, blockers, evidence refs, and receiving-agent outcome across delegation.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/lifecycle/worker_results",
      capabilityScope: ["handoff.write", "delegation.merge"],
      eventKinds: ["HandoffQuality", "WorkerResultMerged"],
      evidence: [
        "objective_preserved",
        "blockers_included",
        "receiver_succeeded",
      ],
      group: "Delegation",
      icon: "split",
    }),
    makeComponent({
      kind: "gui_harness_validator",
      label: "GUI harness validator",
      description:
        "Validates retained Autopilot chat queries, screenshots, transcripts, traces, receipts, source chips, scorecards, and clean chat UX.",
      kernelRef: "scripts/run-autopilot-gui-harness-validation.mjs",
      capabilityScope: ["gui.validate", "harness.validate"],
      eventKinds: ["AutopilotGuiHarnessValidation", "CleanChatUxValidation"],
      evidence: ["screenshots", "transcripts", "trace_refs", "quality_ledger"],
      group: "Validation",
      icon: "monitor-check",
      timeoutMs: 600000,
    }),
    makeComponent({
      kind: "output_writer",
      label: "Output writer",
      description:
        "Materializes final user-visible output under output policy.",
      kernelRef: "crates/services/src/agentic/runtime/service/output",
      capabilityScope: ["output.write"],
      approvalRequired: true,
      eventKinds: ["OutputWritten", "AgentActionResult"],
      evidence: ["output_hash", "delivery_target", "output_policy_slot"],
      group: "Output",
      icon: "file-output",
    }),
    makeComponent({
      kind: "receipt_writer",
      label: "Receipt writer",
      description:
        "Emits durable receipts that link runtime events to workflow node ids.",
      kernelRef: "crates/services/src/agentic/runtime/service/receipts",
      capabilityScope: ["receipt.write"],
      eventKinds: [
        "ExecutionContractReceipt",
        "PlanReceipt",
        "WorkloadReceipt",
      ],
      evidence: ["receipt_id", "node_id", "evidence_commit_hash"],
      group: "Receipts",
      icon: "receipt",
    }),
    makeComponent({
      kind: "retry_policy",
      label: "Retry policy",
      description:
        "Classifies retryable failures and chooses bounded retry behavior.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/tool_execution/processing/retry",
      capabilityScope: ["retry.evaluate"],
      eventKinds: ["RetryScheduled", "RetryExhausted"],
      evidence: ["attempt", "max_attempts", "retry_reason"],
      group: "Recovery",
      icon: "rotate-ccw",
      maxAttempts: 3,
    }),
    makeComponent({
      kind: "repair_loop",
      label: "Repair loop",
      description:
        "Creates bounded repair attempts after verifier or tool failures.",
      kernelRef: "crates/services/src/agentic/runtime/service/repair",
      capabilityScope: ["repair.propose"],
      eventKinds: ["RepairAttemptStarted", "RepairAttemptCompleted"],
      evidence: ["failure_ref", "repair_strategy", "bounded_targets"],
      group: "Recovery",
      icon: "git-pull-request",
      maxAttempts: 2,
    }),
    makeComponent({
      kind: "merge_judge",
      label: "Merge and judge",
      description:
        "Merges branch outputs and judges competing repair or tool results.",
      kernelRef: "crates/services/src/agentic/runtime/service/judge",
      capabilityScope: ["judgement.run"],
      eventKinds: ["MergeReceipt", "JudgementReceipt"],
      evidence: ["candidate_hashes", "winner_reason", "judge_policy_hash"],
      group: "Verification",
      icon: "git-compare",
    }),
    makeComponent({
      kind: "completion_gate",
      label: "Completion gate",
      description:
        "Determines whether the turn is complete and safe to finalize.",
      kernelRef:
        "crates/services/src/agentic/runtime/service/decision_loop/completion",
      capabilityScope: ["completion.evaluate"],
      eventKinds: ["CompletionGateReceipt", "PlanReceipt"],
      evidence: ["completion_contract", "pending_actions", "final_decision"],
      group: "Completion",
      icon: "flag",
    }),
  ];

const REQUIRED_HARNESS_SLOTS: WorkflowHarnessSlotSpec[] = [
  {
    slotId: "slot.model-policy",
    kind: "model_policy",
    label: "Model policy",
    description: "Workflow-level model selection, budget, and fallback policy.",
    required: true,
    allowedComponentKinds: ["model_router", "model_call"],
    defaultComponentId: componentId("model_router"),
    validation: {
      blocksActivation: true,
      reason:
        "Activated harnesses must bind model routing to an explicit policy slot.",
    },
  },
  {
    slotId: "slot.tool-grants",
    kind: "tool_grant_policy",
    label: "Tool grant policy",
    description:
      "Workflow-level grants for native, workflow, connector, and MCP tools.",
    required: true,
    allowedComponentKinds: [
      "tool_router",
      "tool_call",
      "mcp_provider",
      "mcp_tool_call",
      "connector_call",
    ],
    defaultComponentId: componentId("tool_router"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must make tool grants inspectable.",
    },
  },
  {
    slotId: "slot.state-policy",
    kind: "state_policy",
    label: "State policy",
    description:
      "Task state, drift, memory, and projection-state access rules.",
    required: true,
    allowedComponentKinds: [
      "task_state",
      "runtime_doctor",
      "skill_registry",
      "hook_registry",
      "drift_detector",
      "memory_read",
      "memory_search",
      "memory_list",
      "memory_write",
    ],
    defaultComponentId: componentId("task_state"),
    validation: {
      blocksActivation: true,
      reason:
        "Activated harnesses must project task/world state through the shared substrate.",
    },
  },
  {
    slotId: "slot.budget-policy",
    kind: "budget_policy",
    label: "Budget policy",
    description:
      "Cognitive budget, escalation threshold, stop threshold, and retry bounds.",
    required: true,
    allowedComponentKinds: ["budget_gate", "model_router", "retry_policy"],
    defaultComponentId: componentId("budget_gate"),
    validation: {
      blocksActivation: true,
      reason:
        "Autonomous harnesses must expose their cognitive budget before activation.",
    },
  },
  {
    slotId: "slot.dry-run-policy",
    kind: "dry_run_policy",
    label: "Dry-run policy",
    description:
      "Preview rules for file, shell, connector, commerce, and policy side effects.",
    required: true,
    allowedComponentKinds: [
      "dry_run_simulator",
      "policy_gate",
      "tool_call",
      "connector_call",
    ],
    defaultComponentId: componentId("dry_run_simulator"),
    validation: {
      blocksActivation: true,
      reason: "Effectful harness paths need a dry-run or preview policy.",
    },
  },
  {
    slotId: "slot.verifier",
    kind: "verifier_policy",
    label: "Verifier policy",
    description: "Schema, receipt, and completion verification policy.",
    required: true,
    allowedComponentKinds: [
      "verifier",
      "semantic_impact_analyzer",
      "postcondition_synthesizer",
      "merge_judge",
      "completion_gate",
      "gui_harness_validator",
    ],
    defaultComponentId: componentId("verifier"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses require a verifier policy slot.",
    },
  },
  {
    slotId: "slot.approval",
    kind: "approval_policy",
    label: "Approval policy",
    description:
      "Approval gate and wallet capability semantics for privileged work.",
    required: true,
    allowedComponentKinds: [
      "approval_gate",
      "policy_gate",
      "wallet_capability",
    ],
    defaultComponentId: componentId("approval_gate"),
    validation: {
      blocksActivation: true,
      reason: "Privileged harness forks require explicit approval semantics.",
    },
  },
  {
    slotId: "slot.output-policy",
    kind: "output_policy",
    label: "Output policy",
    description:
      "Rules for output writing, materialization, and receipt emission.",
    required: true,
    allowedComponentKinds: ["output_writer", "receipt_writer"],
    defaultComponentId: componentId("output_writer"),
    validation: {
      blocksActivation: true,
      reason: "Outputs must be governed before a harness fork can activate.",
    },
  },
  {
    slotId: "slot.memory-policy",
    kind: "memory_policy",
    label: "Memory policy",
    description:
      "Memory read/write scope, injection, approval, retention, and subagent inheritance behavior.",
    required: true,
    allowedComponentKinds: ["memory_read", "memory_write", "memory_subagent_inheritance"],
    defaultComponentId: componentId("memory_read"),
    validation: {
      blocksActivation: true,
      reason: "Memory access must declare scope before activation.",
    },
  },
  {
    slotId: "slot.quality-ledger",
    kind: "quality_ledger_policy",
    label: "Quality ledger policy",
    description:
      "Scorecard, ledger writeback, stop reason, and bounded self-improvement evidence.",
    required: true,
    allowedComponentKinds: ["quality_ledger", "verifier", "completion_gate"],
    defaultComponentId: componentId("quality_ledger"),
    validation: {
      blocksActivation: true,
      reason:
        "Harness runs must emit quality ledger evidence before activation.",
    },
  },
  {
    slotId: "slot.handoff-policy",
    kind: "handoff_policy",
    label: "Handoff policy",
    description:
      "Delegation handoff, worker merge, blocker preservation, and receiver outcome quality.",
    required: true,
    allowedComponentKinds: ["handoff_bridge", "merge_judge", "receipt_writer"],
    defaultComponentId: componentId("handoff_bridge"),
    validation: {
      blocksActivation: true,
      reason:
        "Delegation-capable harnesses must preserve handoff quality evidence.",
    },
  },
  {
    slotId: "slot.retry-repair",
    kind: "retry_repair_policy",
    label: "Retry and repair policy",
    description: "Retry bounds, repair loops, and merge/judge behavior.",
    required: true,
    allowedComponentKinds: ["retry_policy", "repair_loop", "merge_judge"],
    defaultComponentId: componentId("retry_policy"),
    validation: {
      blocksActivation: true,
      reason: "Recovery behavior must be bounded before activation.",
    },
  },
];

export const DEFAULT_AGENT_HARNESS_SLOTS = REQUIRED_HARNESS_SLOTS;

const HARNESS_FLOW: WorkflowHarnessComponentKind[] = [
  "planner",
  "prompt_assembler",
  "runtime_doctor",
  "skill_registry",
  "hook_registry",
  "task_state",
  "uncertainty_gate",
  "budget_gate",
  "capability_sequencer",
  "model_router",
  "model_call",
  "tool_router",
  "dry_run_simulator",
  "policy_gate",
  "approval_gate",
  "wallet_capability",
  "mcp_provider",
  "mcp_tool_call",
  "tool_call",
  "connector_call",
  "probe_runner",
  "memory_read",
  "memory_search",
  "memory_list",
  "memory_write",
  "semantic_impact_analyzer",
  "postcondition_synthesizer",
  "verifier",
  "drift_detector",
  "retry_policy",
  "repair_loop",
  "merge_judge",
  "quality_ledger",
  "handoff_bridge",
  "gui_harness_validator",
  "completion_gate",
  "receipt_writer",
  "output_writer",
];

const SLOT_BY_KIND: Partial<
  Record<WorkflowHarnessComponentKind, WorkflowHarnessSlotKind[]>
> = {
  planner: ["state_policy"],
  prompt_assembler: ["state_policy"],
  task_state: ["state_policy"],
  runtime_doctor: ["state_policy", "verifier_policy"],
  skill_registry: ["state_policy"],
  hook_registry: ["state_policy", "verifier_policy"],
  uncertainty_gate: ["state_policy", "budget_policy"],
  probe_runner: ["verifier_policy", "budget_policy"],
  budget_gate: ["budget_policy"],
  capability_sequencer: ["tool_grant_policy"],
  model_router: ["model_policy"],
  model_call: ["model_policy"],
  tool_router: ["tool_grant_policy"],
  tool_call: ["tool_grant_policy"],
  dry_run_simulator: ["dry_run_policy"],
  mcp_provider: ["tool_grant_policy"],
  mcp_tool_call: ["tool_grant_policy"],
  connector_call: ["tool_grant_policy"],
  policy_gate: ["approval_policy"],
  approval_gate: ["approval_policy"],
  wallet_capability: ["approval_policy"],
  memory_read: ["memory_policy"],
  memory_search: ["memory_policy"],
  memory_list: ["memory_policy"],
  memory_write: ["memory_policy"],
  semantic_impact_analyzer: ["verifier_policy"],
  postcondition_synthesizer: ["verifier_policy"],
  verifier: ["verifier_policy"],
  drift_detector: ["state_policy", "verifier_policy"],
  retry_policy: ["retry_repair_policy"],
  repair_loop: ["retry_repair_policy"],
  merge_judge: ["retry_repair_policy", "verifier_policy"],
  quality_ledger: ["quality_ledger_policy"],
  handoff_bridge: ["handoff_policy"],
  gui_harness_validator: ["verifier_policy", "quality_ledger_policy"],
  output_writer: ["output_policy"],
  receipt_writer: ["output_policy"],
  completion_gate: ["verifier_policy", "quality_ledger_policy"],
};

function componentFor(
  kind: WorkflowHarnessComponentKind,
): WorkflowHarnessComponentSpec {
  const component = DEFAULT_AGENT_HARNESS_COMPONENTS.find(
    (item) => item.kind === kind,
  );
  if (!component) {
    throw new Error(`Missing harness component spec for ${kind}`);
  }
  return component;
}

function slotIdsFor(kind: WorkflowHarnessComponentKind): string[] {
  return (SLOT_BY_KIND[kind] ?? [])
    .map(
      (slotKind) =>
        REQUIRED_HARNESS_SLOTS.find((slot) => slot.kind === slotKind)?.slotId,
    )
    .filter((slotId): slotId is string => Boolean(slotId));
}

function componentCapturesPolicyDecision(
  kind: WorkflowHarnessComponentKind,
): boolean {
  return [
    "uncertainty_gate",
    "budget_gate",
    "dry_run_simulator",
    "policy_gate",
    "approval_gate",
    "wallet_capability",
    "retry_policy",
    "completion_gate",
    "handoff_bridge",
  ].includes(kind);
}

function componentIsNondeterministic(
  kind: WorkflowHarnessComponentKind,
): boolean {
  return [
    "model_call",
    "tool_call",
    "mcp_tool_call",
    "connector_call",
    "wallet_capability",
  ].includes(kind);
}

function replayEnvelopeFor(
  component: WorkflowHarnessComponentSpec,
): WorkflowHarnessReplayEnvelope {
  const nondeterministic = componentIsNondeterministic(component.kind);
  return {
    deterministicEnvelope: !nondeterministic,
    capturesInput: true,
    capturesOutput: true,
    capturesPolicyDecision: componentCapturesPolicyDecision(component.kind),
    determinism: nondeterministic ? "nondeterministic" : "deterministic",
    nondeterminismReason: nondeterministic
      ? "External model, tool, connector, or wallet boundary requires retained fixture evidence"
      : undefined,
    redactionPolicy: "runtime_redacted",
  };
}

function runtimeBindingFor(
  component: WorkflowHarnessComponentSpec,
): WorkflowHarnessNodeBinding {
  const replayEnvelope = replayEnvelopeFor(component);
  return {
    componentId: component.componentId,
    componentVersion: component.version,
    componentKind: component.kind,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    readiness: component.readiness,
    kernelRef: component.kernelRef,
    slotIds: slotIdsFor(component.kind),
    evidenceEventKinds: component.emittedEvents,
    receiptKinds: component.evidence,
    replayEnvelope,
    replay: {
      deterministicEnvelope: replayEnvelope.deterministicEnvelope,
      capturesInput: replayEnvelope.capturesInput,
      capturesOutput: replayEnvelope.capturesOutput,
      capturesPolicyDecision: replayEnvelope.capturesPolicyDecision,
    },
  };
}

function nodeTypeFor(kind: WorkflowHarnessComponentKind): WorkflowNode["type"] {
  switch (kind) {
    case "task_state":
      return "task_state";
    case "runtime_doctor":
      return "runtime_doctor";
    case "skill_registry":
      return "skill";
    case "hook_registry":
      return "hook";
    case "uncertainty_gate":
      return "uncertainty_gate";
    case "probe_runner":
      return "probe";
    case "budget_gate":
      return "budget_gate";
    case "capability_sequencer":
      return "capability_sequence";
    case "model_call":
      return "model_call";
    case "tool_call":
    case "mcp_tool_call":
      return "plugin_tool";
    case "mcp_provider":
    case "connector_call":
      return "adapter";
    case "approval_gate":
    case "wallet_capability":
      return "human_gate";
    case "memory_read":
    case "memory_search":
    case "memory_list":
    case "memory_write":
      return "state";
    case "dry_run_simulator":
      return "dry_run";
    case "semantic_impact_analyzer":
      return "semantic_impact";
    case "postcondition_synthesizer":
      return "postcondition_synthesis";
    case "drift_detector":
      return "drift_detector";
    case "quality_ledger":
      return "quality_ledger";
    case "handoff_bridge":
      return "handoff";
    case "gui_harness_validator":
      return "gui_harness_validation";
    case "tool_router":
    case "model_router":
    case "policy_gate":
    case "merge_judge":
    case "completion_gate":
      return "decision";
    case "retry_policy":
    case "repair_loop":
      return "loop";
    case "receipt_writer":
      return "output";
    default:
      return "function";
  }
}

function nodeLogicFor(
  component: WorkflowHarnessComponentSpec,
): Record<string, unknown> {
  const base = {
    harnessComponent: component,
    harnessSlots: slotIdsFor(component.kind),
    inputSchema: component.inputSchema,
    outputSchema: component.outputSchema,
    errorSchema: component.errorSchema,
  };
  switch (component.kind) {
    case "model_call":
      return {
        ...base,
        modelRef: "reasoning",
        prompt: "Default agent harness model invocation envelope.",
        validateStructuredOutput: true,
        outputSchema: component.outputSchema,
      };
    case "tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "native_tool",
          toolRef: "agent.runtime.native-tool.catalog.read",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: [
            "native.tool.catalog.read",
            "mcp.tool.catalog.read",
          ],
          sideEffectClass: "read",
          requiresApproval: false,
          arguments: {
            mode: "native_catalog_preview",
            mutation: false,
            mcpToolCatalogRef: "input.mcpToolCatalog",
          },
        },
      };
    case "mcp_tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "mcp_tool",
          toolRef: "mcp.tool.catalog.read",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["mcp.tool.catalog.read", "mcp.provider.read"],
          sideEffectClass: "read",
          requiresApproval: false,
          arguments: {
            mode: "catalog_preview",
            mutation: false,
            providerCatalogRef: "previousAuthorityOutput.providerCatalog",
          },
        },
      };
    case "mcp_provider":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "mcp.capability-provider",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "read",
          requiresApproval: false,
          operation: "catalog",
        },
      };
    case "connector_call":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "agent.connector.catalog",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["connector.catalog.read", "mcp.tool.catalog.read"],
          sideEffectClass: "read",
          requiresApproval: false,
          operation: "describe",
        },
      };
    case "policy_gate":
      return {
        ...base,
        authorityGateKind: "policy_gate",
        policyGateLiveExecution: true,
        routes: ["allow_read_only_route", "deny_mutation"],
        defaultRoute: "allow_read_only_route",
        readOnlyRouteAccepted: true,
        destructiveRouteDenied: true,
        mutatingToolCallsBlocked: true,
        sideEffectsExecuted: false,
        mutationExecuted: false,
        policyDecision: "allow_read_only_route_through_workflow_authority",
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      };
    case "approval_gate":
      return {
        ...base,
        authorityGateKind: "approval_gate",
        text: "Mutating tool authority remains blocked without explicit governed approval.",
        approvalMode: "workflow_recovery_required",
        requiresApproval: true,
        syntheticApprovalGranted: false,
        authorityTransferred: false,
        sideEffectsExecuted: false,
        mutationExecuted: false,
        policyDecision: "require_governed_approval_for_mutating_tooling",
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      };
    case "wallet_capability":
      return {
        ...base,
        text: "Wallet and spending authority remain unavailable during read-only default harness dispatch.",
        approvalMode: "wallet_capability_dry_run",
        capabilityScope: ["wallet.request", "capability.grant"],
        readOnlyAuthority: true,
        requiresApproval: true,
        policyDecision: "retain_wallet_capability_without_grant",
        syntheticApprovalGranted: false,
        capabilityDryRunLiveExecution: true,
        capabilityGranted: false,
        grantMaterialized: false,
        authorityTransferred: false,
        sideEffectsExecuted: false,
        mutationExecuted: false,
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      };
    case "memory_read":
    case "memory_search":
    case "memory_list":
    case "memory_write":
      return {
        ...base,
        stateKey: component.kind,
        stateOperation: {
          key: component.kind,
          operation:
            component.kind === "memory_read"
              ? "read"
              : component.kind === "memory_search"
                ? "memory_search"
                : component.kind === "memory_list"
                  ? "memory_list"
                  : "write",
          reducer: "merge",
        },
      };
    case "retry_policy":
    case "repair_loop":
      return {
        ...base,
        loopKind: component.kind,
        maxIterations: component.retry.maxAttempts,
      };
    case "receipt_writer":
      return {
        ...base,
        format: "receipt",
        materialization: {
          enabled: false,
          assetPath: "receipts/harness/{{run.id}}.json",
        },
        deliveryTarget: { targetKind: "none" },
      };
    default:
      return {
        ...base,
        language: "javascript",
        code: "return { status: 'success', evidence: [], receipts: [] };",
        functionBinding: {
          language: "javascript",
          code: "return { status: 'success', evidence: [], receipts: [] };",
          outputSchema: component.outputSchema,
          sandboxPolicy: {
            timeoutMs: component.timeout.timeoutMs,
            memoryMb: 64,
            outputLimitBytes: 32768,
            permissions: [],
          },
          testInput: { sessionId: "test", turnId: "test" },
        },
      };
  }
}

function makeHarnessNode(
  kind: WorkflowHarnessComponentKind,
  index: number,
): WorkflowNode {
  const component = componentFor(kind);
  const type = nodeTypeFor(kind);
  const runtimeBinding = runtimeBindingFor(component);
  return {
    id: `harness.${kind}`,
    type,
    name: component.label,
    x: 90 + (index % 5) * 260,
    y: 110 + Math.floor(index / 5) * 190,
    metricLabel: component.ui.group,
    metricValue: component.kind,
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["input"],
    outputs: ["output", "error", "retry"],
    runtimeBinding,
    config: {
      logic: nodeLogicFor(component),
      law: {
        requireHumanGate: component.approval.required,
        privilegedActions: component.approval.required
          ? component.requiredCapabilityScope
          : [],
        sandboxPolicy: {
          timeoutMs: component.timeout.timeoutMs,
          memoryMb: 64,
          outputLimitBytes: 65536,
          permissions: [],
        },
      },
    },
  };
}

function makeHarnessEdges(nodes: WorkflowNode[]): WorkflowEdge[] {
  return nodes.slice(0, -1).map((node, index) => ({
    id: `harness.edge.${node.id}.${nodes[index + 1].id}`,
    from: node.id,
    to: nodes[index + 1].id,
    fromPort: "output",
    toPort: "input",
    type: "data",
    connectionClass: "data",
    label: "deterministic envelope",
    data: {
      connectionClass: "data",
      receiptCorrelation: true,
    },
  }));
}

export function defaultHarnessPromotionClusters(): WorkflowHarnessPromotionCluster[] {
  return (
    [
      "cognition",
      "routing_model",
      "verification_output",
      "authority_tooling",
    ] as WorkflowHarnessPromotionClusterId[]
  ).map((clusterId, index) => ({
    clusterId,
    label: HARNESS_PROMOTION_CLUSTER_LABELS[clusterId],
    activationOrder: index + 1,
    componentKinds: HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId],
    requiredExecutionMode: "gated",
    minimumReadiness: "shadow_ready",
    promotionRule:
      "Requires zero blocking divergence, receipt coverage, replay fixture coverage, canary pass, and rollback target.",
    rollbackTarget: "shadow",
    blocksLiveActivation: true,
    promotionStatus: "shadow_ready",
    replayGateProof: {
      schemaVersion: "workflow.harness.promotion-cluster-replay-gate-proof.v1",
      clusterId,
      gateStatus: "not_run",
      activationGateImpact: "pending",
      totalFixtures: 0,
      passedCount: 0,
      blockedCount: 0,
      failedCount: 0,
      blockingDivergenceCount: 0,
      replayFixtureRefs: [],
      blockingReplayFixtureRefs: [],
      receiptRefs: [],
      evidenceRefs: [],
      blockers: ["replay_gate_not_run"],
    },
  }));
}

function harnessMetadata(options: {
  blessed: boolean;
  forkedFrom?: WorkflowHarnessMetadata["forkedFrom"];
  packageName?: string;
  packageManifest?: WorkflowHarnessPackageEvidenceManifest;
  activationId?: string;
  activationState: WorkflowHarnessMetadata["activationState"];
  activationRecord?: WorkflowHarnessForkActivationRecord;
  liveHandoffProof?: WorkflowHarnessLiveHandoffProof;
  runtimeSelectorDecision?: WorkflowHarnessRuntimeSelectorDecision;
  defaultRuntimeDispatchProof?: WorkflowHarnessDefaultRuntimeDispatchProof;
  workerBindingRegistryRecord?: WorkflowHarnessWorkerBindingRegistryRecord;
  workerAttachReceipt?: WorkflowHarnessWorkerAttachReceipt;
  workerAttachLifecycle?: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerSessionRecord?: WorkflowHarnessWorkerSessionRecord;
  workerLaunchEnvelopes?: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts?: WorkflowHarnessWorkerHandoffReceipt[];
  workerHandoffNodeAttemptIds?: string[];
  workerHandoffNodeAttempts?: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffReplayFixtureRefs?: string[];
  canaryExecutionBoundary?: WorkflowHarnessCanaryExecutionBoundary;
  canaryExecutionBoundaries?: WorkflowHarnessCanaryExecutionBoundary[];
  forkMutationCanary?: WorkflowHarnessForkMutationCanary;
}): WorkflowHarnessMetadata {
  return {
    schemaVersion: "workflow.harness.v1",
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessVersion: DEFAULT_AGENT_HARNESS_VERSION,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    templateName: "Default Agent Harness",
    blessed: options.blessed,
    forkable: options.blessed,
    forkedFrom: options.forkedFrom,
    packageName: options.packageName,
    packageManifest: options.packageManifest,
    activationId: options.activationId,
    activationState: options.activationState,
    activationRecord: options.activationRecord,
    liveHandoffProof: options.liveHandoffProof,
    runtimeSelectorDecision: options.runtimeSelectorDecision,
    defaultRuntimeDispatchProof: options.defaultRuntimeDispatchProof,
    workerBindingRegistryRecord: options.workerBindingRegistryRecord,
    workerAttachReceipt: options.workerAttachReceipt,
    workerAttachLifecycle: options.workerAttachLifecycle,
    workerSessionRecord: options.workerSessionRecord,
    workerLaunchEnvelopes: options.workerLaunchEnvelopes,
    workerHandoffReceipts: options.workerHandoffReceipts,
    workerHandoffNodeAttemptIds: options.workerHandoffNodeAttemptIds,
    workerHandoffNodeAttempts: options.workerHandoffNodeAttempts,
    workerHandoffReplayFixtureRefs: options.workerHandoffReplayFixtureRefs,
    canaryExecutionBoundary: options.canaryExecutionBoundary,
    canaryExecutionBoundaries: options.canaryExecutionBoundaries,
    forkMutationCanary: options.forkMutationCanary,
    validationGates: [
      "component_contracts_present",
      "required_slots_bound",
      "proposal_only_self_mutation",
      "receipts_mapped_to_nodes",
      "tests_and_replay_present",
      "activation_review_complete",
    ],
    aiMutationMode: "proposal_only",
    componentIds: DEFAULT_AGENT_HARNESS_COMPONENTS.map(
      (component) => component.componentId,
    ),
    slotIds: REQUIRED_HARNESS_SLOTS.map((slot) => slot.slotId),
    componentReadiness: Object.fromEntries(
      DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => [
        component.componentId,
        component.readiness,
      ]),
    ),
    promotionClusters: defaultHarnessPromotionClusters(),
  };
}

export function makeDefaultAgentHarnessWorkflow(
  nowMs = Date.now(),
): WorkflowProject {
  const nodes = HARNESS_FLOW.map(makeHarnessNode);
  const workerHarnessBinding: WorkflowHarnessWorkerBinding = {
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    source: "default",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    authorityBindingReady: false,
    authorityBindingBlockers: ["worker_binding_authority_not_live"],
    requiredInvariantIds: [
      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
    ],
    invariantBlockers: ["reviewed_import_activation_apply_not_live"],
  };
  const workerBindingRegistryRecord =
    makeWorkflowHarnessWorkerBindingRegistryRecord({
      workerBinding: workerHarnessBinding,
      bindingStatus: "projection",
      blockers: ["worker_binding_registry_not_live"],
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      createdAtMs: nowMs,
    });
  const workerAttachReceipt = resolveWorkflowHarnessWorkerBinding(
    workerBindingRegistryRecord,
    makeWorkflowHarnessWorkerAttachRequest(
      workerBindingRegistryRecord,
      "unbound",
    ),
  );
  const workflow: WorkflowProject = {
    version: "workflow.v1",
    metadata: {
      id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      name: "Default Agent Harness",
      slug: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      workflowKind: "agent_workflow",
      executionMode: "hybrid",
      gitLocation: `.agents/workflows/${DEFAULT_AGENT_HARNESS_WORKFLOW_ID}.workflow.json`,
      readOnly: true,
      dirty: false,
      harness: harnessMetadata({
        blessed: true,
        activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        activationState: "read_only",
        workerBindingRegistryRecord,
        workerAttachReceipt,
      }),
      workerHarnessBinding,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    },
    nodes,
    edges: makeHarnessEdges(nodes),
    global_config: normalizeGlobalConfig({
      environmentProfile: {
        target: "local",
        credentialScope: "runtime-default",
        mockBindingPolicy: "warn",
      },
      modelBindings: {
        reasoning: { modelId: "default-agent-model-policy", required: true },
        vision: { modelId: "", required: false },
        embedding: { modelId: "", required: false },
        image: { modelId: "", required: false },
      },
      policy: {
        maxBudget: 10,
        maxSteps: 80,
        timeoutMs: 180000,
      },
      contract: {
        developerBond: 0,
        adjudicationRubric:
          "Default harness projection is inspectable and read-only; forks must pass activation gates before use.",
      },
      meta: {
        name: "Default Agent Harness",
        description:
          "Read-only projection of the blessed agent runtime harness as workflow-addressable components.",
      },
      production: {
        errorWorkflowPath:
          ".agents/workflows/default-agent-harness-error.workflow.json",
        evaluationSetPath: ".agents/workflows/default-agent-harness.tests.json",
        expectedTimeSavedMinutes: 0,
        mcpAccessReviewed: true,
        requireReplayFixtures: false,
      },
    }),
  };
  const revisionBinding = workflowRevisionBindingFor(workflow, {
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    activatedRevision: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    revisionSource: "file_hash_only",
    nowMs,
  });
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: workflow.metadata.harness
        ? {
            ...workflow.metadata.harness,
            revisionBinding,
          }
        : workflow.metadata.harness,
    },
  };
}

export function defaultAgentHarnessTests(
  workflow: WorkflowProject = makeDefaultAgentHarnessWorkflow(0),
): WorkflowTestCase[] {
  const componentNodeIds = workflow.nodes.map((node) => node.id);
  return [
    {
      id: "test-default-harness-components-present",
      name: "Default harness components are projected",
      targetNodeIds: componentNodeIds.slice(0, 8),
      assertion: { kind: "node_exists" },
      status: "idle",
    },
    {
      id: "test-default-harness-governance-present",
      name: "Default harness governance components are projected",
      targetNodeIds: [
        "harness.policy_gate",
        "harness.approval_gate",
        "harness.receipt_writer",
      ],
      assertion: { kind: "node_exists" },
      status: "idle",
    },
    {
      id: "test-default-harness-recovery-present",
      name: "Default harness retry and repair components are projected",
      targetNodeIds: [
        "harness.retry_policy",
        "harness.repair_loop",
        "harness.merge_judge",
      ],
      assertion: { kind: "node_exists" },
      status: "idle",
    },
  ];
}

export function forkDefaultAgentHarnessWorkflow(
  name = "Default Agent Harness Fork",
  nowMs = Date.now(),
): {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
} {
  const base = makeDefaultAgentHarnessWorkflow(nowMs);
  const slug = slugify(name);
  const activationGateProposalId = `proposal-${slug}-activation-gates`;
  const forkWorkerHarnessBinding: WorkflowHarnessWorkerBinding = {
    harnessWorkflowId: slug,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    source: "fork",
    rollbackTarget: DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET,
    authorityBindingReady: false,
    authorityBindingBlockers: ["fork_activation_not_live_default"],
  };
  const forkWorkerBindingRegistryRecord =
    makeWorkflowHarnessWorkerBindingRegistryRecord({
      workflowId: slug,
      activationId: `activation:${slug}:blocked`,
      workerBinding: {
        ...forkWorkerHarnessBinding,
        harnessActivationId: `activation:${slug}:blocked`,
      },
      bindingStatus: "blocked",
      blockers: ["fork_activation_not_live_default"],
      rollbackTarget: DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET,
      createdAtMs: nowMs,
    });
  const forkWorkerAttachReceipt = resolveWorkflowHarnessWorkerBinding(
    forkWorkerBindingRegistryRecord,
    makeWorkflowHarnessWorkerAttachRequest(
      forkWorkerBindingRegistryRecord,
      "blocked",
    ),
  );
  const blockedActivationRecord = makeHarnessForkActivationRecord({
    workflowId: slug,
    harnessWorkflowId: slug,
    activationState: "blocked",
    evidenceRefs: [activationGateProposalId],
    workerBinding: forkWorkerHarnessBinding,
    workerBindingRegistryRecord: forkWorkerBindingRegistryRecord,
    workerAttachReceipt: forkWorkerAttachReceipt,
    mintedAtMs: nowMs,
  });
  const workflow: WorkflowProject = {
    ...base,
    metadata: {
      ...base.metadata,
      id: slug,
      name,
      slug,
      gitLocation: `.agents/workflows/${slug}.workflow.json`,
      readOnly: false,
      dirty: true,
      harness: harnessMetadata({
        blessed: false,
        forkedFrom: {
          harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
          harnessVersion: DEFAULT_AGENT_HARNESS_VERSION,
          harnessHash: DEFAULT_AGENT_HARNESS_HASH,
        },
        packageName: slug,
        activationState: "blocked",
        activationRecord: blockedActivationRecord,
        workerBindingRegistryRecord: forkWorkerBindingRegistryRecord,
        workerAttachReceipt: forkWorkerAttachReceipt,
      }),
      workerHarnessBinding: forkWorkerHarnessBinding,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    },
    global_config: normalizeGlobalConfig({
      ...base.global_config,
      environmentProfile: {
        target: "sandbox",
        credentialScope: "harness-fork",
        mockBindingPolicy: "block",
      },
      policy: {
        ...(base.global_config.policy ?? {
          maxBudget: 10,
          maxSteps: 80,
          timeoutMs: 180000,
        }),
        maxSteps: Number(DEFAULT_AGENT_HARNESS_FORK_MUTATION_AFTER_VALUE),
      },
      meta: {
        name,
        description:
          "Editable fork of the Default Agent Harness. Activation remains blocked until validation gates pass.",
      },
      production: {
        ...(base.global_config.production ?? {}),
        mcpAccessReviewed: false,
        requireReplayFixtures: true,
      },
    }),
  };
  const forkMutationCanary = makeWorkflowHarnessForkMutationCanary(workflow, {
    proposalId: activationGateProposalId,
    beforeValue: DEFAULT_AGENT_HARNESS_FORK_MUTATION_BEFORE_VALUE,
    afterValue: workflow.global_config.policy.maxSteps,
    nowMs,
  });
  const workflowWithMutationCanary: WorkflowProject = {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: workflow.metadata.harness
        ? {
            ...workflow.metadata.harness,
            forkMutationCanary,
            activationRecord: workflow.metadata.harness.activationRecord
              ? {
                  ...workflow.metadata.harness.activationRecord,
                  forkMutationCanary,
                  evidenceRefs: uniqueStrings([
                    ...workflow.metadata.harness.activationRecord.evidenceRefs,
                    ...workflowHarnessForkMutationCanaryRefs(
                      forkMutationCanary,
                    ),
                  ]),
                }
              : workflow.metadata.harness.activationRecord,
          }
        : workflow.metadata.harness,
    },
  };
  const revisionBinding = workflowRevisionBindingFor(workflowWithMutationCanary, {
    proposalId: activationGateProposalId,
    rollbackActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackRevision: base.metadata.harness?.revisionBinding?.activatedRevision,
    nowMs,
  });
  const workflowWithRevisionBinding: WorkflowProject = {
    ...workflowWithMutationCanary,
    metadata: {
      ...workflowWithMutationCanary.metadata,
      harness: workflowWithMutationCanary.metadata.harness
        ? {
            ...workflowWithMutationCanary.metadata.harness,
            revisionBinding,
            activationRecord: workflowWithMutationCanary.metadata.harness
              .activationRecord
              ? {
                  ...workflowWithMutationCanary.metadata.harness
                    .activationRecord,
                  revisionBinding,
                  rollbackRevisionBinding:
                    base.metadata.harness?.revisionBinding,
                }
              : workflowWithMutationCanary.metadata.harness.activationRecord,
          }
        : workflowWithMutationCanary.metadata.harness,
    },
  };
  const workflowWithPackageManifest = withWorkflowHarnessPackageManifest(
    workflowWithRevisionBinding,
    nowMs,
  );
  return {
    workflow: workflowWithPackageManifest,
    tests: defaultAgentHarnessTests(workflowWithPackageManifest),
    proposals: [
      {
        id: activationGateProposalId,
        title: "Review harness fork activation gates",
        summary:
          "Forked harness packages stay inactive until component slots, MCP access, replay evidence, proposal-only mutation canaries, and activation gates are validated.",
        status: "open",
        createdAtMs: nowMs,
        boundedTargets: [
          "workflow-metadata",
          "workflow-config",
          "harness.slot.model-policy",
          "harness.slot.tool-grants",
          "harness.slot.approval",
          "harness.slot.output-policy",
          DEFAULT_AGENT_HARNESS_FORK_MUTATION_TARGET_PATH,
        ],
        configDiff: {
          changedGlobalKeys: ["environmentProfile", "policy", "production"],
          changedMetadataKeys: ["harness", "workerHarnessBinding"],
        },
        sidecarDiff: {
          testsChanged: true,
          fixturesChanged: true,
          bindingsChanged: true,
          proposalsChanged: true,
          changedRoles: [
            "tests",
            "fixtures",
            "bindings",
            "activation",
            "mutation",
          ],
        },
      },
    ],
  };
}

export function workflowIsHarness(workflow: WorkflowProject): boolean {
  return Boolean(workflow.metadata.harness);
}

export function workflowIsBlessedHarness(workflow: WorkflowProject): boolean {
  return workflow.metadata.harness?.blessed === true;
}

export function workflowIsHarnessFork(workflow: WorkflowProject): boolean {
  return (
    workflowIsHarness(workflow) && workflow.metadata.harness?.blessed !== true
  );
}

export function harnessComponentForNode(
  node: Node,
): WorkflowHarnessComponentSpec | null {
  const logic = node.config?.logic ?? {};
  const value = (logic as Record<string, unknown>).harnessComponent;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const component = value as WorkflowHarnessComponentSpec;
  if (!component.componentId || !component.kind) return null;
  return component;
}

export function harnessSlotsForWorkflow(
  workflow: WorkflowProject,
): WorkflowHarnessSlotSpec[] {
  if (!workflowIsHarness(workflow)) return [];
  return REQUIRED_HARNESS_SLOTS;
}

export function workflowHarnessWorkerBinding(
  workflow: WorkflowProject,
): WorkflowHarnessWorkerBinding {
  if (workflow.metadata.workerHarnessBinding)
    return workflow.metadata.workerHarnessBinding;
  const harness = workflow.metadata.harness;
  if (harness) {
    return {
      harnessWorkflowId: workflow.metadata.id,
      harnessActivationId: harness.activationId,
      harnessHash: harness.harnessHash,
      executionMode: harness.executionMode,
      source: harness.blessed ? "default" : "fork",
      rollbackTarget: harness.activationId,
      authorityBindingReady: false,
      authorityBindingBlockers: [
        harness.blessed
          ? "worker_binding_authority_not_live"
          : "fork_activation_not_live_default",
      ],
      requiredInvariantIds: [
        DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
      ],
      invariantBlockers: ["reviewed_import_activation_apply_not_live"],
    };
  }
  return {
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    source: "recovery",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    authorityBindingReady: false,
    authorityBindingBlockers: ["workflow_recovery_fail_closed"],
    requiredInvariantIds: [
      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
    ],
    invariantBlockers: ["workflow_recovery_fail_closed"],
  };
}

export function harnessNodeEvidenceSummary(
  node: Node,
): Array<{ label: string; value: string }> {
  const component = harnessComponentForNode(node);
  if (!component) return [];
  return [
    { label: "Component", value: component.componentId },
    { label: "Version", value: component.version },
    { label: "Readiness", value: component.readiness },
    { label: "Kernel", value: component.kernelRef },
    {
      label: "Capability",
      value: component.requiredCapabilityScope.join(", ") || "none",
    },
    {
      label: "Approval",
      value: component.approval.required ? component.approval.mode : "none",
    },
    { label: "Events", value: component.emittedEvents.join(", ") },
    { label: "Evidence", value: component.evidence.join(", ") },
  ];
}
