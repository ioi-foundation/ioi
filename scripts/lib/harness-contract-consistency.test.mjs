import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function rustImplBlock(source, implName) {
  const start = source.indexOf(`impl ${implName}`);
  assert.notEqual(start, -1, `missing Rust impl ${implName}`);
  const nextEnum = source.indexOf("\n#[derive", start + 1);
  return source.slice(start, nextEnum > start ? nextEnum : undefined);
}

function rustAsStrValues(source, implName) {
  const implBlock = rustImplBlock(source, implName);
  const matchBlock = implBlock.match(
    /pub fn as_str[\s\S]*?match self \{([\s\S]*?)\n\s+\}/,
  );
  assert.ok(matchBlock, `missing ${implName}::as_str match block`);
  return [...matchBlock[1].matchAll(/Self::[A-Za-z0-9]+ => "([^"]+)"/g)]
    .map((match) => match[1])
    .sort();
}

function tsUnionValues(source, typeName) {
  const match = source.match(
    new RegExp(`export type ${typeName} =[\\s\\S]*?;`),
  );
  assert.ok(match, `missing TS type ${typeName}`);
  return [...match[0].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]).sort();
}

test("TS harness component and mode unions match Rust canonical contract", () => {
  const rust = read("crates/types/src/app/harness.rs");
  const graph = read("packages/agent-ide/src/types/graph.ts");

  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessComponentKind"),
    rustAsStrValues(rust, "HarnessComponentKind"),
  );
  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessExecutionMode"),
    rustAsStrValues(rust, "HarnessExecutionMode"),
  );
  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessComponentReadiness"),
    rustAsStrValues(rust, "HarnessComponentReadiness"),
  );
  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessPromotionClusterId"),
    rustAsStrValues(rust, "HarnessPromotionClusterId"),
  );
  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessClusterPromotionStatus"),
    rustAsStrValues(rust, "HarnessClusterPromotionStatus"),
  );
  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessLiveHandoffSelector"),
    rustAsStrValues(rust, "HarnessLiveHandoffSelector"),
  );
  assert.deepEqual(
    tsUnionValues(graph, "WorkflowHarnessWorkerSessionStatus"),
    rustAsStrValues(rust, "HarnessWorkerSessionStatus"),
  );
});

test("TS harness projection carries canonical mode, readiness, replay, clusters, and prompt assembler", () => {
  const workflow = read("packages/agent-ide/src/runtime/harness-workflow.ts");
  assert.match(workflow, /DEFAULT_HARNESS_EXECUTION_MODE[\s\S]*projection/);
  assert.match(
    workflow,
    /DEFAULT_HARNESS_COMPONENT_READINESS[\s\S]*projection_only/,
  );
  assert.match(
    workflow,
    /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*cognition[\s\S]*prompt_assembler/,
  );
  assert.match(
    workflow,
    /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*routing_model[\s\S]*model_router[\s\S]*tool_router/,
  );
  assert.match(
    workflow,
    /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*verification_output[\s\S]*postcondition_synthesizer[\s\S]*output_writer/,
  );
  assert.match(
    workflow,
    /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*authority_tooling[\s\S]*policy_gate[\s\S]*wallet_capability/,
  );
  assert.match(
    workflow,
    /defaultHarnessPromotionClusters[\s\S]*requiredExecutionMode: "gated"/,
  );
  assert.match(workflow, /kind: "prompt_assembler"/);
  assert.match(
    workflow,
    /replayEnvelopeFor[\s\S]*redactionPolicy: "runtime_redacted"/,
  );
  assert.match(workflow, /executionMode: DEFAULT_HARNESS_EXECUTION_MODE/);
  assert.match(workflow, /readiness: component\.readiness/);
});

test("TS harness fork activation contract records blocked and canary-validated paths", () => {
  const graph = read("packages/agent-ide/src/types/graph.ts");
  const workflow = read("packages/agent-ide/src/runtime/harness-workflow.ts");
  const validation = read(
    "packages/agent-ide/src/runtime/workflow-validation.ts",
  );
  const guiValidation = read(
    "scripts/run-autopilot-gui-harness-validation.mjs",
  );
  const rust = read("crates/types/src/app/harness.rs");
  const serviceHarness = read("crates/services/src/agentic/runtime/harness.rs");

  assert.match(graph, /WorkflowHarnessForkActivationRecord/);
  assert.match(
    graph,
    /WorkflowHarnessActionFrame[\s\S]*workflowId[\s\S]*nodeId[\s\S]*componentKind[\s\S]*slotIds/,
  );
  assert.match(
    graph,
    /WorkflowHarnessComponentInvocation[\s\S]*invocationId[\s\S]*componentKind[\s\S]*executionMode[\s\S]*receiptIds/,
  );
  assert.match(
    graph,
    /WorkflowHarnessComponentAdapterResult[\s\S]*actionFrame[\s\S]*nodeAttempt[\s\S]*resultHash[\s\S]*replay/,
  );
  assert.match(
    graph,
    /WorkflowRevisionBinding[\s\S]*workflowPath[\s\S]*workflowContentHash[\s\S]*rollbackRevision/,
  );
  assert.match(
    graph,
    /WorkflowRevisionRestoreRequest[\s\S]*revisionBinding: WorkflowRevisionBinding[\s\S]*expectedWorkflowContentHash[\s\S]*dryRun\?: boolean/,
  );
  assert.match(
    graph,
    /WorkflowRevisionRestoreResult[\s\S]*dryRun\?: boolean[\s\S]*git_show_file_restore[\s\S]*bundle\?: WorkflowWorkbenchBundle/,
  );
  assert.match(
    graph,
    /WorkflowRevisionRestoreResult[\s\S]*receiptBindingRef\?: string/,
  );
  assert.match(
    graph,
    /WorkflowHarnessRollbackRestoreCanaryStatus[\s\S]*not_required/,
  );
  assert.match(
    graph,
    /WorkflowHarnessRollbackRestoreCanary[\s\S]*status[\s\S]*restoreStrategy[\s\S]*file_hash_only_metadata_restore[\s\S]*expectedWorkflowContentHash[\s\S]*actualWorkflowContentHash[\s\S]*hashVerified[\s\S]*blockers/,
  );
  assert.match(
    graph,
    /WorkflowHarnessRollbackRestoreCanary[\s\S]*receiptBindingRef\?: string[\s\S]*evidenceRefs/,
  );
  assert.match(
    graph,
    /WorkflowHarnessActivationAuditEvent[\s\S]*evidenceRefs: string\[\][\s\S]*receiptRefs: string\[\]/,
  );
  assert.match(
    graph,
    /WorkflowHarnessActivationRollbackProof[\s\S]*evidenceRefs: string\[\][\s\S]*receiptRefs: string\[\]/,
  );
  assert.match(
    graph,
    /WorkflowHarnessActivationRollbackExecution[\s\S]*restoreStrategy[\s\S]*git_show_file_restore[\s\S]*restoreRepoRoot[\s\S]*restoreRelativeWorkflowPath[\s\S]*restoredRevision[\s\S]*restoredFileSha256[\s\S]*restoreBlockers[\s\S]*hashVerified[\s\S]*executionStatus[\s\S]*evidenceRefs: string\[\][\s\S]*receiptRefs: string\[\][\s\S]*restoreReceiptBindingRef\?: string/,
  );
  assert.match(
    graph,
    /WorkflowHarnessForkActivationCandidate[\s\S]*dryRunOnly: true[\s\S]*rollbackRestoreCanary: WorkflowHarnessRollbackRestoreCanary[\s\S]*revisionBindingPreview: WorkflowRevisionBinding/,
  );
  assert.match(
    graph,
    /WorkflowHarnessActivationCandidateGateResult[\s\S]*gateId[\s\S]*evidenceRefs/,
  );
  assert.match(graph, /WorkflowHarnessLiveHandoffProof/);
  assert.match(graph, /WorkflowHarnessRuntimeSelectorDecision/);
  assert.match(
    graph,
    /WorkflowHarnessWorkerBinding[\s\S]*selectorDecisionId\?: string[\s\S]*defaultDispatchId\?: string[\s\S]*authorityBindingReady\?: boolean[\s\S]*livePromotionReadinessProofId\?: string/,
  );
  assert.match(graph, /WorkflowHarnessWorkerBindingRegistryRecord/);
  assert.match(
    graph,
    /WorkflowHarnessWorkerBindingRegistryRecord[\s\S]*registryRecordId: string[\s\S]*activationHash: string[\s\S]*bindingStatus: WorkflowHarnessWorkerBindingStatus[\s\S]*workerBinding: WorkflowHarnessWorkerBinding/,
  );
  assert.match(graph, /WorkflowHarnessWorkerAttachRequest/);
  assert.match(graph, /WorkflowHarnessWorkerAttachReceipt/);
  assert.match(
    graph,
    /WorkflowHarnessWorkerAttachReceipt[\s\S]*receiptId: string[\s\S]*registryRecordId: string[\s\S]*attachStatus: WorkflowHarnessWorkerAttachStatus[\s\S]*accepted: boolean[\s\S]*workerBinding: WorkflowHarnessWorkerBinding/,
  );
  assert.match(
    graph,
    /WorkflowHarnessLiveHandoffProof[\s\S]*livePromotionReadinessProof\?: WorkflowHarnessLivePromotionReadinessProof \| null[\s\S]*livePromotionReadinessReady: boolean[\s\S]*livePromotionReadinessBlockers: string\[\]/,
  );
  assert.match(
    graph,
    /WorkflowHarnessRuntimeSelectorDecision[\s\S]*livePromotionReadinessProof\?: WorkflowHarnessLivePromotionReadinessProof \| null[\s\S]*livePromotionReadinessReady: boolean[\s\S]*livePromotionReadinessBlockers: string\[\]/,
  );
  assert.match(graph, /WorkflowHarnessLivePromotionReadinessProof/);
  assert.match(
    graph,
    /WorkflowHarnessLivePromotionReadinessProof[\s\S]*requiredClusterIds[\s\S]*clusterReadiness[\s\S]*defaultLiveActivationReady[\s\S]*invalidForkLiveActivationBlocked/,
  );
  assert.match(graph, /WorkflowHarnessDefaultRuntimeDispatchProof/);
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*cognitionExecutionAdapterMode[\s\S]*cognitionExecutionAdapterResults[\s\S]*WorkflowHarnessComponentAdapterResult/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*cognitionExecutionGateAdapterMode[\s\S]*cognitionExecutionGateAdapterResults[\s\S]*WorkflowHarnessDivergenceClass/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*routingModelAdapterMode[\s\S]*routingModelAdapterResults[\s\S]*routingModelDivergenceClasses[\s\S]*WorkflowHarnessDivergenceClass/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*verificationOutputAdapterMode[\s\S]*verificationOutputAdapterResults[\s\S]*verificationOutputDivergenceClasses[\s\S]*WorkflowHarnessDivergenceClass/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*authorityToolingAdapterMode[\s\S]*authorityToolingAdapterResults[\s\S]*authorityToolingDivergenceClasses[\s\S]*WorkflowHarnessDivergenceClass/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*livePromotionReadinessProof: WorkflowHarnessLivePromotionReadinessProof/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*workerBindingRegistryRecord: WorkflowHarnessWorkerBindingRegistryRecord/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*workerAttachReceipt: WorkflowHarnessWorkerAttachReceipt/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*workerAttachLifecycle: WorkflowHarnessWorkerAttachLifecycleEvent\[\]/,
  );
  assert.match(graph, /WorkflowHarnessWorkerAttachLifecycleEvent/);
  assert.match(graph, /WorkflowHarnessWorkerSessionRecord/);
  assert.match(
    graph,
    /WorkflowHarnessWorkerSessionRecord[\s\S]*sessionRecordId: string[\s\S]*sessionId: string[\s\S]*workerId: string[\s\S]*currentStatus: WorkflowHarnessWorkerSessionStatus[\s\S]*rollbackTargetReady: boolean[\s\S]*accepted: boolean/,
  );
  assert.match(
    graph,
    /WorkflowHarnessDefaultRuntimeDispatchProof[\s\S]*workerSessionRecord: WorkflowHarnessWorkerSessionRecord/,
  );
  assert.match(graph, /WorkflowHarnessCanaryExecutionBoundary/);
  assert.match(
    graph,
    /defaultRuntimeDispatchProof\?: WorkflowHarnessDefaultRuntimeDispatchProof/,
  );
  assert.match(
    graph,
    /canaryExecutionBoundaries\?: WorkflowHarnessCanaryExecutionBoundary\[\]/,
  );
  assert.match(
    workflow,
    /workflowHarnessActivationIdGateClickProofBlockers[\s\S]*activation_id_gate_click_proof_missing[\s\S]*activation_id_gate_mint_worker_binding_mismatch/,
  );
  assert.match(
    workflow,
    /makeHarnessForkActivationRecord[\s\S]*activationState: "blocked"/,
  );
  assert.match(workflow, /harnessForkActivationId[\s\S]*validated-canary/);
  assert.match(
    workflow,
    /makeBlessedHarnessLiveHandoffProof[\s\S]*blessed_workflow_live_canary/,
  );
  assert.match(
    workflow,
    /makeHarnessRuntimeSelectorDecision[\s\S]*legacy_runtime[\s\S]*blessed_workflow_live_canary/,
  );
  assert.match(
    workflow,
    /workflowHarnessLivePromotionReadinessProofBlockers[\s\S]*live_promotion_readiness_proof_missing[\s\S]*live_promotion_readiness_invalid_fork_not_blocked[\s\S]*live_promotion_readiness_cluster_divergence_not_ready/,
  );
  assert.match(
    workflow,
    /workflowHarnessWorkerBinding[\s\S]*authorityBindingReady: false[\s\S]*authorityBindingBlockers/,
  );
  [
    /makeHarnessDefaultRuntimeDispatchProof/,
    /read_only_cognition_routing_verification_completion_authority_tooling/,
    /cognitionExecutionAdapterMode: "workflow_component_adapter_live"/,
    /cognitionExecutionAdapterResults/,
    /cognitionExecutionGateAdapterMode: "workflow_component_adapter_gated"/,
    /cognitionExecutionGateAdapterResults/,
    /routingModelAdapterMode: "workflow_component_adapter_gated"/,
    /routingModelAdapterResults/,
    /routingModelComponentKinds/,
    /verificationOutputAdapterMode: "workflow_component_adapter_gated"/,
    /verificationOutputAdapterResults/,
    /verificationOutputComponentKinds/,
    /authorityToolingAdapterMode: "workflow_component_adapter_gated"/,
    /authorityToolingAdapterResults/,
    /authorityToolingComponentKinds/,
    /cognitionExecutionMode: "workflow_synchronous_envelope"/,
    /promptAssemblyMode: "workflow_synchronous_envelope"/,
    /modelExecutionMode: "workflow_synchronous_envelope"/,
    /modelExecutionProviderInvocationMode: "workflow_provider_canary"/,
    /modelProviderCanaryMode: "workflow_provider_canary"/,
    /modelProviderGatedVisibleOutputMode:[\s\S]*"workflow_provider_gated_visible_output"/,
    /selectedVisibleOutputAuthority: "workflow_model_provider_call"/,
    /outputWriterDeferred: false/,
    /outputWriterStatus: "visible_write_committed"/,
    /outputWriterMaterializationMode: "workflow_visible_transcript_write"/,
    /outputWriterStagedWriteMode: "isolated_checkpoint_blob"/,
    /outputWriterVisibleWriteMode: "workflow_visible_transcript_write"/,
    /authorityToolingMode: "workflow_live_dry_run"/,
    /legacyOutputAuthorityRetained: false/,
  ].forEach((pattern) => assert.match(workflow, pattern));
  [
    /DEFAULT_VERIFICATION_OUTPUT_GATE_ADAPTER_COMPONENTS/,
    /postcondition_synthesizer/,
    /completion_gate/,
    /output_writer/,
    /DEFAULT_AUTHORITY_TOOLING_GATE_ADAPTER_COMPONENTS/,
    /policy_gate/,
    /dry_run_simulator/,
    /wallet_capability/,
    /verificationOutputProof:/,
    /workflow\.harness\.verification-output-envelope\.v1/,
    /componentKinds: verificationOutputComponentKinds/,
    /accept_workflow_verification_output_adapter_envelope/,
    /authorityToolingAdapterProof:/,
    /workflow\.harness\.authority-tooling-adapter-envelope\.v1/,
    /componentKinds: authorityToolingComponentKinds/,
    /accept_workflow_authority_tooling_adapter_envelope/,
    /makeHarnessLivePromotionReadinessProof/,
    /workflow\.harness\.live-promotion-readiness\.v1/,
    /invalidForkLiveActivationBlocked/,
    /allow_default_harness_live_promotion_readiness/,
    /livePromotionReadinessProof/,
    /clusterId: "cognition"/,
    /clusterId: "routing_model"/,
    /clusterId: "verification_output"/,
    /clusterId: "authority_tooling"/,
    /authorityToolingGateLiveAttemptIds:/,
    /authority_tooling_policy_gate/,
    /authority_tooling_destructive_denial/,
    /authority_tooling_approval_gate/,
    /authority_tooling_mcp_provider_read_only/,
    /authority_tooling_mcp_tool_call_read_only/,
    /authority_tooling_tool_call_read_only/,
    /authority_tooling_connector_call_read_only/,
    /authority_tooling_wallet_capability_read_only/,
    /authorityToolingGateLiveReady: true/,
    /authorityToolingPolicyGateLiveReady: true/,
    /authorityToolingDestructiveDenialLiveReady: true/,
    /authorityToolingApprovalGateLiveReady: true/,
    /authorityToolingReadOnlyAuthorityCanaryReady: true/,
    /authorityToolingProviderCatalogLiveReady: true/,
    /authorityToolingMcpToolCatalogLiveReady: true/,
    /authorityToolingNativeToolCatalogLiveReady: true/,
    /authorityToolingConnectorCatalogLiveReady: true/,
    /authorityToolingWalletCapabilityLiveDryRunReady: true/,
    /mutationDeferredComponentKinds/,
    /authorityToolingMutationDeferredComponentKinds/,
    /readOnlyCapabilityRoutingMode: "workflow_read_only_capability_routing"/,
    /readOnlyCapabilityRoutingScenario: "retained_repo_grounded_answer"/,
    /readOnlyCapabilityRoutingWorkflowOwnedNodeKinds:/,
    /"memory_read"/,
    /"capability_sequencer"/,
    /"tool_router"/,
    /"dry_run_simulator"/,
    /sideEffectsExecuted: false/,
    /mutationExecuted: false/,
    /modelProviderGatedVisibleOutputRollbackDrillReady: true/,
    /modelProviderGatedVisibleOutputRollbackDrillDivergenceClass:\s*"provider_output_hash_divergence"/,
    /modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority:\s*"legacy_runtime_model_invocation"/,
    /modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted: true/,
    /makeHarnessCanaryExecutionBoundary/,
    /workflow_node_executor/,
    /rollbackDrill/,
    /makeHarnessCanaryExecutionBoundaries/,
  ].forEach((pattern) => assert.match(workflow, pattern));
  assert.match(workflow, /DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET/);
  [
    /stableContentHash/,
    /workflowSourceProjection/,
    /workflowRevisionBindingFor/,
    /executeWorkflowHarnessRevisionRollback/,
    /rollback_execution_restored_verified_workflow_revision/,
    /rollback_executed/,
    /activationRollbackExecution/,
    /activationCandidateReceiptRefs/,
    /recordWorkflowHarnessActivationDryRun/,
    /workflowRollbackReceiptRefs/,
    /executeWorkflowHarnessRollbackDrill/,
    /restoreResult\?\.receiptBindingRef/,
    /restoreReceiptBindingRef/,
  ].forEach((pattern) => assert.match(workflow, pattern));
  [/activationRecordValidated/, /canaryStatus === "passed"/].forEach(
    (pattern) => assert.match(validation, pattern),
  );
  [
    /workerBindingAuthorityReady/,
    /workerBindingRegistryBound/,
    /workerBindingRegistryRecord/,
    /workerAttachAccepted/,
    /workerAttachReceipt/,
    /workerAttachLifecycleComplete/,
    /workerAttachLifecycleStatuses/,
    /workerAttachLifecycleAttemptIds/,
    /workerSessionRecordBound/,
    /workerSessionRecord/,
    /workerSessionStatus/,
    /livePromotionReadinessProofIdsMatch/,
    /invalidForkLiveActivationBlocked/,
    /activeWorkerBinding:/,
    /workerBinding\?\.selectorDecisionId === selector\?\.decisionId/,
    /workerBinding\?\.livePromotionReadinessProofId/,
  ].forEach((pattern) => assert.match(guiValidation, pattern));
  [
    /workerBinding\?\.harnessActivationId === harness\?\.activationId/,
    /createWorkflowHarnessActivationCandidate/,
    /activationIdPreview/,
    /decision/,
    /mintable/,
    /workerBindingPreview/,
    /revisionBindingPreview/,
    /rollbackRestoreCanary/,
    /receiptBindingRef/,
    /workflow_restore_canary:/,
    /evidenceRefs/,
    /rollback_restore_canary_not_run/,
    /rollback_restore_canary_not_restored/,
    /rollback_restore_canary_bundle_missing/,
    /rollback_restore_canary_hash_mismatch/,
    /gateId: "slots"/,
    /gateId: "tests"/,
    /gateId: "replay-fixtures"/,
    /gateId: "policy-posture"/,
    /gateId: "receipt-coverage"/,
    /gateId: "canary"/,
    /gateId: "rollback-restore"/,
    /gateId: "rollback"/,
    /gateId: "worker-binding"/,
    /gateId: "activation-id"/,
  ].forEach((pattern) => assert.match(validation, pattern));
  assert.match(
    rust,
    /pub struct HarnessComponentInvocation[\s\S]*pub component_kind: HarnessComponentKind[\s\S]*pub execution_mode: HarnessExecutionMode[\s\S]*pub receipt_ids: Vec<String>/,
  );
  assert.match(
    rust,
    /pub struct HarnessComponentAdapterResult[\s\S]*pub action_frame: HarnessActionFrame[\s\S]*pub node_attempt: HarnessNodeAttemptRecord/,
  );
  assert.match(
    rust,
    /default_harness_action_frame_for_component[\s\S]*execution_mode/,
  );
  assert.match(
    serviceHarness,
    /readiness_allows_mode[\s\S]*invoke_default_harness_component[\s\S]*HarnessComponentAdapterResult[\s\S]*harness_component_not_ready_for_mode/,
  );
});
