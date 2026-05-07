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
  const matchBlock = implBlock.match(/pub fn as_str[\s\S]*?match self \{([\s\S]*?)\n\s+\}/);
  assert.ok(matchBlock, `missing ${implName}::as_str match block`);
  return [...matchBlock[1].matchAll(/Self::[A-Za-z0-9]+ => "([^"]+)"/g)]
    .map((match) => match[1])
    .sort();
}

function tsUnionValues(source, typeName) {
  const match = source.match(new RegExp(`export type ${typeName} =[\\s\\S]*?;`));
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
});

test("TS harness projection carries canonical mode, readiness, replay, clusters, and prompt assembler", () => {
  const workflow = read("packages/agent-ide/src/runtime/harness-workflow.ts");
  assert.match(workflow, /DEFAULT_HARNESS_EXECUTION_MODE[\s\S]*projection/);
  assert.match(workflow, /DEFAULT_HARNESS_COMPONENT_READINESS[\s\S]*projection_only/);
  assert.match(workflow, /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*cognition[\s\S]*prompt_assembler/);
  assert.match(workflow, /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*routing_model[\s\S]*model_router[\s\S]*tool_router/);
  assert.match(workflow, /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*verification_output[\s\S]*postcondition_synthesizer[\s\S]*output_writer/);
  assert.match(workflow, /HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*authority_tooling[\s\S]*policy_gate[\s\S]*wallet_capability/);
  assert.match(workflow, /defaultHarnessPromotionClusters[\s\S]*requiredExecutionMode: "gated"/);
  assert.match(workflow, /kind: "prompt_assembler"/);
  assert.match(workflow, /replayEnvelopeFor[\s\S]*redactionPolicy: "runtime_redacted"/);
  assert.match(workflow, /executionMode: DEFAULT_HARNESS_EXECUTION_MODE/);
  assert.match(workflow, /readiness: component\.readiness/);
});

test("TS harness fork activation contract records blocked and canary-validated paths", () => {
  const graph = read("packages/agent-ide/src/types/graph.ts");
  const workflow = read("packages/agent-ide/src/runtime/harness-workflow.ts");
  const validation = read("packages/agent-ide/src/runtime/workflow-validation.ts");
  const rust = read("crates/types/src/app/harness.rs");
  const serviceHarness = read("crates/services/src/agentic/runtime/harness.rs");

  assert.match(graph, /WorkflowHarnessForkActivationRecord/);
  assert.match(graph, /WorkflowHarnessActionFrame[\s\S]*workflowId[\s\S]*nodeId[\s\S]*componentKind[\s\S]*slotIds/);
  assert.match(graph, /WorkflowHarnessComponentInvocation[\s\S]*invocationId[\s\S]*componentKind[\s\S]*executionMode[\s\S]*receiptIds/);
  assert.match(graph, /WorkflowHarnessComponentAdapterResult[\s\S]*actionFrame[\s\S]*nodeAttempt[\s\S]*resultHash[\s\S]*replay/);
  assert.match(graph, /WorkflowHarnessForkActivationCandidate[\s\S]*dryRunOnly: true/);
  assert.match(graph, /WorkflowHarnessActivationCandidateGateResult[\s\S]*gateId[\s\S]*evidenceRefs/);
  assert.match(graph, /WorkflowHarnessLiveHandoffProof/);
  assert.match(graph, /WorkflowHarnessRuntimeSelectorDecision/);
  assert.match(graph, /WorkflowHarnessDefaultRuntimeDispatchProof/);
  assert.match(graph, /WorkflowHarnessCanaryExecutionBoundary/);
  assert.match(graph, /defaultRuntimeDispatchProof\?: WorkflowHarnessDefaultRuntimeDispatchProof/);
  assert.match(graph, /canaryExecutionBoundaries\?: WorkflowHarnessCanaryExecutionBoundary\[\]/);
  assert.match(workflow, /makeHarnessForkActivationRecord[\s\S]*activationState: "blocked"/);
  assert.match(workflow, /harnessForkActivationId[\s\S]*validated-canary/);
  assert.match(workflow, /makeBlessedHarnessLiveHandoffProof[\s\S]*blessed_workflow_live_canary/);
  assert.match(workflow, /makeHarnessRuntimeSelectorDecision[\s\S]*legacy_runtime[\s\S]*blessed_workflow_live_canary/);
  assert.match(workflow, /makeHarnessDefaultRuntimeDispatchProof[\s\S]*read_only_cognition_routing_verification_completion_authority_tooling[\s\S]*cognitionExecutionMode: "workflow_synchronous_envelope"[\s\S]*promptAssemblyMode: "workflow_synchronous_envelope"[\s\S]*modelExecutionMode: "workflow_synchronous_envelope"[\s\S]*modelExecutionProviderInvocationMode: "workflow_provider_canary"[\s\S]*modelProviderCanaryMode: "workflow_provider_canary"[\s\S]*modelProviderGatedVisibleOutputMode: "workflow_provider_gated_visible_output"[\s\S]*selectedVisibleOutputAuthority: "workflow_model_provider_call"[\s\S]*outputWriterDeferred: false[\s\S]*outputWriterStatus: "visible_write_committed"[\s\S]*outputWriterMaterializationMode: "workflow_visible_transcript_write"[\s\S]*outputWriterStagedWriteMode: "isolated_checkpoint_blob"[\s\S]*outputWriterVisibleWriteMode: "workflow_visible_transcript_write"[\s\S]*authorityToolingMode: "workflow_live_dry_run"[\s\S]*legacyOutputAuthorityRetained: false/);
  assert.match(workflow, /makeHarnessDefaultRuntimeDispatchProof[\s\S]*authorityToolingReadOnlyLiveAttemptIds:[\s\S]*authority_tooling_mcp_provider_read_only[\s\S]*authority_tooling_mcp_tool_call_read_only[\s\S]*authority_tooling_tool_call_read_only[\s\S]*authority_tooling_connector_call_read_only[\s\S]*authority_tooling_wallet_capability_read_only[\s\S]*authorityToolingProviderCatalogLiveAttemptIds:[\s\S]*authority_tooling_mcp_provider_read_only[\s\S]*authorityToolingMcpToolCatalogLiveAttemptIds:[\s\S]*authority_tooling_mcp_tool_call_read_only[\s\S]*authorityToolingConnectorCatalogLiveAttemptIds:[\s\S]*authority_tooling_connector_call_read_only[\s\S]*authorityToolingReadOnlyAuthorityCanaryReady: true[\s\S]*authorityToolingProviderCatalogLiveReady: true[\s\S]*authorityToolingMcpToolCatalogLiveReady: true[\s\S]*authorityToolingConnectorCatalogLiveReady: true[\s\S]*readOnlyAuthorityCanaryReady: true[\s\S]*providerCatalogLiveReady: true[\s\S]*mcpToolCatalogLiveReady: true[\s\S]*connectorCatalogLiveReady: true[\s\S]*mutationDeferredComponentKinds: authorityToolingMutationDeferredComponentKinds/);
  assert.match(workflow, /makeHarnessDefaultRuntimeDispatchProof[\s\S]*readOnlyCapabilityRoutingMode: "workflow_read_only_capability_routing"[\s\S]*readOnlyCapabilityRoutingScenario: "retained_repo_grounded_answer"[\s\S]*readOnlyCapabilityRoutingWorkflowOwnedNodeKinds:[\s\S]*"memory_read"[\s\S]*"capability_sequencer"[\s\S]*"tool_router"[\s\S]*"dry_run_simulator"[\s\S]*readOnlyCapabilityRoutingProof:[\s\S]*sideEffectsExecuted: false[\s\S]*mutationExecuted: false/);
  assert.match(workflow, /makeHarnessDefaultRuntimeDispatchProof[\s\S]*modelProviderGatedVisibleOutputRollbackDrillReady: true[\s\S]*modelProviderGatedVisibleOutputRollbackDrillDivergenceClass:\s*"provider_output_hash_divergence"[\s\S]*modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority:\s*"legacy_runtime_model_invocation"[\s\S]*modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted: true/);
  assert.match(workflow, /makeHarnessCanaryExecutionBoundary[\s\S]*workflow_node_executor[\s\S]*rollbackDrill/);
  assert.match(workflow, /makeHarnessCanaryExecutionBoundaries[\s\S]*clusterId: "cognition"[\s\S]*clusterId: "routing_model"[\s\S]*clusterId: "verification_output"[\s\S]*clusterId: "authority_tooling"/);
  assert.match(workflow, /DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET/);
  assert.match(validation, /activationRecordValidated[\s\S]*canaryStatus === "passed"/);
  assert.match(validation, /workerBinding\?\.harnessActivationId === harness\?\.activationId/);
  assert.match(validation, /createWorkflowHarnessActivationCandidate[\s\S]*activationIdPreview[\s\S]*decision[\s\S]*mintable[\s\S]*workerBindingPreview/);
  assert.match(validation, /gateId: "slots"[\s\S]*gateId: "tests"[\s\S]*gateId: "replay-fixtures"[\s\S]*gateId: "policy-posture"[\s\S]*gateId: "receipt-coverage"[\s\S]*gateId: "canary"[\s\S]*gateId: "rollback"[\s\S]*gateId: "worker-binding"[\s\S]*gateId: "activation-id"/);
  assert.match(rust, /pub struct HarnessComponentInvocation[\s\S]*pub component_kind: HarnessComponentKind[\s\S]*pub execution_mode: HarnessExecutionMode[\s\S]*pub receipt_ids: Vec<String>/);
  assert.match(rust, /pub struct HarnessComponentAdapterResult[\s\S]*pub action_frame: HarnessActionFrame[\s\S]*pub node_attempt: HarnessNodeAttemptRecord/);
  assert.match(rust, /default_harness_action_frame_for_component[\s\S]*execution_mode/);
  assert.match(serviceHarness, /readiness_allows_mode[\s\S]*invoke_default_harness_component[\s\S]*HarnessComponentAdapterResult[\s\S]*harness_component_not_ready_for_mode/);
});
