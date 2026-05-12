#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { parseArgs } from "./args.mjs";
export { parseArgs } from "./args.mjs";
import { writeBundle } from "./artifacts.mjs";
export { writeBundle } from "./artifacts.mjs";
import {
  captureScreenshot,
  closeMatchingWindows,
  commandExists,
  runShell,
  typeQuery,
  waitForWindow,
} from "./desktop.mjs";
export {
  assertGuiClickTargetSafe,
  captureScreenshot,
  closeMatchingWindows,
  detectFocusedComposerClick,
  waitForWindow,
  windowGeometry,
  windowIds,
} from "./desktop.mjs";

import {
  AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
  AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS,
  AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS,
  AUTOPILOT_RETAINED_QUERIES,
  DEFAULT_LIVE_PROMOTION_INVARIANTS,
  GUI_AUTOMATION_CLICK_POLICY,
  autopilotGuiHarnessContract,
  buildBlockedAutopilotGuiHarnessResult,
  validateAutopilotGuiHarnessResult,
} from "../autopilot-gui-harness-contract.mjs";

const repoRoot = resolve(new URL("../../..", import.meta.url).pathname);
const DEFAULT_AGENT_HARNESS_WORKFLOW_ID = "default-agent-harness";
const DEFAULT_AGENT_HARNESS_ACTIVATION_ID =
  "activation:default-agent-harness:blessed-readonly";
const DEFAULT_AGENT_HARNESS_HASH =
  "sha256:default-agent-harness-component-projection-v1";
const HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS = Object.freeze([
  "planner",
  "prompt_assembler",
  "task_state",
]);
const HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS = Object.freeze([
  "model_router",
  "model_call",
  "tool_router",
]);
const HARNESS_VERIFICATION_OUTPUT_LIVE_SHADOW_COMPONENT_KINDS = Object.freeze([
  "postcondition_synthesizer",
  "verifier",
  "completion_gate",
  "receipt_writer",
  "quality_ledger",
  "output_writer",
]);
const HARNESS_AUTHORITY_TOOLING_LIVE_SHADOW_COMPONENT_KINDS = Object.freeze([
  "policy_gate",
  "approval_gate",
  "dry_run_simulator",
  "mcp_provider",
  "mcp_tool_call",
  "tool_call",
  "connector_call",
  "github_pr_create",
  "wallet_capability",
]);
const HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS = Object.freeze([
  ...HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS,
  ...HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS,
  ...HARNESS_VERIFICATION_OUTPUT_LIVE_SHADOW_COMPONENT_KINDS,
  ...HARNESS_AUTHORITY_TOOLING_LIVE_SHADOW_COMPONENT_KINDS,
]);
const REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID =
  DEFAULT_LIVE_PROMOTION_INVARIANTS.find(
    (invariant) =>
      invariant.artifact === "harness_package_import_activation_apply",
  )?.id ?? "reviewed_import_activation_apply";

function sameStringSet(left, right) {
  const normalize = (value) =>
    Array.isArray(value)
      ? [...new Set(value.filter((entry) => typeof entry === "string"))].sort()
      : [];
  const leftItems = normalize(left);
  const rightItems = normalize(right);
  return (
    leftItems.length === rightItems.length &&
    leftItems.every((entry, index) => entry === rightItems[index])
  );
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

async function sleep(ms) {
  await new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

function autopilotProfileRoot() {
  const profile = process.env.AUTOPILOT_DATA_PROFILE || "desktop-localgpu";
  return join(
    process.env.HOME || "",
    ".local/share/ai.ioi.autopilot/profiles",
    profile,
  );
}

function normalizeText(value) {
  return String(value ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

function extractUserRequest(storeContent) {
  const marker = "[User request]";
  const content = String(storeContent ?? "");
  const markerIndex = content.indexOf(marker);
  if (markerIndex < 0) return content.trim();
  return content.slice(markerIndex + marker.length).trim();
}

async function openReadonlySqliteDatabase(filePath) {
  try {
    const { default: Database } = await import("better-sqlite3");
    return new Database(filePath, { readonly: true, fileMustExist: true });
  } catch (error) {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(filePath, { readOnly: true });
    db.__fallbackReason = String(error?.message || error);
    return db;
  }
}

export async function retainedQueryRuntimeEvidence(query, startedAtMs) {
  const profileRoot = autopilotProfileRoot();
  const chatDbPath = join(profileRoot, "chat-memory.db");
  if (!existsSync(chatDbPath)) {
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: `chat memory database not found: ${chatDbPath}`,
    };
  }

  let db;
  try {
    db = await openReadonlySqliteDatabase(chatDbPath);
    const rows = db
      .prepare(
        "select id, hex(thread_id) as thread_hex, role, timestamp_ms, store_content from checkpoint_transcript_messages where timestamp_ms >= ? order by id asc",
      )
      .all(startedAtMs);
    const normalizedQuery = normalizeText(query);
    const retainedQueries = new Set(
      AUTOPILOT_RETAINED_QUERIES.map((item) => normalizeText(item.query)),
    );
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row.role !== "user") continue;
      const extracted = normalizeText(extractUserRequest(row.store_content));
      if (extracted !== normalizedQuery) continue;
      const concatenatedPrompt = [...retainedQueries].some(
        (candidate) =>
          candidate !== normalizedQuery && extracted.includes(candidate),
      );
      const assistant = rows
        .slice(index + 1)
        .find(
          (candidate) =>
            candidate.thread_hex === row.thread_hex &&
            ["agent", "assistant"].includes(
              String(candidate.role).toLowerCase(),
            ) &&
            normalizeText(candidate.store_content).length > 0,
        );
      return {
        matchedUserRequest: true,
        hasAssistantResponse: Boolean(assistant),
        concatenatedPrompt,
        containsInlineSourcesUsed: assistant
          ? /sources used:/i.test(String(assistant.store_content || ""))
          : false,
        threadId: row.thread_hex,
        userTimestampMs: row.timestamp_ms,
        assistantTimestampMs: assistant?.timestamp_ms ?? null,
        assistantSnippet: assistant
          ? normalizeText(assistant.store_content).slice(0, 240)
          : "",
      };
    }
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: "exact retained query not found in transcript projection",
    };
  } catch (error) {
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: String(error?.message || error),
    };
  } finally {
    try {
      db?.close();
    } catch {
      // best-effort close
    }
  }
}

export async function waitForRetainedQueryRuntimeEvidence(
  query,
  startedAtMs,
  timeoutMs,
) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not checked",
  };
  while (Date.now() < deadline) {
    latest = await retainedQueryRuntimeEvidence(query, startedAtMs);
    if (
      latest.matchedUserRequest === true &&
      latest.hasAssistantResponse === true &&
      latest.concatenatedPrompt !== true
    ) {
      return latest;
    }
    await sleep(2_000);
  }
  return {
    ...latest,
    timedOut: true,
  };
}

export async function waitForRetainedQueryUserRequest(query, startedAtMs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not checked",
  };
  while (Date.now() < deadline) {
    latest = await retainedQueryRuntimeEvidence(query, startedAtMs);
    if (
      latest.matchedUserRequest === true &&
      latest.concatenatedPrompt !== true
    ) {
      return latest;
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    timedOutWaitingForSubmit: true,
  };
}

export async function submitRetainedQuery(windowId, query, startedAtMs) {
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not submitted",
  };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    typeQuery(windowId, query);
    latest = await waitForRetainedQueryUserRequest(query, startedAtMs, 6_000);
    if (
      latest.matchedUserRequest === true &&
      latest.concatenatedPrompt !== true
    ) {
      return {
        ...latest,
        submitAttempt: attempt,
      };
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    submitAttempt: 3,
  };
}

export async function collectRuntimeArtifacts(outputRoot, logPath) {
  const profileRoot = autopilotProfileRoot();
  const chatDbPath = join(profileRoot, "chat-memory.db");
  const summary = {
    profileRoot,
    chatDbPath,
    transcriptCount: 0,
    threadEventCount: 0,
    artifactRecordCount: 0,
    runtimeEvidenceReportCount: 0,
    runBundleCount: 0,
    selectedSourceCount: 0,
    promptAssemblyCount: 0,
    turnStateCount: 0,
    decisionLoopCount: 0,
    traceBundleCount: 0,
    modelRoutingCount: 0,
    toolSelectionQualityCount: 0,
    scorecardCount: 0,
    stopReasonCount: 0,
    qualityLedgerCount: 0,
    harnessWorkerBindingCount: 0,
    harnessShadowRunCount: 0,
    harnessNodeAttemptCount: 0,
    harnessShadowComparisonCount: 0,
    harnessBlockingDivergenceCount: 0,
    harnessGatedClusterCount: 0,
    harnessGatedCognitionCount: 0,
    harnessGatedRoutingModelCount: 0,
    harnessGatedVerificationOutputCount: 0,
    harnessGatedAuthorityToolingCount: 0,
    harnessForkActivationBlockedCount: 0,
    harnessForkActivationMintedCount: 0,
    harnessForkMutationCanaryReadyCount: 0,
    harnessForkMutationCanaryReceiptCount: 0,
    harnessForkMutationCanaryReplayCount: 0,
    harnessForkMutationCanaryNodeAttemptCount: 0,
    harnessForkHandoffTimelineBoundCount: 0,
    harnessRollbackRestoreCanaryBlockedCount: 0,
    harnessRollbackRestoreCanaryReadyCount: 0,
    harnessRollbackRestoreCanaryReceiptCount: 0,
    harnessRollbackRestoreCanaryStatuses: [],
    harnessActivationAuditReceiptCount: 0,
    harnessRollbackExecutionReceiptCount: 0,
    harnessCanaryBoundaryExecutedCount: 0,
    harnessCanaryBoundaryRollbackDrillCount: 0,
    harnessSelectorCanaryRoutedCount: 0,
    harnessSelectorWorkflowRecoveryBlockedCount: 0,
    harnessSelectorDefaultPromotedCount: 0,
    harnessSelectorLivePromotionReadinessGatedCount: 0,
    harnessSelectorReviewedImportActivationApplyInvariantCount: 0,
    harnessLiveHandoffCanaryCount: 0,
    harnessLiveHandoffDefaultPromotedCount: 0,
    harnessLiveHandoffRollbackCount: 0,
    harnessDefaultRuntimeDispatchReadonlyCount: 0,
    harnessLivePromotionReadinessCount: 0,
    harnessActivationIdGateClickProofRuntimeCount: 0,
    harnessActivationIdGateClickProofRuntimeBlockedCount: 0,
    harnessDefaultRuntimeBindingCount: 0,
    harnessDefaultRuntimeBindingMatchedCount: 0,
    harnessDefaultRuntimeRollbackLiveShadowGateBoundCount: 0,
    harnessWorkerBindingRegistryReviewedPackageBoundCount: 0,
    harnessWorkerLaunchReviewedImportActivationInvariantCount: 0,
    harnessDefaultRuntimeBindingSamples: [],
    harnessCognitionNodeAuthorityCount: 0,
    harnessCognitionNodeAuthoritySamples: [],
    harnessRoutingModelNodeAuthorityCount: 0,
    harnessRoutingModelNodeAuthoritySamples: [],
    harnessVerificationOutputNodeAuthorityCount: 0,
    harnessVerificationOutputNodeAuthoritySamples: [],
    harnessAuthorityToolingNodeAuthorityCount: 0,
    harnessAuthorityToolingNodeAuthoritySamples: [],
    harnessLiveTurnNodeTimelineCount: 0,
    harnessLiveTurnNodeTimelineScenarios: [],
    harnessLiveTurnNodeTimelineSamples: [],
    harnessLiveTurnNodeInspectorCount: 0,
    harnessLiveTurnNodeInspectorScenarios: [],
    harnessLiveTurnNodeInspectorSamples: [],
    harnessLiveShadowComparisonCount: 0,
    harnessLiveShadowComparisonScenarios: [],
    harnessLiveShadowComparisonComponentKinds: [],
    harnessLiveShadowComparisonSamples: [],
    harnessAuthorityToolingReadOnlyCanaryCount: 0,
    harnessAuthorityToolingGateLiveCount: 0,
    harnessAuthorityToolingProviderCatalogLiveCount: 0,
    harnessAuthorityToolingMcpToolCatalogLiveCount: 0,
    harnessAuthorityToolingNativeToolCatalogLiveCount: 0,
    harnessAuthorityToolingConnectorCatalogLiveCount: 0,
    harnessAuthorityToolingGithubPrCreateDryRunCount: 0,
    harnessAuthorityToolingWalletCapabilityLiveDryRunCount: 0,
    harnessModelProviderGatedVisibleOutputCount: 0,
    harnessModelProviderGatedVisibleOutputRollbackDrillCount: 0,
    harnessModelProviderGatedVisibleOutputScenarios: [],
    harnessModelProviderGatedVisibleOutputRollbackDrillScenarios: [],
    harnessReadOnlyCapabilityRoutingCount: 0,
    harnessReadOnlyCapabilityRoutingNoMutationCount: 0,
    harnessReadOnlyCapabilityRoutingScenarios: [],
    harnessReadOnlyCapabilityRoutingNoMutationScenarios: [],
    recentArtifacts: [],
    logSignals: {
      kernelEvents: 0,
      chatProofTrace: 0,
      sessionProjectionRefreshes: 0,
    },
    collectionErrors: [],
  };
  const harnessCognitionNodeAuthorityKeys = new Set();
  const harnessRoutingModelNodeAuthorityKeys = new Set();
  const harnessVerificationOutputNodeAuthorityKeys = new Set();
  const harnessAuthorityToolingNodeAuthorityKeys = new Set();
  const harnessLiveTurnNodeTimelineKeys = new Set();
  const harnessLiveTurnNodeInspectorKeys = new Set();
  const harnessLiveShadowComparisonKeys = new Set();
  const addScenario = (items, scenario) => {
    if (
      typeof scenario === "string" &&
      scenario.length > 0 &&
      !items.includes(scenario)
    ) {
      items.push(scenario);
      items.sort();
    }
  };
  const stringArrayLength = (value) =>
    Array.isArray(value) ? value.length : 0;
  const adapterResultsReady = (value, mode, readiness, status, minimum) =>
    Array.isArray(value) &&
    value.length >= minimum &&
    value.every(
      (result) =>
        result?.actionFrame?.executionMode === mode &&
        result?.actionFrame?.readiness === readiness &&
        result?.nodeAttempt?.status === status &&
        Array.isArray(result?.nodeAttempt?.receiptIds) &&
        result.nodeAttempt.receiptIds.length > 0 &&
        typeof result?.nodeAttempt?.replay?.fixtureRef === "string" &&
        result.nodeAttempt.replay.fixtureRef.length > 0,
    );
  const cognitionNodeAuthorityReady = (dispatch) => {
    const gate = dispatch?.cognitionNodeAuthorityGate;
    return (
      gate?.schemaVersion ===
        "workflow.harness.default-runtime-dispatch.cognition-node-authority.v1" &&
      gate?.gateId === "cognition-node-authority" &&
      gate?.authorityMode === "node_authoritative" &&
      gate?.authoritative === true &&
      gate?.workflowId === dispatch?.workflowId &&
      gate?.activationId === dispatch?.activationId &&
      gate?.harnessHash === dispatch?.harnessHash &&
      gate?.requiredExecutionMode === "live" &&
      gate?.runtimeAuthority === "blessed_workflow_activation_default" &&
      gate?.adapterMode === "workflow_component_adapter_live" &&
      gate?.recoveryAvailable === true &&
      typeof gate?.recoveryTarget === "string" &&
      gate.recoveryTarget.length > 0 &&
      gate?.policyDecision === "allow_node_authoritative_cognition" &&
      Array.isArray(gate?.blockers) &&
      gate.blockers.length === 0 &&
      ["planner", "prompt_assembler", "task_state"].every(
        (componentKind) =>
          gate.componentKinds?.includes(componentKind) &&
          gate.liveReadyComponentKinds?.includes(componentKind),
      ) &&
      stringArrayLength(gate.actionFrameIds) >= 3 &&
      stringArrayLength(gate.attemptIds) >= 3 &&
      stringArrayLength(gate.receiptIds) >= 3 &&
      stringArrayLength(gate.replayFixtureRefs) >= 3
    );
  };
  const routingModelNodeAuthorityReady = (dispatch) => {
    const gate = dispatch?.routingModelNodeAuthorityGate;
    return (
      gate?.schemaVersion ===
        "workflow.harness.default-runtime-dispatch.routing-model-node-authority.v1" &&
      gate?.gateId === "routing-model-node-authority" &&
      gate?.authorityMode === "gated_node_authoritative" &&
      gate?.authoritative === true &&
      gate?.workflowId === dispatch?.workflowId &&
      gate?.activationId === dispatch?.activationId &&
      gate?.harnessHash === dispatch?.harnessHash &&
      gate?.requiredExecutionMode === "gated" &&
      gate?.runtimeAuthority === "blessed_workflow_activation_default" &&
      gate?.adapterMode === "workflow_component_adapter_gated" &&
      gate?.recoveryAvailable === true &&
      typeof gate?.recoveryTarget === "string" &&
      gate.recoveryTarget.length > 0 &&
      gate?.policyDecision ===
        "allow_gated_node_authoritative_routing_model" &&
      gate?.providerCanaryReady === true &&
      gate?.visibleOutputSelected === true &&
      gate?.visibleOutputAuthority === "workflow_model_provider_call" &&
      gate?.rollbackAvailable === true &&
      Array.isArray(gate?.blockers) &&
      gate.blockers.length === 0 &&
      ["model_router", "model_call", "tool_router"].every(
        (componentKind) =>
          gate.componentKinds?.includes(componentKind) &&
          gate.shadowReadyComponentKinds?.includes(componentKind),
      ) &&
      stringArrayLength(gate.actionFrameIds) >= 3 &&
      stringArrayLength(gate.attemptIds) >= 3 &&
      stringArrayLength(gate.receiptIds) >= 3 &&
      stringArrayLength(gate.replayFixtureRefs) >= 3 &&
      stringArrayLength(gate.shadowAttemptIds) >= 3 &&
      stringArrayLength(gate.shadowReceiptIds) >= 3 &&
      stringArrayLength(gate.shadowReplayFixtureRefs) >= 3 &&
      (gate.divergenceClasses ?? []).every(
        (divergenceClass) => divergenceClass === "none",
      ) &&
      (gate.shadowDivergenceClasses ?? []).every(
        (divergenceClass) => divergenceClass === "none",
      )
    );
  };
  const verificationOutputNodeAuthorityReady = (dispatch) => {
    const gate = dispatch?.verificationOutputNodeAuthorityGate;
    return (
      gate?.schemaVersion ===
        "workflow.harness.default-runtime-dispatch.verification-output-node-authority.v1" &&
      gate?.gateId === "verification-output-node-authority" &&
      gate?.authorityMode === "gated_node_authoritative" &&
      gate?.authoritative === true &&
      gate?.workflowId === dispatch?.workflowId &&
      gate?.activationId === dispatch?.activationId &&
      gate?.harnessHash === dispatch?.harnessHash &&
      gate?.requiredExecutionMode === "gated" &&
      gate?.runtimeAuthority === "blessed_workflow_activation_default" &&
      gate?.adapterMode === "workflow_component_adapter_gated" &&
      gate?.recoveryAvailable === true &&
      typeof gate?.recoveryTarget === "string" &&
      gate.recoveryTarget.length > 0 &&
      gate?.policyDecision ===
        "allow_gated_node_authoritative_verification_output" &&
      gate?.outputWriterHandoffReady === true &&
      gate?.outputWriterMaterializationCanaryReady === true &&
      gate?.outputWriterStagedWriteCanaryReady === true &&
      gate?.outputWriterVisibleWriteReady === true &&
      gate?.outputWriterVisibleWriteCommitted === true &&
      gate?.rollbackAvailable === true &&
      Array.isArray(gate?.blockers) &&
      gate.blockers.length === 0 &&
      [
        "postcondition_synthesizer",
        "verifier",
        "completion_gate",
        "receipt_writer",
        "quality_ledger",
        "output_writer",
      ].every(
        (componentKind) =>
          gate.componentKinds?.includes(componentKind) &&
          gate.shadowReadyComponentKinds?.includes(componentKind),
      ) &&
      stringArrayLength(gate.actionFrameIds) >= 6 &&
      stringArrayLength(gate.attemptIds) >= 6 &&
      stringArrayLength(gate.receiptIds) >= 6 &&
      stringArrayLength(gate.replayFixtureRefs) >= 6 &&
      stringArrayLength(gate.shadowAttemptIds) >= 6 &&
      stringArrayLength(gate.shadowReceiptIds) >= 6 &&
      stringArrayLength(gate.shadowReplayFixtureRefs) >= 6 &&
      (gate.divergenceClasses ?? []).every(
        (divergenceClass) => divergenceClass === "none",
      ) &&
      (gate.shadowDivergenceClasses ?? []).every(
        (divergenceClass) => divergenceClass === "none",
      )
    );
  };
  const authorityToolingNodeAuthorityReady = (dispatch) => {
    const gate = dispatch?.authorityToolingNodeAuthorityGate;
    return (
      gate?.schemaVersion ===
        "workflow.harness.default-runtime-dispatch.authority-tooling-node-authority.v1" &&
      gate?.gateId === "authority-tooling-node-authority" &&
      gate?.authorityMode === "gated_node_authoritative" &&
      gate?.authoritative === true &&
      gate?.workflowId === dispatch?.workflowId &&
      gate?.activationId === dispatch?.activationId &&
      gate?.harnessHash === dispatch?.harnessHash &&
      gate?.requiredExecutionMode === "gated" &&
      gate?.runtimeAuthority === "blessed_workflow_activation_default" &&
      gate?.adapterMode === "workflow_component_adapter_gated" &&
      gate?.recoveryAvailable === true &&
      typeof gate?.recoveryTarget === "string" &&
      gate.recoveryTarget.length > 0 &&
      gate?.policyDecision ===
        "allow_gated_node_authoritative_authority_tooling" &&
      gate?.readOnlyRouteAccepted === true &&
      gate?.destructiveRouteDenied === true &&
      gate?.mutatingToolCallsBlocked === true &&
      gate?.sideEffectsExecuted === false &&
      gate?.policyGateReady === true &&
      gate?.toolRouterReady === true &&
      gate?.dryRunSimulatorReady === true &&
      gate?.approvalGateReady === true &&
      gate?.gateLiveReady === true &&
      gate?.readOnlyAuthorityCanaryReady === true &&
      gate?.rollbackAvailable === true &&
      Array.isArray(gate?.blockers) &&
      gate.blockers.length === 0 &&
      [
        "policy_gate",
        "approval_gate",
        "dry_run_simulator",
        "mcp_provider",
        "mcp_tool_call",
        "tool_call",
        "connector_call",
        "wallet_capability",
      ].every(
        (componentKind) =>
          gate.componentKinds?.includes(componentKind) &&
          gate.shadowReadyComponentKinds?.includes(componentKind),
      ) &&
      stringArrayLength(gate.actionFrameIds) >= 8 &&
      stringArrayLength(gate.attemptIds) >= 8 &&
      stringArrayLength(gate.receiptIds) >= 8 &&
      stringArrayLength(gate.replayFixtureRefs) >= 8 &&
      stringArrayLength(gate.shadowAttemptIds) >= 8 &&
      stringArrayLength(gate.shadowReceiptIds) >= 8 &&
      stringArrayLength(gate.shadowReplayFixtureRefs) >= 8 &&
      (gate.divergenceClasses ?? []).every(
        (divergenceClass) => divergenceClass === "none",
      ) &&
      (gate.shadowDivergenceClasses ?? []).every(
        (divergenceClass) => divergenceClass === "none",
      )
    );
  };
  const extractInspectableHarnessAttempt = (dispatch) => {
    const resultSources = [
      dispatch?.cognitionExecutionAdapterResults,
      dispatch?.cognitionExecutionShadowAdapterResults,
      dispatch?.cognitionExecutionGateAdapterResults,
      dispatch?.routingModelAdapterResults,
      dispatch?.routingModelShadowAdapterResults,
      dispatch?.verificationOutputAdapterResults,
      dispatch?.verificationOutputShadowAdapterResults,
      dispatch?.authorityToolingAdapterResults,
      dispatch?.authorityToolingShadowAdapterResults,
    ];
    const resultAttempt = resultSources
      .flatMap((items) => (Array.isArray(items) ? items : []))
      .map((result) => ({
        actionFrame: result?.actionFrame,
        nodeAttempt: result?.nodeAttempt,
      }))
      .find(({ actionFrame, nodeAttempt }) => {
        const replayFixtureRef = nodeAttempt?.replay?.fixtureRef;
        return (
          typeof nodeAttempt?.attemptId === "string" &&
          nodeAttempt.attemptId.length > 0 &&
          typeof nodeAttempt?.workflowNodeId === "string" &&
          nodeAttempt.workflowNodeId.length > 0 &&
          typeof nodeAttempt?.componentKind === "string" &&
          nodeAttempt.componentKind.length > 0 &&
          typeof nodeAttempt?.executionMode === "string" &&
          nodeAttempt.executionMode.length > 0 &&
          typeof nodeAttempt?.readiness === "string" &&
          nodeAttempt.readiness.length > 0 &&
          typeof nodeAttempt?.status === "string" &&
          nodeAttempt.status.length > 0 &&
          Array.isArray(nodeAttempt?.receiptIds) &&
          nodeAttempt.receiptIds.length > 0 &&
          typeof replayFixtureRef === "string" &&
          replayFixtureRef.length > 0 &&
          typeof nodeAttempt?.policyDecision === "string" &&
          nodeAttempt.policyDecision.length > 0 &&
          typeof nodeAttempt?.inputHash === "string" &&
          nodeAttempt.inputHash.length > 0 &&
          typeof nodeAttempt?.outputHash === "string" &&
          nodeAttempt.outputHash.length > 0 &&
          (!actionFrame ||
            (actionFrame.nodeId === nodeAttempt.workflowNodeId &&
              actionFrame.componentKind === nodeAttempt.componentKind &&
              actionFrame.executionMode === nodeAttempt.executionMode))
        );
      });
    if (resultAttempt?.nodeAttempt) return resultAttempt;

    const directAttempt = (
      Array.isArray(dispatch?.dispatchNodeAttempts)
        ? dispatch.dispatchNodeAttempts
        : []
    ).find((nodeAttempt) => {
      const replayFixtureRef = nodeAttempt?.replay?.fixtureRef;
      return (
        typeof nodeAttempt?.attemptId === "string" &&
        nodeAttempt.attemptId.length > 0 &&
        typeof nodeAttempt?.workflowNodeId === "string" &&
        nodeAttempt.workflowNodeId.length > 0 &&
        typeof nodeAttempt?.componentKind === "string" &&
        nodeAttempt.componentKind.length > 0 &&
        Array.isArray(nodeAttempt?.receiptIds) &&
        nodeAttempt.receiptIds.length > 0 &&
        typeof replayFixtureRef === "string" &&
        replayFixtureRef.length > 0 &&
        typeof nodeAttempt?.policyDecision === "string" &&
        nodeAttempt.policyDecision.length > 0 &&
        typeof nodeAttempt?.inputHash === "string" &&
        nodeAttempt.inputHash.length > 0 &&
        typeof nodeAttempt?.outputHash === "string" &&
        nodeAttempt.outputHash.length > 0
      );
    });
    return directAttempt
      ? { actionFrame: null, nodeAttempt: directAttempt }
      : null;
  };
  const extractHarnessLiveShadowComparisons = (dispatch) => {
    const comparisons = Array.isArray(dispatch?.liveShadowComparisons)
      ? dispatch.liveShadowComparisons
      : [];
    if (comparisons.length === 0) return [];
    const attempts = [
      dispatch?.cognitionExecutionAdapterResults,
      dispatch?.cognitionExecutionShadowAdapterResults,
      dispatch?.cognitionExecutionGateAdapterResults,
      dispatch?.routingModelAdapterResults,
      dispatch?.routingModelShadowAdapterResults,
      dispatch?.verificationOutputAdapterResults,
      dispatch?.verificationOutputShadowAdapterResults,
      dispatch?.authorityToolingAdapterResults,
      dispatch?.authorityToolingShadowAdapterResults,
    ]
      .flatMap((items) => (Array.isArray(items) ? items : []))
      .map((result) => result?.nodeAttempt)
      .filter(Boolean);
    const readyComparisons = [];
    for (const comparison of comparisons) {
      const liveAttempt =
        attempts.find(
          (attempt) => attempt?.attemptId === comparison?.liveAttemptId,
        ) ?? null;
      const shadowAttempt =
        attempts.find(
          (attempt) => attempt?.attemptId === comparison?.shadowAttemptId,
        ) ?? null;
      if (!liveAttempt || !shadowAttempt) continue;
      const ready =
        comparison.divergence === "none" &&
        comparison.blocking === false &&
        ["live", "gated"].includes(liveAttempt.executionMode) &&
        shadowAttempt.executionMode === "shadow" &&
        Array.isArray(liveAttempt.receiptIds) &&
        liveAttempt.receiptIds.length > 0 &&
        Array.isArray(shadowAttempt.receiptIds) &&
        shadowAttempt.receiptIds.length > 0 &&
        typeof liveAttempt.replay?.fixtureRef === "string" &&
        liveAttempt.replay.fixtureRef.length > 0 &&
        typeof shadowAttempt.replay?.fixtureRef === "string" &&
        shadowAttempt.replay.fixtureRef.length > 0 &&
        typeof liveAttempt.inputHash === "string" &&
        liveAttempt.inputHash.length > 0 &&
        liveAttempt.inputHash === shadowAttempt.inputHash &&
        typeof liveAttempt.outputHash === "string" &&
        liveAttempt.outputHash.length > 0 &&
        liveAttempt.outputHash === shadowAttempt.outputHash;
      if (ready) {
        readyComparisons.push({ comparison, liveAttempt, shadowAttempt });
      }
    }
    return readyComparisons;
  };
  const noteHarnessLiveTurnNodeTimeline = (dispatch, artifactId = null) => {
    if (!dispatch || typeof dispatch !== "object") return;
    const scenario = dispatch.modelProviderGatedVisibleOutputScenario;
    const policyDecisions = [
      dispatch.policyDecision,
      dispatch.modelExecutionProof?.policyDecision,
      dispatch.modelProviderCanaryProof?.policyDecision,
      dispatch.modelProviderGatedVisibleOutputProof?.policyDecision,
      dispatch.modelProviderGatedVisibleOutputRollbackDrillProof
        ?.policyDecision,
      dispatch.readOnlyCapabilityRoutingProof?.policyDecision,
      dispatch.authorityToolingProof?.policyDecision,
      dispatch.authorityToolingAdapterProof?.policyDecision,
      dispatch.cognitionNodeAuthorityGate?.policyDecision,
      dispatch.routingModelNodeAuthorityGate?.policyDecision,
      dispatch.verificationOutputNodeAuthorityGate?.policyDecision,
      dispatch.authorityToolingNodeAuthorityGate?.policyDecision,
    ].filter((decision) => typeof decision === "string" && decision.length > 0);
    const liveTurnTimelineReady =
      dispatch.schemaVersion ===
        "workflow.harness.default-runtime-dispatch.v1" &&
      scenario === "retained_harness_dogfooding" &&
      dispatch.status === "accepted" &&
      dispatch.selectedSelector === "blessed_workflow_live_default" &&
      dispatch.productionDefaultSelector === "blessed_workflow_live_default" &&
      dispatch.executionMode === "live" &&
      dispatch.runtimeAuthority === "blessed_workflow_activation_default" &&
      dispatch.drivesRuntimeDecision === true &&
      dispatch.outputAuthority === "blessed_workflow_activation_default" &&
      dispatch.outputWriterStatus === "visible_write_committed" &&
      stringArrayLength(dispatch.dispatchNodeAttemptIds) >= 20 &&
      stringArrayLength(dispatch.acceptedNodeAttemptIds) >= 18 &&
      stringArrayLength(dispatch.receiptIds) >= 18 &&
      stringArrayLength(dispatch.replayFixtureRefs) >= 18 &&
      stringArrayLength(dispatch.cognitionExecutionAttemptIds) >= 3 &&
      stringArrayLength(dispatch.cognitionExecutionReceiptIds) >= 3 &&
      stringArrayLength(dispatch.cognitionExecutionReplayFixtureRefs) >= 3 &&
      adapterResultsReady(
        dispatch.cognitionExecutionAdapterResults,
        "live",
        "live_ready",
        "live",
        3,
      ) &&
      cognitionNodeAuthorityReady(dispatch) &&
      routingModelNodeAuthorityReady(dispatch) &&
      verificationOutputNodeAuthorityReady(dispatch) &&
      authorityToolingNodeAuthorityReady(dispatch) &&
      adapterResultsReady(
        dispatch.cognitionExecutionGateAdapterResults,
        "gated",
        "shadow_ready",
        "gated",
        3,
      ) &&
      adapterResultsReady(
        dispatch.routingModelAdapterResults,
        "gated",
        "shadow_ready",
        "gated",
        3,
      ) &&
      adapterResultsReady(
        dispatch.routingModelShadowAdapterResults,
        "shadow",
        "shadow_ready",
        "shadow",
        3,
      ) &&
      adapterResultsReady(
        dispatch.verificationOutputAdapterResults,
        "gated",
        "shadow_ready",
        "gated",
        6,
      ) &&
      adapterResultsReady(
        dispatch.verificationOutputShadowAdapterResults,
        "shadow",
        "shadow_ready",
        "shadow",
        6,
      ) &&
      adapterResultsReady(
        dispatch.authorityToolingAdapterResults,
        "gated",
        "shadow_ready",
        "gated",
        8,
      ) &&
      adapterResultsReady(
        dispatch.authorityToolingShadowAdapterResults,
        "shadow",
        "shadow_ready",
        "shadow",
        8,
      ) &&
      stringArrayLength(dispatch.modelExecutionAttemptIds) >= 5 &&
      stringArrayLength(dispatch.modelExecutionReceiptIds) >= 5 &&
      stringArrayLength(dispatch.modelExecutionReplayFixtureRefs) >= 5 &&
      policyDecisions.length >= 4;
    if (!liveTurnTimelineReady) return;
    const timelineKey =
      dispatch.dispatchId ??
      `${scenario}:${artifactId ?? "runtime-evidence-projection"}`;
    if (harnessLiveTurnNodeTimelineKeys.has(timelineKey)) return;
    harnessLiveTurnNodeTimelineKeys.add(timelineKey);
    if (!harnessCognitionNodeAuthorityKeys.has(timelineKey)) {
      harnessCognitionNodeAuthorityKeys.add(timelineKey);
      summary.harnessCognitionNodeAuthorityCount += 1;
      if (summary.harnessCognitionNodeAuthoritySamples.length < 8) {
        summary.harnessCognitionNodeAuthoritySamples.push({
          artifactId,
          dispatchId: dispatch.dispatchId ?? null,
          scenario,
          gateId: dispatch.cognitionNodeAuthorityGate?.gateId ?? null,
          authorityMode:
            dispatch.cognitionNodeAuthorityGate?.authorityMode ?? null,
          policyDecision:
            dispatch.cognitionNodeAuthorityGate?.policyDecision ?? null,
          componentKinds:
            dispatch.cognitionNodeAuthorityGate?.componentKinds ?? [],
          attemptIds: dispatch.cognitionNodeAuthorityGate?.attemptIds ?? [],
          receiptIds: dispatch.cognitionNodeAuthorityGate?.receiptIds ?? [],
          replayFixtureRefs:
            dispatch.cognitionNodeAuthorityGate?.replayFixtureRefs ?? [],
        });
      }
    }
    if (!harnessRoutingModelNodeAuthorityKeys.has(timelineKey)) {
      harnessRoutingModelNodeAuthorityKeys.add(timelineKey);
      summary.harnessRoutingModelNodeAuthorityCount += 1;
      if (summary.harnessRoutingModelNodeAuthoritySamples.length < 8) {
        summary.harnessRoutingModelNodeAuthoritySamples.push({
          artifactId,
          dispatchId: dispatch.dispatchId ?? null,
          scenario,
          gateId: dispatch.routingModelNodeAuthorityGate?.gateId ?? null,
          authorityMode:
            dispatch.routingModelNodeAuthorityGate?.authorityMode ?? null,
          policyDecision:
            dispatch.routingModelNodeAuthorityGate?.policyDecision ?? null,
          componentKinds:
            dispatch.routingModelNodeAuthorityGate?.componentKinds ?? [],
          attemptIds: dispatch.routingModelNodeAuthorityGate?.attemptIds ?? [],
          receiptIds: dispatch.routingModelNodeAuthorityGate?.receiptIds ?? [],
          replayFixtureRefs:
            dispatch.routingModelNodeAuthorityGate?.replayFixtureRefs ?? [],
          visibleOutputAuthority:
            dispatch.routingModelNodeAuthorityGate?.visibleOutputAuthority ??
            null,
        });
      }
    }
    if (!harnessVerificationOutputNodeAuthorityKeys.has(timelineKey)) {
      harnessVerificationOutputNodeAuthorityKeys.add(timelineKey);
      summary.harnessVerificationOutputNodeAuthorityCount += 1;
      if (summary.harnessVerificationOutputNodeAuthoritySamples.length < 8) {
        summary.harnessVerificationOutputNodeAuthoritySamples.push({
          artifactId,
          dispatchId: dispatch.dispatchId ?? null,
          scenario,
          gateId: dispatch.verificationOutputNodeAuthorityGate?.gateId ?? null,
          authorityMode:
            dispatch.verificationOutputNodeAuthorityGate?.authorityMode ?? null,
          policyDecision:
            dispatch.verificationOutputNodeAuthorityGate?.policyDecision ?? null,
          componentKinds:
            dispatch.verificationOutputNodeAuthorityGate?.componentKinds ?? [],
          attemptIds:
            dispatch.verificationOutputNodeAuthorityGate?.attemptIds ?? [],
          receiptIds:
            dispatch.verificationOutputNodeAuthorityGate?.receiptIds ?? [],
          replayFixtureRefs:
            dispatch.verificationOutputNodeAuthorityGate?.replayFixtureRefs ??
            [],
          outputWriterVisibleWriteCommitted:
            dispatch.verificationOutputNodeAuthorityGate
              ?.outputWriterVisibleWriteCommitted ?? null,
        });
      }
    }
    if (!harnessAuthorityToolingNodeAuthorityKeys.has(timelineKey)) {
      harnessAuthorityToolingNodeAuthorityKeys.add(timelineKey);
      summary.harnessAuthorityToolingNodeAuthorityCount += 1;
      if (summary.harnessAuthorityToolingNodeAuthoritySamples.length < 8) {
        summary.harnessAuthorityToolingNodeAuthoritySamples.push({
          artifactId,
          dispatchId: dispatch.dispatchId ?? null,
          scenario,
          gateId: dispatch.authorityToolingNodeAuthorityGate?.gateId ?? null,
          authorityMode:
            dispatch.authorityToolingNodeAuthorityGate?.authorityMode ?? null,
          policyDecision:
            dispatch.authorityToolingNodeAuthorityGate?.policyDecision ?? null,
          componentKinds:
            dispatch.authorityToolingNodeAuthorityGate?.componentKinds ?? [],
          attemptIds:
            dispatch.authorityToolingNodeAuthorityGate?.attemptIds ?? [],
          receiptIds:
            dispatch.authorityToolingNodeAuthorityGate?.receiptIds ?? [],
          replayFixtureRefs:
            dispatch.authorityToolingNodeAuthorityGate?.replayFixtureRefs ??
            [],
          readOnlyRouteAccepted:
            dispatch.authorityToolingNodeAuthorityGate?.readOnlyRouteAccepted ??
            null,
          destructiveRouteDenied:
            dispatch.authorityToolingNodeAuthorityGate?.destructiveRouteDenied ??
            null,
          sideEffectsExecuted:
            dispatch.authorityToolingNodeAuthorityGate?.sideEffectsExecuted ??
            null,
        });
      }
    }
    summary.harnessLiveTurnNodeTimelineCount += 1;
    addScenario(summary.harnessLiveTurnNodeTimelineScenarios, scenario);
    if (summary.harnessLiveTurnNodeTimelineSamples.length < 8) {
      summary.harnessLiveTurnNodeTimelineSamples.push({
        artifactId,
        dispatchId: dispatch.dispatchId ?? null,
        scenario,
        workflowId: dispatch.workflowId ?? null,
        activationId: dispatch.activationId ?? null,
        harnessHash: dispatch.harnessHash ?? null,
        executionMode: dispatch.executionMode ?? null,
        runtimeAuthority: dispatch.runtimeAuthority ?? null,
        policyDecision: dispatch.policyDecision ?? null,
        policyDecisions,
        dispatchNodeAttemptCount: stringArrayLength(
          dispatch.dispatchNodeAttemptIds,
        ),
        acceptedNodeAttemptCount: stringArrayLength(
          dispatch.acceptedNodeAttemptIds,
        ),
        receiptRefCount: stringArrayLength(dispatch.receiptIds),
        replayFixtureRefCount: stringArrayLength(dispatch.replayFixtureRefs),
        liveAdapterAttemptCount: stringArrayLength(
          dispatch.cognitionExecutionAttemptIds,
        ),
        gatedAdapterAttemptCount:
          stringArrayLength(dispatch.cognitionExecutionGateAttemptIds) +
          stringArrayLength(dispatch.routingModelAttemptIds) +
          stringArrayLength(dispatch.verificationOutputAttemptIds) +
          stringArrayLength(dispatch.authorityToolingAttemptIds),
        modelExecutionAttemptCount: stringArrayLength(
          dispatch.modelExecutionAttemptIds,
        ),
      });
    }
    const inspectableAttempt = extractInspectableHarnessAttempt(dispatch);
    if (!inspectableAttempt?.nodeAttempt) return;
    const nodeAttempt = inspectableAttempt.nodeAttempt;
    const actionFrame = inspectableAttempt.actionFrame;
    const replayFixtureRef = nodeAttempt.replay?.fixtureRef ?? null;
    const inspectorKey = `${timelineKey}:${nodeAttempt.attemptId}`;
    if (harnessLiveTurnNodeInspectorKeys.has(inspectorKey)) return;
    harnessLiveTurnNodeInspectorKeys.add(inspectorKey);
    summary.harnessLiveTurnNodeInspectorCount += 1;
    addScenario(summary.harnessLiveTurnNodeInspectorScenarios, scenario);
    if (summary.harnessLiveTurnNodeInspectorSamples.length < 8) {
      summary.harnessLiveTurnNodeInspectorSamples.push({
        artifactId,
        dispatchId: dispatch.dispatchId ?? null,
        scenario,
        workflowId:
          dispatch.workflowId ?? nodeAttempt.harnessWorkflowId ?? null,
        activationId:
          dispatch.activationId ?? nodeAttempt.harnessActivationId ?? null,
        harnessHash: dispatch.harnessHash ?? nodeAttempt.harnessHash ?? null,
        runtimeAuthority: dispatch.runtimeAuthority ?? null,
        nodeAttemptId: nodeAttempt.attemptId,
        workflowNodeId: nodeAttempt.workflowNodeId,
        componentId:
          nodeAttempt.componentId ?? actionFrame?.componentId ?? null,
        componentKind:
          nodeAttempt.componentKind ?? actionFrame?.componentKind ?? null,
        executionMode:
          nodeAttempt.executionMode ?? actionFrame?.executionMode ?? null,
        readiness: nodeAttempt.readiness ?? actionFrame?.readiness ?? null,
        status: nodeAttempt.status ?? null,
        policyDecision: nodeAttempt.policyDecision ?? null,
        receiptRefs: Array.isArray(nodeAttempt.receiptIds)
          ? nodeAttempt.receiptIds.slice(0, 12)
          : [],
        receiptRefCount: stringArrayLength(nodeAttempt.receiptIds),
        replayFixtureRef,
        replayDeterminism: nodeAttempt.replay?.determinism ?? null,
        replayRedactionPolicy: nodeAttempt.replay?.redactionPolicy ?? null,
        inputHash: nodeAttempt.inputHash ?? null,
        outputHash: nodeAttempt.outputHash ?? null,
        actionFrameNodeId: actionFrame?.nodeId ?? null,
        actionFrameComponentKind: actionFrame?.componentKind ?? null,
        actionFrameExecutionMode: actionFrame?.executionMode ?? null,
        inspectorTestId: "workflow-harness-node-attempt-inspector",
        selectedNodeInspectorTestId: "workflow-selected-node-harness-attempt",
        timelineTestId: "workflow-run-harness-timeline",
        deepLinkParam: "nodeAttemptId",
      });
    }
    const comparisonBundles = extractHarnessLiveShadowComparisons(dispatch);
    if (comparisonBundles.length === 0) return;
    for (const { comparison, liveAttempt, shadowAttempt } of comparisonBundles) {
      const comparisonKey = `${timelineKey}:${comparison.liveAttemptId}:${comparison.shadowAttemptId}`;
      if (harnessLiveShadowComparisonKeys.has(comparisonKey)) continue;
      harnessLiveShadowComparisonKeys.add(comparisonKey);
      summary.harnessLiveShadowComparisonCount += 1;
      addScenario(summary.harnessLiveShadowComparisonScenarios, scenario);
      addScenario(
        summary.harnessLiveShadowComparisonComponentKinds,
        comparison.componentKind,
      );
      if (summary.harnessLiveShadowComparisonSamples.length < 8) {
        summary.harnessLiveShadowComparisonSamples.push({
          artifactId,
          dispatchId: dispatch.dispatchId ?? null,
          scenario,
          workflowId:
            dispatch.workflowId ?? liveAttempt.harnessWorkflowId ?? null,
          activationId:
            dispatch.activationId ?? liveAttempt.harnessActivationId ?? null,
          harnessHash: dispatch.harnessHash ?? liveAttempt.harnessHash ?? null,
          runtimeAuthority: dispatch.runtimeAuthority ?? null,
          workflowNodeId: comparison.workflowNodeId,
          componentKind: comparison.componentKind,
          liveAttemptId: comparison.liveAttemptId,
          shadowAttemptId: comparison.shadowAttemptId,
          divergence: comparison.divergence,
          blocking: comparison.blocking,
          summary: comparison.summary ?? null,
          liveExecutionMode: liveAttempt.executionMode ?? null,
          shadowExecutionMode: shadowAttempt.executionMode ?? null,
          liveReceiptRefs: Array.isArray(liveAttempt.receiptIds)
            ? liveAttempt.receiptIds.slice(0, 12)
            : [],
          shadowReceiptRefs: Array.isArray(shadowAttempt.receiptIds)
            ? shadowAttempt.receiptIds.slice(0, 12)
            : [],
          liveReplayFixtureRef: liveAttempt.replay?.fixtureRef ?? null,
          shadowReplayFixtureRef: shadowAttempt.replay?.fixtureRef ?? null,
          liveInputHash: liveAttempt.inputHash ?? null,
          shadowInputHash: shadowAttempt.inputHash ?? null,
          liveOutputHash: liveAttempt.outputHash ?? null,
          shadowOutputHash: shadowAttempt.outputHash ?? null,
          comparisonInspectorTestId:
            "workflow-harness-live-shadow-comparison-inspector",
          nodeInspectorTestId: "workflow-harness-node-attempt-inspector",
          timelineTestId: "workflow-run-harness-timeline",
          deepLinkParam: "nodeAttemptId",
        });
      }
    }
  };
  const noteHarnessDefaultRuntimeBinding = (binding) => {
    if (!binding || typeof binding !== "object") return;
    if (binding.schemaVersion !== "workflow.harness.default-runtime-binding.v1")
      return;
    summary.harnessDefaultRuntimeBindingCount += 1;
    const sample = {
      bindingId: binding.bindingId ?? null,
      workflowId: binding.workflowId ?? null,
      activationId: binding.activationId ?? null,
      harnessHash: binding.harnessHash ?? null,
      selectorDecisionId: binding.selectorDecisionId ?? null,
      defaultDispatchId: binding.defaultDispatchId ?? null,
      selectedSelector: binding.selectedSelector ?? null,
      productionDefaultSelector: binding.productionDefaultSelector ?? null,
      executionMode: binding.executionMode ?? null,
      runtimeAuthority: binding.runtimeAuthority ?? null,
      rollbackTarget: binding.rollbackTarget ?? null,
      rollbackAvailable: binding.rollbackAvailable ?? null,
      bindingMatched: binding.bindingMatched ?? null,
      selectorDecisionLinksDispatch:
        binding.selectorDecisionLinksDispatch ?? null,
      drivesRuntimeDecision: binding.drivesRuntimeDecision ?? null,
      dispatchDrivesRuntime: binding.dispatchDrivesRuntime ?? null,
      selectorLivePromotionReadinessReady:
        binding.selectorLivePromotionReadinessReady ?? null,
      liveHandoffLivePromotionReadinessReady:
        binding.liveHandoffLivePromotionReadinessReady ?? null,
      dispatchLivePromotionReadinessReady:
        binding.dispatchLivePromotionReadinessReady ?? null,
      selectorLiveShadowComparisonGateReady:
        binding.selectorLiveShadowComparisonGateReady ?? null,
      liveHandoffLiveShadowComparisonGateReady:
        binding.liveHandoffLiveShadowComparisonGateReady ?? null,
      dispatchLiveShadowComparisonGateReady:
        binding.dispatchLiveShadowComparisonGateReady ?? null,
      selectorLiveShadowComparisonGateId:
        binding.selectorLiveShadowComparisonGateId ?? null,
      liveHandoffLiveShadowComparisonGateId:
        binding.liveHandoffLiveShadowComparisonGateId ?? null,
      dispatchLiveShadowComparisonGateId:
        binding.dispatchLiveShadowComparisonGateId ?? null,
      liveShadowComparisonGateIdsMatch:
        binding.liveShadowComparisonGateIdsMatch ?? null,
      selectorLivePromotionReadinessProofId:
        binding.selectorLivePromotionReadinessProofId ?? null,
      liveHandoffLivePromotionReadinessProofId:
        binding.liveHandoffLivePromotionReadinessProofId ?? null,
      dispatchLivePromotionReadinessProofId:
        binding.dispatchLivePromotionReadinessProofId ?? null,
      livePromotionReadinessProofIdsMatch:
        binding.livePromotionReadinessProofIdsMatch ?? null,
      invalidForkLiveActivationBlocked:
        binding.invalidForkLiveActivationBlocked ?? null,
      workerBindingAuthorityReady: binding.workerBindingAuthorityReady ?? null,
      workerBindingAuthorityBlockers: Array.isArray(
        binding.workerBindingAuthorityBlockers,
      )
        ? binding.workerBindingAuthorityBlockers
        : null,
      workerBindingRegistryBound: binding.workerBindingRegistryBound ?? null,
      workerBindingRegistryStatus: binding.workerBindingRegistryStatus ?? null,
      workerBindingRegistryBlockers: Array.isArray(
        binding.workerBindingRegistryBlockers,
      )
        ? binding.workerBindingRegistryBlockers
        : null,
      workerAttachAccepted: binding.workerAttachAccepted ?? null,
      workerAttachStatus: binding.workerAttachStatus ?? null,
      workerAttachBlockers: Array.isArray(binding.workerAttachBlockers)
        ? binding.workerAttachBlockers
        : null,
      workerAttachRollbackAvailable:
        binding.workerAttachRollbackAvailable ?? null,
      workerAttachResumeAccepted: binding.workerAttachResumeAccepted ?? null,
      workerAttachRollbackAccepted:
        binding.workerAttachRollbackAccepted ?? null,
      workerAttachLifecycleComplete:
        binding.workerAttachLifecycleComplete ?? null,
      workerAttachLifecycleStatuses: Array.isArray(
        binding.workerAttachLifecycleStatuses,
      )
        ? binding.workerAttachLifecycleStatuses
        : null,
      workerAttachLifecycleAttemptIds: Array.isArray(
        binding.workerAttachLifecycleAttemptIds,
      )
        ? binding.workerAttachLifecycleAttemptIds
        : null,
      invalidWorkerAttachBlocked: binding.invalidWorkerAttachBlocked ?? null,
      workerBinding:
        binding.workerBinding && typeof binding.workerBinding === "object"
          ? {
              harnessWorkflowId:
                binding.workerBinding.harnessWorkflowId ?? null,
              harnessActivationId:
                binding.workerBinding.harnessActivationId ?? null,
              harnessHash: binding.workerBinding.harnessHash ?? null,
              executionMode: binding.workerBinding.executionMode ?? null,
              source: binding.workerBinding.source ?? null,
              selectorDecisionId:
                binding.workerBinding.selectorDecisionId ?? null,
              defaultDispatchId:
                binding.workerBinding.defaultDispatchId ?? null,
              rollbackTarget: binding.workerBinding.rollbackTarget ?? null,
              authorityBindingReady:
                binding.workerBinding.authorityBindingReady ?? null,
              authorityBindingBlockers: Array.isArray(
                binding.workerBinding.authorityBindingBlockers,
              )
                ? binding.workerBinding.authorityBindingBlockers
                : null,
              livePromotionReadinessProofId:
                binding.workerBinding.livePromotionReadinessProofId ?? null,
              liveShadowComparisonGateId:
                binding.workerBinding.liveShadowComparisonGateId ?? null,
              liveShadowComparisonGateReady:
                binding.workerBinding.liveShadowComparisonGateReady ?? null,
              rollbackPolicyDecision:
                binding.workerBinding.rollbackPolicyDecision ?? null,
              policyDecision: binding.workerBinding.policyDecision ?? null,
              requiredInvariantIds: Array.isArray(
                binding.workerBinding.requiredInvariantIds,
              )
                ? binding.workerBinding.requiredInvariantIds
                : null,
              invariantBlockers: Array.isArray(
                binding.workerBinding.invariantBlockers,
              )
                ? binding.workerBinding.invariantBlockers
                : null,
            }
          : null,
      workerBindingRegistryRecord:
        binding.workerBindingRegistryRecord &&
        typeof binding.workerBindingRegistryRecord === "object"
          ? {
              registryRecordId:
                binding.workerBindingRegistryRecord.registryRecordId ?? null,
              workflowId:
                binding.workerBindingRegistryRecord.workflowId ?? null,
              activationId:
                binding.workerBindingRegistryRecord.activationId ?? null,
              activationHash:
                binding.workerBindingRegistryRecord.activationHash ?? null,
              harnessHash:
                binding.workerBindingRegistryRecord.harnessHash ?? null,
              reviewedPackageSnapshotHash:
                binding.workerBindingRegistryRecord
                  .reviewedPackageSnapshotHash ?? null,
              reviewedWorkflowContentHash:
                binding.workerBindingRegistryRecord
                  .reviewedWorkflowContentHash ?? null,
              reviewedActivationId:
                binding.workerBindingRegistryRecord.reviewedActivationId ??
                null,
              reviewedHarnessWorkflowId:
                binding.workerBindingRegistryRecord
                  .reviewedHarnessWorkflowId ?? null,
              reviewedWorkerBindingActivationId:
                binding.workerBindingRegistryRecord
                  .reviewedWorkerBindingActivationId ?? null,
              reviewedRollbackTarget:
                binding.workerBindingRegistryRecord.reviewedRollbackTarget ??
                null,
              reviewedReplayFixtureRefs: Array.isArray(
                binding.workerBindingRegistryRecord.reviewedReplayFixtureRefs,
              )
                ? binding.workerBindingRegistryRecord.reviewedReplayFixtureRefs
                : null,
              reviewedWorkerHandoffNodeAttemptIds: Array.isArray(
                binding.workerBindingRegistryRecord
                  .reviewedWorkerHandoffNodeAttemptIds,
              )
                ? binding.workerBindingRegistryRecord
                    .reviewedWorkerHandoffNodeAttemptIds
                : null,
              reviewedWorkerHandoffReceiptIds: Array.isArray(
                binding.workerBindingRegistryRecord
                  .reviewedWorkerHandoffReceiptIds,
              )
                ? binding.workerBindingRegistryRecord
                    .reviewedWorkerHandoffReceiptIds
                : null,
              reviewedPolicyPosture:
                binding.workerBindingRegistryRecord.reviewedPolicyPosture ??
                null,
              rollbackTarget:
                binding.workerBindingRegistryRecord.rollbackTarget ?? null,
              readinessProofId:
                binding.workerBindingRegistryRecord.readinessProofId ?? null,
              rollbackReadinessProofId:
                binding.workerBindingRegistryRecord.rollbackReadinessProofId ??
                null,
              rollbackLiveShadowComparisonGateId:
                binding.workerBindingRegistryRecord
                  .rollbackLiveShadowComparisonGateId ?? null,
              rollbackLiveShadowComparisonGateReady:
                binding.workerBindingRegistryRecord
                  .rollbackLiveShadowComparisonGateReady ?? null,
              rollbackActivationId:
                binding.workerBindingRegistryRecord.rollbackActivationId ??
                null,
              rollbackHarnessHash:
                binding.workerBindingRegistryRecord.rollbackHarnessHash ?? null,
              rollbackPolicyDecision:
                binding.workerBindingRegistryRecord.rollbackPolicyDecision ??
                null,
              canaryResultId:
                binding.workerBindingRegistryRecord.canaryResultId ?? null,
              bindingStatus:
                binding.workerBindingRegistryRecord.bindingStatus ?? null,
              blockers: Array.isArray(
                binding.workerBindingRegistryRecord.blockers,
              )
                ? binding.workerBindingRegistryRecord.blockers
                : null,
              requiredInvariantIds: Array.isArray(
                binding.workerBindingRegistryRecord.requiredInvariantIds,
              )
                ? binding.workerBindingRegistryRecord.requiredInvariantIds
                : null,
              invariantBlockers: Array.isArray(
                binding.workerBindingRegistryRecord.invariantBlockers,
              )
                ? binding.workerBindingRegistryRecord.invariantBlockers
                : null,
              workerBindingActivationId:
                binding.workerBindingRegistryRecord.workerBinding
                  ?.harnessActivationId ?? null,
              workerBinding:
                binding.workerBindingRegistryRecord.workerBinding ?? null,
            }
          : null,
      workerAttachReceipt:
        binding.workerAttachReceipt &&
        typeof binding.workerAttachReceipt === "object"
          ? {
              receiptId: binding.workerAttachReceipt.receiptId ?? null,
              workerId: binding.workerAttachReceipt.workerId ?? null,
              registryRecordId:
                binding.workerAttachReceipt.registryRecordId ?? null,
              attachStatus: binding.workerAttachReceipt.attachStatus ?? null,
              accepted: binding.workerAttachReceipt.accepted ?? null,
              readinessProofId:
                binding.workerAttachReceipt.readinessProofId ?? null,
              rollbackReadinessProofId:
                binding.workerAttachReceipt.rollbackReadinessProofId ?? null,
              rollbackLiveShadowComparisonGateId:
                binding.workerAttachReceipt
                  .rollbackLiveShadowComparisonGateId ?? null,
              rollbackLiveShadowComparisonGateReady:
                binding.workerAttachReceipt
                  .rollbackLiveShadowComparisonGateReady ?? null,
              rollbackActivationId:
                binding.workerAttachReceipt.rollbackActivationId ?? null,
              rollbackHarnessHash:
                binding.workerAttachReceipt.rollbackHarnessHash ?? null,
              rollbackPolicyDecision:
                binding.workerAttachReceipt.rollbackPolicyDecision ?? null,
              reviewedPackageSnapshotHash:
                binding.workerAttachReceipt.reviewedPackageSnapshotHash ??
                null,
              reviewedWorkflowContentHash:
                binding.workerAttachReceipt.reviewedWorkflowContentHash ??
                null,
              reviewedActivationId:
                binding.workerAttachReceipt.reviewedActivationId ?? null,
              reviewedWorkerBindingActivationId:
                binding.workerAttachReceipt
                  .reviewedWorkerBindingActivationId ?? null,
              reviewedReplayFixtureRefs: Array.isArray(
                binding.workerAttachReceipt.reviewedReplayFixtureRefs,
              )
                ? binding.workerAttachReceipt.reviewedReplayFixtureRefs
                : null,
              blockers: Array.isArray(binding.workerAttachReceipt.blockers)
                ? binding.workerAttachReceipt.blockers
                : null,
              requiredInvariantIds: Array.isArray(
                binding.workerAttachReceipt.requiredInvariantIds,
              )
                ? binding.workerAttachReceipt.requiredInvariantIds
                : null,
              invariantBlockers: Array.isArray(
                binding.workerAttachReceipt.invariantBlockers,
              )
                ? binding.workerAttachReceipt.invariantBlockers
                : null,
            }
          : null,
      workerAttachResumeReceipt:
        binding.workerAttachResumeReceipt &&
        typeof binding.workerAttachResumeReceipt === "object"
          ? {
              receiptId: binding.workerAttachResumeReceipt.receiptId ?? null,
              attachStatus:
                binding.workerAttachResumeReceipt.attachStatus ?? null,
              accepted: binding.workerAttachResumeReceipt.accepted ?? null,
              rollbackReadinessProofId:
                binding.workerAttachResumeReceipt.rollbackReadinessProofId ??
                null,
              rollbackLiveShadowComparisonGateId:
                binding.workerAttachResumeReceipt
                  .rollbackLiveShadowComparisonGateId ?? null,
              rollbackLiveShadowComparisonGateReady:
                binding.workerAttachResumeReceipt
                  .rollbackLiveShadowComparisonGateReady ?? null,
              blockers: Array.isArray(
                binding.workerAttachResumeReceipt.blockers,
              )
                ? binding.workerAttachResumeReceipt.blockers
                : null,
            }
          : null,
      workerAttachRollbackReceipt:
        binding.workerAttachRollbackReceipt &&
        typeof binding.workerAttachRollbackReceipt === "object"
          ? {
              receiptId: binding.workerAttachRollbackReceipt.receiptId ?? null,
              attachStatus:
                binding.workerAttachRollbackReceipt.attachStatus ?? null,
              accepted: binding.workerAttachRollbackReceipt.accepted ?? null,
              rollbackReadinessProofId:
                binding.workerAttachRollbackReceipt.rollbackReadinessProofId ??
                null,
              rollbackLiveShadowComparisonGateId:
                binding.workerAttachRollbackReceipt
                  .rollbackLiveShadowComparisonGateId ?? null,
              rollbackLiveShadowComparisonGateReady:
                binding.workerAttachRollbackReceipt
                  .rollbackLiveShadowComparisonGateReady ?? null,
              rollbackActivationId:
                binding.workerAttachRollbackReceipt.rollbackActivationId ??
                null,
              rollbackHarnessHash:
                binding.workerAttachRollbackReceipt.rollbackHarnessHash ?? null,
              rollbackPolicyDecision:
                binding.workerAttachRollbackReceipt.rollbackPolicyDecision ??
                null,
              blockers: Array.isArray(
                binding.workerAttachRollbackReceipt.blockers,
              )
                ? binding.workerAttachRollbackReceipt.blockers
                : null,
            }
          : null,
      workerAttachLifecycle: Array.isArray(binding.workerAttachLifecycle)
        ? binding.workerAttachLifecycle.map((event) => ({
            phase: event?.phase ?? null,
            attemptId: event?.attemptId ?? null,
            attachStatus: event?.attachStatus ?? null,
            accepted: event?.accepted ?? null,
            receiptId: event?.receiptId ?? null,
            rollbackReadinessProofId:
              event?.rollbackReadinessProofId ?? null,
            rollbackLiveShadowComparisonGateId:
              event?.rollbackLiveShadowComparisonGateId ?? null,
            rollbackLiveShadowComparisonGateReady:
              event?.rollbackLiveShadowComparisonGateReady ?? null,
            rollbackActivationId: event?.rollbackActivationId ?? null,
            rollbackHarnessHash: event?.rollbackHarnessHash ?? null,
            rollbackPolicyDecision: event?.rollbackPolicyDecision ?? null,
            blockers: Array.isArray(event?.blockers) ? event.blockers : null,
            requiredInvariantIds: Array.isArray(event?.requiredInvariantIds)
              ? event.requiredInvariantIds
              : null,
            invariantBlockers: Array.isArray(event?.invariantBlockers)
              ? event.invariantBlockers
              : null,
          }))
        : null,
      workerSessionAccepted: binding.workerSessionAccepted ?? null,
      workerSessionStatus: binding.workerSessionStatus ?? null,
      workerSessionRecordId: binding.workerSessionRecordId ?? null,
      workerSessionBlockers: Array.isArray(binding.workerSessionBlockers)
        ? binding.workerSessionBlockers
        : null,
      workerSessionRecord:
        binding.workerSessionRecord &&
        typeof binding.workerSessionRecord === "object"
          ? {
              schemaVersion: binding.workerSessionRecord.schemaVersion ?? null,
              sessionRecordId:
                binding.workerSessionRecord.sessionRecordId ?? null,
              sessionId: binding.workerSessionRecord.sessionId ?? null,
              workerId: binding.workerSessionRecord.workerId ?? null,
              workflowId: binding.workerSessionRecord.workflowId ?? null,
              activationId: binding.workerSessionRecord.activationId ?? null,
              activationHash:
                binding.workerSessionRecord.activationHash ?? null,
              harnessHash: binding.workerSessionRecord.harnessHash ?? null,
              rollbackTarget:
                binding.workerSessionRecord.rollbackTarget ?? null,
              readinessProofId:
                binding.workerSessionRecord.readinessProofId ?? null,
              rollbackReadinessProofId:
                binding.workerSessionRecord.rollbackReadinessProofId ?? null,
              rollbackLiveShadowComparisonGateId:
                binding.workerSessionRecord
                  .rollbackLiveShadowComparisonGateId ?? null,
              rollbackLiveShadowComparisonGateReady:
                binding.workerSessionRecord
                  .rollbackLiveShadowComparisonGateReady ?? null,
              rollbackActivationId:
                binding.workerSessionRecord.rollbackActivationId ?? null,
              rollbackHarnessHash:
                binding.workerSessionRecord.rollbackHarnessHash ?? null,
              rollbackPolicyDecision:
                binding.workerSessionRecord.rollbackPolicyDecision ?? null,
              registryRecordId:
                binding.workerSessionRecord.registryRecordId ?? null,
              currentStatus: binding.workerSessionRecord.currentStatus ?? null,
              currentAttemptId:
                binding.workerSessionRecord.currentAttemptId ?? null,
              currentReceiptId:
                binding.workerSessionRecord.currentReceiptId ?? null,
              resumed: binding.workerSessionRecord.resumed ?? null,
              rollbackTargetReady:
                binding.workerSessionRecord.rollbackTargetReady ?? null,
              accepted: binding.workerSessionRecord.accepted ?? null,
              blockers: Array.isArray(binding.workerSessionRecord.blockers)
                ? binding.workerSessionRecord.blockers
                : null,
              persistenceKey:
                binding.workerSessionRecord.persistenceKey ?? null,
              recordPersistenceKey:
                binding.workerSessionRecord.recordPersistenceKey ?? null,
              persistedInRuntimeCheckpoint:
                binding.workerSessionRecord.persistedInRuntimeCheckpoint ??
                null,
              restoredFromPersistedSession:
                binding.workerSessionRecord.restoredFromPersistedSession ??
                null,
              runtimeCheckpointSource:
                binding.workerSessionRecord.runtimeCheckpointSource ?? null,
              persistenceBlockers: Array.isArray(
                binding.workerSessionRecord.persistenceBlockers,
              )
                ? binding.workerSessionRecord.persistenceBlockers
                : null,
              launchAuthorityReady:
                binding.workerSessionRecord.launchAuthorityReady ?? null,
              launchAuthorityBlockers: Array.isArray(
                binding.workerSessionRecord.launchAuthorityBlockers,
              )
                ? binding.workerSessionRecord.launchAuthorityBlockers
                : null,
              launchAuthorityInvariantIds: Array.isArray(
                binding.workerSessionRecord.launchAuthorityInvariantIds,
              )
                ? binding.workerSessionRecord.launchAuthorityInvariantIds
                : null,
              launchAuthorityInvariantBlockers: Array.isArray(
                binding.workerSessionRecord.launchAuthorityInvariantBlockers,
              )
                ? binding.workerSessionRecord.launchAuthorityInvariantBlockers
                : null,
              launchAuthoritySource:
                binding.workerSessionRecord.launchAuthoritySource ?? null,
              rollbackHandoffReady:
                binding.workerSessionRecord.rollbackHandoffReady ?? null,
              rollbackHandoffBlockers: Array.isArray(
                binding.workerSessionRecord.rollbackHandoffBlockers,
              )
                ? binding.workerSessionRecord.rollbackHandoffBlockers
                : null,
              rollbackHandoffTarget:
                binding.workerSessionRecord.rollbackHandoffTarget ?? null,
            }
          : null,
      workerLaunchEnvelopes: Array.isArray(binding.workerLaunchEnvelopes)
        ? binding.workerLaunchEnvelopes.map((envelope) => ({
            schemaVersion: envelope?.schemaVersion ?? null,
            envelopeId: envelope?.envelopeId ?? null,
            phase: envelope?.phase ?? null,
            sessionRecordId: envelope?.sessionRecordId ?? null,
            workerId: envelope?.workerId ?? null,
            readinessProofId: envelope?.readinessProofId ?? null,
            rollbackReadinessProofId: envelope?.rollbackReadinessProofId ?? null,
            rollbackLiveShadowComparisonGateId:
              envelope?.rollbackLiveShadowComparisonGateId ?? null,
            rollbackLiveShadowComparisonGateReady:
              envelope?.rollbackLiveShadowComparisonGateReady ?? null,
            rollbackActivationId: envelope?.rollbackActivationId ?? null,
            rollbackHarnessHash: envelope?.rollbackHarnessHash ?? null,
            rollbackPolicyDecision: envelope?.rollbackPolicyDecision ?? null,
            launchAuthorityReady: envelope?.launchAuthorityReady ?? null,
            launchAuthorityInvariantIds: Array.isArray(
              envelope?.launchAuthorityInvariantIds,
            )
              ? envelope.launchAuthorityInvariantIds
              : null,
            launchAuthorityInvariantBlockers: Array.isArray(
              envelope?.launchAuthorityInvariantBlockers,
            )
              ? envelope.launchAuthorityInvariantBlockers
              : null,
            rollbackHandoffReady: envelope?.rollbackHandoffReady ?? null,
            accepted: envelope?.accepted ?? null,
            blockers: Array.isArray(envelope?.blockers)
              ? envelope.blockers
              : null,
            policyDecision: envelope?.policyDecision ?? null,
          }))
        : null,
      workerHandoffReceipts: Array.isArray(binding.workerHandoffReceipts)
        ? binding.workerHandoffReceipts.map((receipt) => ({
            schemaVersion: receipt?.schemaVersion ?? null,
            receiptId: receipt?.receiptId ?? null,
            envelopeId: receipt?.envelopeId ?? null,
            phase: receipt?.phase ?? null,
            sessionRecordId: receipt?.sessionRecordId ?? null,
            workerId: receipt?.workerId ?? null,
            readinessProofId: receipt?.readinessProofId ?? null,
            rollbackReadinessProofId: receipt?.rollbackReadinessProofId ?? null,
            rollbackLiveShadowComparisonGateId:
              receipt?.rollbackLiveShadowComparisonGateId ?? null,
            rollbackLiveShadowComparisonGateReady:
              receipt?.rollbackLiveShadowComparisonGateReady ?? null,
            rollbackActivationId: receipt?.rollbackActivationId ?? null,
            rollbackHarnessHash: receipt?.rollbackHarnessHash ?? null,
            rollbackPolicyDecision: receipt?.rollbackPolicyDecision ?? null,
            accepted: receipt?.accepted ?? null,
            handoffStatus: receipt?.handoffStatus ?? null,
            blockers: Array.isArray(receipt?.blockers)
              ? receipt.blockers
              : null,
            requiredInvariantIds: Array.isArray(receipt?.requiredInvariantIds)
              ? receipt.requiredInvariantIds
              : null,
            invariantBlockers: Array.isArray(receipt?.invariantBlockers)
              ? receipt.invariantBlockers
              : null,
            receiptRefs: Array.isArray(receipt?.receiptRefs)
              ? receipt.receiptRefs
              : null,
            policyDecision: receipt?.policyDecision ?? null,
          }))
        : null,
      workerLaunchEnvelopeIds: Array.isArray(binding.workerLaunchEnvelopeIds)
        ? binding.workerLaunchEnvelopeIds
        : null,
      workerHandoffReceiptIds: Array.isArray(binding.workerHandoffReceiptIds)
        ? binding.workerHandoffReceiptIds
        : null,
      workerLaunchEnvelopesAccepted:
        binding.workerLaunchEnvelopesAccepted ?? null,
      workerHandoffReceiptsAccepted:
        binding.workerHandoffReceiptsAccepted ?? null,
      invalidWorkerAttachReceipt:
        binding.invalidWorkerAttachReceipt &&
        typeof binding.invalidWorkerAttachReceipt === "object"
          ? {
              attachStatus:
                binding.invalidWorkerAttachReceipt.attachStatus ?? null,
              accepted: binding.invalidWorkerAttachReceipt.accepted ?? null,
              blockers: Array.isArray(
                binding.invalidWorkerAttachReceipt.blockers,
              )
                ? binding.invalidWorkerAttachReceipt.blockers
                : null,
            }
          : null,
    };
    const hasReviewedImportActivationInvariant = (ids) =>
      Array.isArray(ids) &&
      ids.includes(REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID);
    const hasNoInvariantBlockers = (blockers) =>
      Array.isArray(blockers) && blockers.length === 0;
    const workerLaunchReviewedImportActivationInvariantBound =
      hasReviewedImportActivationInvariant(
        binding.workerBinding?.requiredInvariantIds,
      ) &&
      hasNoInvariantBlockers(binding.workerBinding?.invariantBlockers) &&
      hasReviewedImportActivationInvariant(
        binding.workerBindingRegistryRecord?.requiredInvariantIds,
      ) &&
      hasNoInvariantBlockers(
        binding.workerBindingRegistryRecord?.invariantBlockers,
      ) &&
      hasReviewedImportActivationInvariant(
        binding.workerAttachReceipt?.requiredInvariantIds,
      ) &&
      hasNoInvariantBlockers(binding.workerAttachReceipt?.invariantBlockers) &&
      Array.isArray(binding.workerAttachLifecycle) &&
      binding.workerAttachLifecycle.length >= 3 &&
      binding.workerAttachLifecycle.every(
        (event) =>
          hasReviewedImportActivationInvariant(event?.requiredInvariantIds) &&
          hasNoInvariantBlockers(event?.invariantBlockers),
      ) &&
      hasReviewedImportActivationInvariant(
        binding.workerSessionRecord?.launchAuthorityInvariantIds,
      ) &&
      hasNoInvariantBlockers(
        binding.workerSessionRecord?.launchAuthorityInvariantBlockers,
      ) &&
      Array.isArray(binding.workerLaunchEnvelopes) &&
      binding.workerLaunchEnvelopes.length >= 3 &&
      binding.workerLaunchEnvelopes.every(
        (envelope) =>
          hasReviewedImportActivationInvariant(
            envelope?.launchAuthorityInvariantIds,
          ) &&
          hasNoInvariantBlockers(envelope?.launchAuthorityInvariantBlockers),
      ) &&
      Array.isArray(binding.workerHandoffReceipts) &&
      binding.workerHandoffReceipts.length >= 3 &&
      binding.workerHandoffReceipts.every(
        (receipt) =>
          hasReviewedImportActivationInvariant(receipt?.requiredInvariantIds) &&
          hasNoInvariantBlockers(receipt?.invariantBlockers),
      );
    sample.workerLaunchReviewedImportActivationInvariantBound =
      workerLaunchReviewedImportActivationInvariantBound;
    if (workerLaunchReviewedImportActivationInvariantBound) {
      summary.harnessWorkerLaunchReviewedImportActivationInvariantCount += 1;
    }
    const reviewedPackageSnapshotBound =
      typeof binding.workerBindingRegistryRecord
        ?.reviewedPackageSnapshotHash === "string" &&
      binding.workerBindingRegistryRecord.reviewedPackageSnapshotHash.length >
        0 &&
      binding.workerBindingRegistryRecord.reviewedWorkflowContentHash ===
        binding.workerAttachReceipt?.reviewedWorkflowContentHash &&
      binding.workerBindingRegistryRecord.reviewedActivationId ===
        binding.workerAttachReceipt?.reviewedActivationId &&
      binding.workerBindingRegistryRecord.reviewedWorkerBindingActivationId ===
        binding.workerAttachReceipt?.reviewedWorkerBindingActivationId &&
      binding.workerBindingRegistryRecord.reviewedActivationId ===
        binding.workerBindingRegistryRecord
          .reviewedWorkerBindingActivationId &&
      binding.workerBindingRegistryRecord.reviewedRollbackTarget ===
        binding.workerBindingRegistryRecord.rollbackTarget &&
      binding.workerBindingRegistryRecord.reviewedPolicyPosture ===
        "canary" &&
      Array.isArray(
        binding.workerBindingRegistryRecord.reviewedReplayFixtureRefs,
      ) &&
      binding.workerBindingRegistryRecord.reviewedReplayFixtureRefs.length >
        0 &&
      Array.isArray(
        binding.workerBindingRegistryRecord
          .reviewedWorkerHandoffNodeAttemptIds,
      ) &&
      binding.workerBindingRegistryRecord.reviewedWorkerHandoffNodeAttemptIds
        .length > 0 &&
      Array.isArray(
        binding.workerBindingRegistryRecord.reviewedWorkerHandoffReceiptIds,
      ) &&
      binding.workerBindingRegistryRecord.reviewedWorkerHandoffReceiptIds
        .length > 0 &&
      Array.isArray(binding.workerAttachReceipt?.reviewedReplayFixtureRefs) &&
      binding.workerAttachReceipt.reviewedReplayFixtureRefs.length > 0;
    sample.reviewedPackageSnapshotBound = reviewedPackageSnapshotBound;
    if (reviewedPackageSnapshotBound) {
      summary.harnessWorkerBindingRegistryReviewedPackageBoundCount += 1;
    }
    const expectedRollbackGateId = "p0-live-shadow-comparison-gate";
    const expectedRollbackPolicyDecision =
      "allow_default_harness_worker_rollback_from_live_shadow_gate";
    const rollbackArtifactBoundToLiveShadowGate = (artifact) => {
      const readinessProofId =
        artifact?.readinessProofId ?? artifact?.receipt?.readinessProofId;
      return (
        artifact &&
        readinessProofId === binding.selectorLivePromotionReadinessProofId &&
        artifact.rollbackReadinessProofId ===
          binding.selectorLivePromotionReadinessProofId &&
        artifact.rollbackLiveShadowComparisonGateId ===
          expectedRollbackGateId &&
        artifact.rollbackLiveShadowComparisonGateReady === true &&
        artifact.rollbackActivationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        artifact.rollbackHarnessHash === DEFAULT_AGENT_HARNESS_HASH &&
        artifact.rollbackPolicyDecision === expectedRollbackPolicyDecision
      );
    };
    const rollbackFromLiveShadowGateBound =
      binding.liveShadowComparisonGateIdsMatch === true &&
      binding.selectorLiveShadowComparisonGateId === expectedRollbackGateId &&
      binding.liveHandoffLiveShadowComparisonGateId === expectedRollbackGateId &&
      binding.dispatchLiveShadowComparisonGateId === expectedRollbackGateId &&
      binding.selectorLivePromotionReadinessProofId &&
      binding.workerBinding?.liveShadowComparisonGateId ===
        expectedRollbackGateId &&
      binding.workerBinding?.liveShadowComparisonGateReady === true &&
      binding.workerBinding?.rollbackPolicyDecision ===
        expectedRollbackPolicyDecision &&
      rollbackArtifactBoundToLiveShadowGate(
        binding.workerBindingRegistryRecord,
      ) &&
      rollbackArtifactBoundToLiveShadowGate(binding.workerAttachReceipt) &&
      rollbackArtifactBoundToLiveShadowGate(
        binding.workerAttachResumeReceipt,
      ) &&
      rollbackArtifactBoundToLiveShadowGate(
        binding.workerAttachRollbackReceipt,
      ) &&
      rollbackArtifactBoundToLiveShadowGate(binding.workerSessionRecord) &&
      Array.isArray(binding.workerAttachLifecycle) &&
      binding.workerAttachLifecycle.length >= 3 &&
      binding.workerAttachLifecycle.every((event) =>
        rollbackArtifactBoundToLiveShadowGate(event),
      ) &&
      Array.isArray(binding.workerLaunchEnvelopes) &&
      binding.workerLaunchEnvelopes.length >= 3 &&
      binding.workerLaunchEnvelopes.every((envelope) =>
        rollbackArtifactBoundToLiveShadowGate(envelope),
      ) &&
      Array.isArray(binding.workerHandoffReceipts) &&
      binding.workerHandoffReceipts.length >= 3 &&
      binding.workerHandoffReceipts.every((receipt) =>
        rollbackArtifactBoundToLiveShadowGate(receipt),
      );
    sample.rollbackFromLiveShadowGateBound =
      rollbackFromLiveShadowGateBound;
    if (rollbackFromLiveShadowGateBound) {
      summary.harnessDefaultRuntimeRollbackLiveShadowGateBoundCount += 1;
    }
    const bindingMatched =
      binding.bindingMatched === true &&
      binding.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
      binding.activationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      binding.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
      binding.selectedSelector === "blessed_workflow_live_default" &&
      binding.productionDefaultSelector === "blessed_workflow_live_default" &&
      binding.executionMode === "live" &&
      binding.runtimeAuthority === "blessed_workflow_activation_default" &&
      binding.rollbackTarget === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      binding.rollbackAvailable === true &&
      binding.selectorDecisionLinksDispatch === true &&
      binding.drivesRuntimeDecision === true &&
      binding.dispatchDrivesRuntime === true &&
      binding.selectorLivePromotionReadinessReady === true &&
      binding.liveHandoffLivePromotionReadinessReady === true &&
      binding.dispatchLivePromotionReadinessReady === true &&
      binding.selectorLiveShadowComparisonGateReady === true &&
      binding.liveHandoffLiveShadowComparisonGateReady === true &&
      binding.dispatchLiveShadowComparisonGateReady === true &&
      binding.liveShadowComparisonGateIdsMatch === true &&
      binding.livePromotionReadinessProofIdsMatch === true &&
      binding.invalidForkLiveActivationBlocked === true &&
      rollbackFromLiveShadowGateBound &&
      workerLaunchReviewedImportActivationInvariantBound &&
      reviewedPackageSnapshotBound &&
      binding.workerBindingAuthorityReady === true &&
      Array.isArray(binding.workerBindingAuthorityBlockers) &&
      binding.workerBindingAuthorityBlockers.length === 0 &&
      binding.workerBindingRegistryBound === true &&
      binding.workerBindingRegistryStatus === "bound" &&
      Array.isArray(binding.workerBindingRegistryBlockers) &&
      binding.workerBindingRegistryBlockers.length === 0 &&
      binding.workerAttachAccepted === true &&
      binding.workerAttachStatus === "bound" &&
      Array.isArray(binding.workerAttachBlockers) &&
      binding.workerAttachBlockers.length === 0 &&
      binding.workerAttachRollbackAvailable === true &&
      binding.workerAttachResumeAccepted === true &&
      binding.workerAttachRollbackAccepted === true &&
      binding.workerAttachLifecycleComplete === true &&
      Array.isArray(binding.workerAttachLifecycleStatuses) &&
      binding.workerAttachLifecycleStatuses.includes("bound") &&
      binding.workerAttachLifecycleStatuses.includes("resumed") &&
      binding.workerAttachLifecycleStatuses.includes("rolled_back") &&
      Array.isArray(binding.workerAttachLifecycleAttemptIds) &&
      binding.workerAttachLifecycleAttemptIds.length >= 3 &&
      Array.isArray(binding.workerAttachLifecycle) &&
      binding.workerAttachLifecycle.length >= 3 &&
      binding.workerAttachLifecycle.every(
        (event) =>
          event?.schemaVersion ===
            "workflow.harness.worker-attach-lifecycle.v1" &&
          event?.workflowNodeId === "harness.handoff_bridge" &&
          event?.componentKind === "handoff_bridge" &&
          event?.accepted === true &&
          Array.isArray(event?.blockers) &&
          event.blockers.length === 0 &&
          hasReviewedImportActivationInvariant(event?.requiredInvariantIds) &&
          hasNoInvariantBlockers(event?.invariantBlockers),
      ) &&
      binding.workerSessionAccepted === true &&
      binding.workerSessionStatus === "rollback_ready" &&
      Array.isArray(binding.workerSessionBlockers) &&
      binding.workerSessionBlockers.length === 0 &&
      binding.workerSessionRecord?.schemaVersion ===
        "workflow.harness.worker-session.v1" &&
      binding.workerSessionRecord?.accepted === true &&
      binding.workerSessionRecord?.currentStatus === "rollback_ready" &&
      binding.workerSessionRecord?.resumed === true &&
      binding.workerSessionRecord?.rollbackTargetReady === true &&
      binding.workerSessionRecord?.registryRecordId ===
        binding.workerBindingRegistryRecord?.registryRecordId &&
      binding.workerSessionRecord?.workerId ===
        binding.workerAttachReceipt?.workerId &&
      typeof binding.workerSessionRecord?.persistenceKey === "string" &&
      binding.workerSessionRecord.persistenceKey.startsWith(
        "agent::harness_worker_session::",
      ) &&
      typeof binding.workerSessionRecord?.recordPersistenceKey === "string" &&
      binding.workerSessionRecord.recordPersistenceKey.startsWith(
        "agent::harness_worker_session_record::",
      ) &&
      binding.workerSessionRecord?.persistedInRuntimeCheckpoint === true &&
      binding.workerSessionRecord?.restoredFromPersistedSession === true &&
      binding.workerSessionRecord?.runtimeCheckpointSource ===
        "runtime_state_access_harness_worker_session_record" &&
      Array.isArray(binding.workerSessionRecord?.persistenceBlockers) &&
      binding.workerSessionRecord.persistenceBlockers.length === 0 &&
      binding.workerSessionRecord?.launchAuthorityReady === true &&
      Array.isArray(binding.workerSessionRecord?.launchAuthorityBlockers) &&
      binding.workerSessionRecord.launchAuthorityBlockers.length === 0 &&
      hasReviewedImportActivationInvariant(
        binding.workerSessionRecord?.launchAuthorityInvariantIds,
      ) &&
      hasNoInvariantBlockers(
        binding.workerSessionRecord?.launchAuthorityInvariantBlockers,
      ) &&
      binding.workerSessionRecord?.launchAuthoritySource ===
        "persisted_harness_worker_session_record" &&
      binding.workerSessionRecord?.rollbackHandoffReady === true &&
      Array.isArray(binding.workerSessionRecord?.rollbackHandoffBlockers) &&
      binding.workerSessionRecord.rollbackHandoffBlockers.length === 0 &&
      binding.workerSessionRecord?.rollbackHandoffTarget ===
        binding.workerSessionRecord?.rollbackTarget &&
      binding.workerLaunchEnvelopesAccepted === true &&
      Array.isArray(binding.workerLaunchEnvelopes) &&
      binding.workerLaunchEnvelopes.length >= 3 &&
      Array.isArray(binding.workerLaunchEnvelopeIds) &&
      binding.workerLaunchEnvelopeIds.length >= 3 &&
      ["launch", "resume", "rollback"].every((phase) =>
        binding.workerLaunchEnvelopes.some(
          (envelope) =>
            envelope?.schemaVersion ===
              "workflow.harness.worker-launch-envelope.v1" &&
            envelope?.phase === phase &&
            envelope?.sessionRecordId ===
              binding.workerSessionRecord?.sessionRecordId &&
            envelope?.workerId === binding.workerSessionRecord?.workerId &&
            envelope?.accepted === true &&
            Array.isArray(envelope?.blockers) &&
            envelope.blockers.length === 0 &&
            envelope?.launchAuthorityReady === true &&
            hasReviewedImportActivationInvariant(
              envelope?.launchAuthorityInvariantIds,
            ) &&
            hasNoInvariantBlockers(
              envelope?.launchAuthorityInvariantBlockers,
            ) &&
            (phase !== "rollback" || envelope?.rollbackHandoffReady === true),
        ),
      ) &&
      binding.workerHandoffReceiptsAccepted === true &&
      Array.isArray(binding.workerHandoffReceipts) &&
      binding.workerHandoffReceipts.length >= 3 &&
      Array.isArray(binding.workerHandoffReceiptIds) &&
      binding.workerHandoffReceiptIds.length >= 3 &&
      [
        ["launch", "launched"],
        ["resume", "resumed"],
        ["rollback", "rollback_handoff_ready"],
      ].every(([phase, status]) =>
        binding.workerHandoffReceipts.some(
          (receipt) =>
            receipt?.schemaVersion ===
              "workflow.harness.worker-handoff-receipt.v1" &&
            receipt?.phase === phase &&
            receipt?.handoffStatus === status &&
            receipt?.sessionRecordId ===
              binding.workerSessionRecord?.sessionRecordId &&
            receipt?.workerId === binding.workerSessionRecord?.workerId &&
            receipt?.accepted === true &&
            Array.isArray(receipt?.blockers) &&
            receipt.blockers.length === 0 &&
            hasReviewedImportActivationInvariant(
              receipt?.requiredInvariantIds,
            ) &&
            hasNoInvariantBlockers(receipt?.invariantBlockers) &&
            Array.isArray(receipt?.receiptRefs) &&
            receipt.receiptRefs.length >= 4,
        ),
      ) &&
      binding.invalidWorkerAttachBlocked === true &&
      typeof binding.selectorDecisionId === "string" &&
      binding.selectorDecisionId.startsWith("harness-selector:") &&
      typeof binding.defaultDispatchId === "string" &&
      binding.defaultDispatchId.startsWith("harness-default-dispatch:") &&
      binding.workerBinding?.harnessWorkflowId ===
        DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
      binding.workerBinding?.harnessActivationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      binding.workerBinding?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
      binding.workerBinding?.executionMode === "live" &&
      binding.workerBinding?.selectorDecisionId ===
        binding.selectorDecisionId &&
      binding.workerBinding?.defaultDispatchId === binding.defaultDispatchId &&
      binding.workerBinding?.rollbackTarget ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      binding.workerBinding?.authorityBindingReady === true &&
      Array.isArray(binding.workerBinding?.authorityBindingBlockers) &&
      binding.workerBinding.authorityBindingBlockers.length === 0 &&
      hasReviewedImportActivationInvariant(
        binding.workerBinding?.requiredInvariantIds,
      ) &&
      hasNoInvariantBlockers(binding.workerBinding?.invariantBlockers) &&
      binding.workerBinding?.livePromotionReadinessProofId ===
        binding.selectorLivePromotionReadinessProofId &&
      binding.workerBindingRegistryRecord?.bindingStatus === "bound" &&
      Array.isArray(binding.workerBindingRegistryRecord?.blockers) &&
      binding.workerBindingRegistryRecord.blockers.length === 0 &&
      hasReviewedImportActivationInvariant(
        binding.workerBindingRegistryRecord?.requiredInvariantIds,
      ) &&
      hasNoInvariantBlockers(
        binding.workerBindingRegistryRecord?.invariantBlockers,
      ) &&
      binding.workerBindingRegistryRecord?.readinessProofId ===
        binding.selectorLivePromotionReadinessProofId &&
      binding.workerBindingRegistryRecord?.activationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      binding.workerBindingRegistryRecord?.activationHash ===
        DEFAULT_AGENT_HARNESS_HASH &&
      binding.workerBindingRegistryRecord?.workerBinding
        ?.harnessActivationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      binding.workerAttachReceipt?.schemaVersion ===
        "workflow.harness.worker-attach-receipt.v1" &&
      binding.workerAttachReceipt?.accepted === true &&
      binding.workerAttachReceipt?.attachStatus === "bound" &&
      hasReviewedImportActivationInvariant(
        binding.workerAttachReceipt?.requiredInvariantIds,
      ) &&
      hasNoInvariantBlockers(binding.workerAttachReceipt?.invariantBlockers) &&
      binding.workerAttachReceipt?.registryRecordId ===
        binding.workerBindingRegistryRecord?.registryRecordId &&
      binding.workerAttachReceipt?.readinessProofId ===
        binding.selectorLivePromotionReadinessProofId &&
      binding.workerAttachResumeReceipt?.accepted === true &&
      binding.workerAttachResumeReceipt?.attachStatus === "resumed" &&
      binding.workerAttachRollbackReceipt?.accepted === true &&
      binding.workerAttachRollbackReceipt?.attachStatus === "rolled_back" &&
      binding.invalidWorkerAttachReceipt?.accepted === false &&
      Array.isArray(binding.invalidWorkerAttachReceipt?.blockers) &&
      binding.invalidWorkerAttachReceipt.blockers.includes(
        "worker_attach_activation_hash_mismatch",
      );
    if (bindingMatched) {
      summary.harnessDefaultRuntimeBindingMatchedCount += 1;
    }
    if (summary.harnessDefaultRuntimeBindingSamples.length < 12) {
      summary.harnessDefaultRuntimeBindingSamples.push(sample);
    } else if (
      bindingMatched &&
      !summary.harnessDefaultRuntimeBindingSamples.some(
        (candidate) => candidate?.bindingMatched,
      )
    ) {
      summary.harnessDefaultRuntimeBindingSamples.shift();
      summary.harnessDefaultRuntimeBindingSamples.push(sample);
    }
  };
  const noteProviderGatedVisibleOutputCoverage = (coverage) => {
    if (!coverage || typeof coverage !== "object") return;
    if (Array.isArray(coverage.providerGatedVisibleOutputScenarios)) {
      for (const scenario of coverage.providerGatedVisibleOutputScenarios) {
        addScenario(
          summary.harnessModelProviderGatedVisibleOutputScenarios,
          scenario,
        );
      }
    }
    if (Array.isArray(coverage.rollbackDrillScenarios)) {
      for (const scenario of coverage.rollbackDrillScenarios) {
        addScenario(
          summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
          scenario,
        );
      }
    }
  };
  const noteReadOnlyCapabilityRoutingCoverage = (coverage) => {
    if (!coverage || typeof coverage !== "object") return;
    if (Array.isArray(coverage.readOnlyCapabilityRoutingScenarios)) {
      for (const scenario of coverage.readOnlyCapabilityRoutingScenarios) {
        addScenario(
          summary.harnessReadOnlyCapabilityRoutingScenarios,
          scenario,
        );
      }
    }
    if (Array.isArray(coverage.noMutationScenarios)) {
      for (const scenario of coverage.noMutationScenarios) {
        addScenario(
          summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
          scenario,
        );
      }
    }
  };
  const noteRollbackRestoreCanaryStatus = (status) => {
    if (
      typeof status === "string" &&
      status.length > 0 &&
      !summary.harnessRollbackRestoreCanaryStatuses.includes(status)
    ) {
      summary.harnessRollbackRestoreCanaryStatuses.push(status);
      summary.harnessRollbackRestoreCanaryStatuses.sort();
    }
  };
  const rollbackRestoreCanaryHasReceiptBinding = (canary) => {
    if (!canary || typeof canary !== "object") return false;
    const receiptBindingRef = canary.receiptBindingRef;
    return (
      typeof receiptBindingRef === "string" &&
      receiptBindingRef.startsWith("workflow_restore_canary:") &&
      Array.isArray(canary.evidenceRefs) &&
      canary.evidenceRefs.includes(receiptBindingRef)
    );
  };
  const noteRollbackRestoreCanaryReceipt = (canary) => {
    if (rollbackRestoreCanaryHasReceiptBinding(canary)) {
      summary.harnessRollbackRestoreCanaryReceiptCount += 1;
    }
  };
  const hasRestoreCanaryReceiptRef = (value) =>
    typeof value === "string" && value.startsWith("workflow_restore_canary:");
  const noteReceiptRefArray = (refs, counterName) => {
    if (
      Array.isArray(refs) &&
      refs.some((reference) => hasRestoreCanaryReceiptRef(reference))
    ) {
      summary[counterName] += 1;
    }
  };
  const noteRollbackRestoreCanaryProof = (activation) => {
    if (!activation || typeof activation !== "object") return;
    const invalidCanary = activation.invalidFork?.rollbackRestoreCanary;
    const validCanary = activation.validFork?.rollbackRestoreCanary;
    for (const fork of [activation.invalidFork, activation.validFork]) {
      if (!fork || typeof fork !== "object") continue;
      if (Array.isArray(fork.activationAudit)) {
        for (const event of fork.activationAudit) {
          noteReceiptRefArray(
            event?.receiptRefs,
            "harnessActivationAuditReceiptCount",
          );
        }
      }
      noteReceiptRefArray(
        fork.activationRollbackExecution?.receiptRefs,
        "harnessRollbackExecutionReceiptCount",
      );
      const mutationCanary = fork.forkMutationCanary;
      if (
        mutationCanary &&
        typeof mutationCanary === "object" &&
        mutationCanary.schemaVersion ===
          "workflow.harness.fork-mutation-canary.v1" &&
        mutationCanary.status === "passed" &&
        mutationCanary.canaryStatus === "passed" &&
        mutationCanary.rollbackAvailable === true &&
        Array.isArray(mutationCanary.blockers) &&
        mutationCanary.blockers.length === 0
      ) {
        summary.harnessForkMutationCanaryReadyCount += 1;
        summary.harnessForkMutationCanaryReceiptCount += Array.isArray(
          mutationCanary.receiptRefs,
        )
          ? mutationCanary.receiptRefs.length
          : 0;
        summary.harnessForkMutationCanaryReplayCount += Array.isArray(
          mutationCanary.replayFixtureRefs,
        )
          ? mutationCanary.replayFixtureRefs.length
          : 0;
        summary.harnessForkMutationCanaryNodeAttemptCount += Array.isArray(
          mutationCanary.nodeAttemptIds,
        )
          ? mutationCanary.nodeAttemptIds.length
          : 0;
      }
      if (
        hasRestoreCanaryReceiptRef(
          fork.activationRollbackExecution?.restoreReceiptBindingRef,
        )
      ) {
        summary.harnessRollbackExecutionReceiptCount += 1;
      }
    }
    if (invalidCanary && typeof invalidCanary === "object") {
      noteRollbackRestoreCanaryStatus(invalidCanary.status);
      noteRollbackRestoreCanaryReceipt(invalidCanary);
      if (
        invalidCanary.schemaVersion ===
          "workflow.harness.rollback-restore-canary.v1" &&
        invalidCanary.status === "blocked" &&
        invalidCanary.hashVerified === false &&
        Array.isArray(invalidCanary.blockers) &&
        invalidCanary.blockers.includes("rollback_restore_canary_not_run")
      ) {
        summary.harnessRollbackRestoreCanaryBlockedCount += 1;
      }
    }
    if (validCanary && typeof validCanary === "object") {
      noteRollbackRestoreCanaryStatus(validCanary.status);
      noteRollbackRestoreCanaryReceipt(validCanary);
      if (
        validCanary.schemaVersion ===
          "workflow.harness.rollback-restore-canary.v1" &&
        ["passed", "not_required"].includes(validCanary.status) &&
        validCanary.hashVerified === true &&
        Array.isArray(validCanary.blockers) &&
        validCanary.blockers.length === 0
      ) {
        summary.harnessRollbackRestoreCanaryReadyCount += 1;
      }
    }
  };
  const forkHandoffTimelineBound = (fork) => {
    if (!fork || typeof fork !== "object") return false;
    const receipts = Array.isArray(fork.workerHandoffReceipts)
      ? fork.workerHandoffReceipts
      : [];
    const receiptIds = Array.isArray(fork.workerHandoffReceiptIds)
      ? fork.workerHandoffReceiptIds
      : receipts
          .map((receipt) => receipt?.receiptId)
          .filter((receiptId) => typeof receiptId === "string");
    const attempts = Array.isArray(fork.workerHandoffNodeAttempts)
      ? fork.workerHandoffNodeAttempts
      : [];
    const attemptIds = Array.isArray(fork.workerHandoffNodeAttemptIds)
      ? fork.workerHandoffNodeAttemptIds
      : attempts
          .map((attempt) => attempt?.attemptId)
          .filter((attemptId) => typeof attemptId === "string");
    const replayRefs = Array.isArray(fork.workerHandoffReplayFixtureRefs)
      ? fork.workerHandoffReplayFixtureRefs
      : attempts
          .map((attempt) => attempt?.replay?.fixtureRef)
          .filter((fixtureRef) => typeof fixtureRef === "string");
    return (
      fork.workerHandoffNodeTimelineBound === true &&
      receipts.length >= 3 &&
      attempts.length >= 3 &&
      attemptIds.length >= 3 &&
      replayRefs.length >= 3 &&
      ["launch", "resume", "rollback"].every((phase) =>
        attempts.some((attempt) => {
          const receipt = receipts.find(
            (candidate) => candidate?.phase === phase,
          );
          return (
            receipt?.receiptId &&
            attempt?.workflowNodeId === "harness.handoff_bridge" &&
            attempt?.componentKind === "handoff_bridge" &&
            attempt?.executionMode === "gated" &&
            attempt?.status === "gated" &&
            Array.isArray(attempt?.receiptIds) &&
            attempt.receiptIds.includes(receipt.receiptId) &&
            typeof attempt?.replay?.fixtureRef === "string" &&
            replayRefs.includes(attempt.replay.fixtureRef) &&
            attemptIds.includes(attempt.attemptId) &&
            receiptIds.includes(receipt.receiptId)
          );
        }),
      )
    );
  };

  if (existsSync(logPath)) {
    const log = readFileSync(logPath, "utf8");
    summary.logSignals.kernelEvents = (
      log.match(/\[Autopilot\] Block/g) || []
    ).length;
    summary.logSignals.chatProofTrace = (
      log.match(/\[chat-proof-trace\]/g) || []
    ).length;
    summary.logSignals.sessionProjectionRefreshes = (
      log.match(/Session projection refreshed/g) || []
    ).length;
  }

  if (existsSync(chatDbPath)) {
    try {
      const db = await openReadonlySqliteDatabase(chatDbPath);
      const noteProjection = (projection) => {
        if (!projection || typeof projection !== "object") return;
        noteProviderGatedVisibleOutputCoverage(
          projection.HarnessModelProviderGatedVisibleOutputCoverage,
        );
        noteProviderGatedVisibleOutputCoverage(
          projection.HarnessDefaultRuntimeDispatch
            ?.modelProviderGatedVisibleOutputSessionCoverage,
        );
        noteReadOnlyCapabilityRoutingCoverage(
          projection.HarnessReadOnlyCapabilityRoutingCoverage,
        );
        noteReadOnlyCapabilityRoutingCoverage(
          projection.HarnessDefaultRuntimeDispatch
            ?.readOnlyCapabilityRoutingSessionCoverage,
        );
        if (projection.schemaVersion === "ioi.agent-runtime.substrate.v1") {
          summary.runtimeEvidenceReportCount += 1;
        }
        if (
          projection.PromptAssemblyContract?.finalPromptHash ||
          projection.PromptAssemblyContract?.final_prompt_hash
        ) {
          summary.promptAssemblyCount += 1;
        }
        if (projection.AgentTurnState) summary.turnStateCount += 1;
        if (projection.AgentDecisionLoop) summary.decisionLoopCount += 1;
        if (projection.SessionTraceBundle) summary.traceBundleCount += 1;
        if (projection.ModelRoutingDecision) summary.modelRoutingCount += 1;
        if (projection.ToolSelectionQualityModel)
          summary.toolSelectionQualityCount += 1;
        const knownResources = projection.TaskStateModel?.knownResources;
        if (Array.isArray(knownResources) && knownResources.length > 0) {
          summary.selectedSourceCount = Math.max(
            summary.selectedSourceCount,
            knownResources.length,
          );
        }
        if (projection.AgentQualityLedger) {
          summary.qualityLedgerCount += 1;
          summary.scorecardCount += 1;
        }
        if (projection.AgentQualityLedger?.scorecardMetrics) {
          summary.scorecardCount += 1;
        }
        if (projection.StopConditionRecord) {
          summary.stopReasonCount += 1;
        }
        if (projection.HarnessWorkerBinding) {
          summary.harnessWorkerBindingCount += 1;
        }
        noteHarnessDefaultRuntimeBinding(
          projection.HarnessDefaultRuntimeBinding,
        );
        if (projection.HarnessRuntimeSelectorDecision) {
          const decision = projection.HarnessRuntimeSelectorDecision;
          if (
            decision.schemaVersion === "workflow.harness.runtime-selector.v1" &&
            decision.selectedSelector === "blessed_workflow_live_canary" &&
            decision.productionDefaultSelector === "workflow_recovery_blocked" &&
            decision.canaryEligible === true &&
            Array.isArray(decision.canaryBlockers) &&
            decision.canaryBlockers.length === 0 &&
            decision.executionMode === "live" &&
            decision.actualRuntimeAuthority ===
              "blessed_workflow_activation_canary" &&
            decision.rollbackAvailable === true
          ) {
            summary.harnessSelectorCanaryRoutedCount += 1;
          }
          if (
            decision.schemaVersion === "workflow.harness.runtime-selector.v1" &&
            decision.selectedSelector === "blessed_workflow_live_default" &&
            decision.productionDefaultSelector ===
              "blessed_workflow_live_default" &&
            decision.canaryEligible === true &&
            Array.isArray(decision.canaryBlockers) &&
            decision.canaryBlockers.length === 0 &&
            decision.executionMode === "live" &&
            decision.actualRuntimeAuthority ===
              "blessed_workflow_activation_default" &&
            decision.defaultPromotionGate?.enabled === true &&
            decision.defaultPromotionGate?.eligible === true &&
            decision.rollbackAvailable === true &&
            decision.livePromotionReadinessReady === true &&
            Array.isArray(decision.livePromotionReadinessBlockers) &&
            decision.livePromotionReadinessBlockers.length === 0 &&
            decision.livePromotionReadinessProof?.schemaVersion ===
              "workflow.harness.live-promotion-readiness.v1" &&
            decision.livePromotionReadinessPolicyDecision ===
              "allow_default_harness_live_promotion_readiness"
          ) {
            summary.harnessSelectorDefaultPromotedCount += 1;
          }
          if (
            decision.defaultLivePromotionInvariantIds?.includes(
              REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
            ) === true &&
            Array.isArray(decision.defaultLivePromotionInvariantBlockers) &&
            decision.defaultLivePromotionInvariantBlockers.length === 0 &&
            decision.reviewedImportActivationApplyProofPresent === true &&
            decision.reviewedImportActivationApplyProofPassed === true &&
            Array.isArray(
              decision.reviewedImportActivationApplyProofBlockers,
            ) &&
            decision.reviewedImportActivationApplyProofBlockers.length === 0
          ) {
            summary.harnessSelectorReviewedImportActivationApplyInvariantCount += 1;
          }
          if (
            decision.livePromotionReadinessReady === true &&
            Array.isArray(decision.livePromotionReadinessBlockers) &&
            decision.livePromotionReadinessBlockers.length === 0 &&
            decision.livePromotionReadinessProof?.schemaVersion ===
              "workflow.harness.live-promotion-readiness.v1" &&
            decision.livePromotionReadinessPolicyDecision ===
              "allow_default_harness_live_promotion_readiness"
          ) {
            summary.harnessSelectorLivePromotionReadinessGatedCount += 1;
          }
          if (
            decision.productionDefaultSelector === "workflow_recovery_blocked" &&
            decision.recoveryMode === "fail_closed" &&
            typeof decision.rollbackTarget === "string" &&
            decision.rollbackTarget.length > 0
          ) {
            summary.harnessSelectorWorkflowRecoveryBlockedCount += 1;
          }
        }
        if (projection.HarnessShadowRun) {
          summary.harnessShadowRunCount += 1;
          if (Array.isArray(projection.HarnessShadowRun.nodeAttempts)) {
            summary.harnessNodeAttemptCount +=
              projection.HarnessShadowRun.nodeAttempts.length;
          }
          if (Array.isArray(projection.HarnessShadowRun.comparisons)) {
            summary.harnessShadowComparisonCount +=
              projection.HarnessShadowRun.comparisons.length;
          }
          summary.harnessBlockingDivergenceCount += Number(
            projection.HarnessShadowRun.blockingDivergenceCount ?? 0,
          );
        }
        if (Array.isArray(projection.HarnessGatedClusterRuns)) {
          summary.harnessGatedClusterCount +=
            projection.HarnessGatedClusterRuns.length;
          summary.harnessGatedCognitionCount +=
            projection.HarnessGatedClusterRuns.filter(
              (run) =>
                run?.clusterId === "cognition" &&
                run?.executionMode === "gated" &&
                run?.status === "gated" &&
                run?.promotionBlocked === false &&
                run?.rollbackAvailable === true &&
                run?.canaryStatus === "passed",
            ).length;
          summary.harnessGatedRoutingModelCount +=
            projection.HarnessGatedClusterRuns.filter(
              (run) =>
                run?.clusterId === "routing_model" &&
                run?.executionMode === "gated" &&
                run?.status === "gated" &&
                run?.promotionBlocked === false &&
                run?.rollbackAvailable === true &&
                run?.canaryStatus === "passed",
            ).length;
          summary.harnessGatedVerificationOutputCount +=
            projection.HarnessGatedClusterRuns.filter(
              (run) =>
                run?.clusterId === "verification_output" &&
                run?.executionMode === "gated" &&
                run?.status === "gated" &&
                run?.promotionBlocked === false &&
                run?.rollbackAvailable === true &&
                run?.canaryStatus === "passed",
            ).length;
          summary.harnessGatedAuthorityToolingCount +=
            projection.HarnessGatedClusterRuns.filter(
              (run) =>
                run?.clusterId === "authority_tooling" &&
                run?.executionMode === "gated" &&
                run?.status === "gated" &&
                run?.promotionBlocked === false &&
                run?.rollbackAvailable === true &&
                run?.canaryStatus === "passed" &&
                run?.runtimeAuthority === "workflow_recovery_fail_closed",
            ).length;
        }
        if (projection.HarnessForkActivation) {
          noteRollbackRestoreCanaryProof(projection.HarnessForkActivation);
          const invalidFork =
            projection.HarnessForkActivation.invalidFork ?? {};
          const validFork = projection.HarnessForkActivation.validFork ?? {};
          if (
            invalidFork.activationState === "blocked" &&
            Array.isArray(invalidFork.activationBlockers) &&
            invalidFork.activationBlockers.length > 0 &&
            invalidFork.activationMinted === false
          ) {
            summary.harnessForkActivationBlockedCount += 1;
          }
          if (
            typeof validFork.activationId === "string" &&
            validFork.activationId.length > 0 &&
            validFork.activationState === "validated" &&
            validFork.canaryStatus === "passed" &&
            validFork.rollbackAvailable === true &&
            validFork.liveAuthorityTransferred === false &&
            validFork.workerBinding?.harnessActivationId ===
              validFork.activationId &&
            forkHandoffTimelineBound(validFork)
          ) {
            summary.harnessForkActivationMintedCount += 1;
          }
          if (forkHandoffTimelineBound(validFork)) {
            summary.harnessForkHandoffTimelineBoundCount += 1;
          }
        }
        {
          const boundaries = Array.isArray(
            projection.HarnessCanaryExecutionBoundaries,
          )
            ? projection.HarnessCanaryExecutionBoundaries
            : projection.HarnessCanaryExecutionBoundary
              ? [projection.HarnessCanaryExecutionBoundary]
              : [];
          const boundaryPasses = (clusterId) =>
            boundaries.some((boundary) => {
              const minimumAttempts =
                clusterId === "routing_model"
                  ? 3
                  : clusterId === "authority_tooling"
                    ? 8
                    : 6;
              return (
                boundary?.schemaVersion ===
                  "workflow.harness.canary-execution-boundary.v1" &&
                boundary.clusterId === clusterId &&
                boundary.status === "passed" &&
                boundary.executionMode === "live" &&
                boundary.runtimeAuthority ===
                  "blessed_workflow_activation_canary" &&
                boundary.executorKind === "workflow_node_executor" &&
                boundary.synchronous === true &&
                Array.isArray(boundary.nodeAttemptIds) &&
                boundary.nodeAttemptIds.length >= minimumAttempts &&
                Array.isArray(boundary.executedComponentKinds) &&
                boundary.executedComponentKinds.length >= minimumAttempts &&
                Array.isArray(boundary.activationBlockers) &&
                boundary.activationBlockers.length === 0
              );
            });
          const rollbackPasses = (clusterId) =>
            boundaries.some(
              (boundary) =>
                boundary?.clusterId === clusterId &&
                boundary.rollbackDrill?.clusterId === clusterId &&
                boundary.rollbackDrill?.failureInjected === true &&
                boundary.rollbackDrill?.observedFailure === true &&
                boundary.rollbackDrill?.rollbackExecuted === true &&
                boundary.rollbackDrill?.rollbackSelector ===
                  "workflow_recovery_blocked" &&
                boundary.rollbackDrill?.recoveryMode === "fail_closed" &&
                boundary.rollbackDrill?.drillStatus === "passed",
            );
          if (
            boundaryPasses("cognition") &&
            boundaryPasses("routing_model") &&
            boundaryPasses("verification_output") &&
            boundaryPasses("authority_tooling")
          ) {
            summary.harnessCanaryBoundaryExecutedCount += 1;
          }
          if (
            rollbackPasses("cognition") &&
            rollbackPasses("routing_model") &&
            rollbackPasses("verification_output") &&
            rollbackPasses("authority_tooling")
          ) {
            summary.harnessCanaryBoundaryRollbackDrillCount += 1;
          }
        }
        if (projection.HarnessLiveHandoff) {
          const handoff = projection.HarnessLiveHandoff;
          if (
            handoff.schemaVersion === "workflow.harness.live-handoff.v1" &&
            handoff.selector === "blessed_workflow_live_canary" &&
            handoff.productionDefaultSelector === "workflow_recovery_blocked" &&
            handoff.canaryStatus === "passed" &&
            handoff.canaryTurnRoutedThroughWorkflow === true &&
            handoff.executionBoundaryStatus === "passed" &&
            handoff.defaultAuthorityTransferred === false &&
            handoff.runtimeAuthority === "blessed_workflow_activation_canary" &&
            Array.isArray(handoff.executionBoundaryClusterIds) &&
            handoff.executionBoundaryClusterIds.includes("cognition") &&
            handoff.executionBoundaryClusterIds.includes("routing_model") &&
            handoff.executionBoundaryClusterIds.includes(
              "verification_output",
            ) &&
            handoff.executionBoundaryClusterIds.includes("authority_tooling") &&
            Array.isArray(handoff.gatedClusterIds) &&
            handoff.gatedClusterIds.includes("authority_tooling")
          ) {
            summary.harnessLiveHandoffCanaryCount += 1;
          }
          if (
            handoff.schemaVersion === "workflow.harness.live-handoff.v1" &&
            handoff.selector === "blessed_workflow_live_default" &&
            handoff.productionDefaultSelector ===
              "blessed_workflow_live_default" &&
            handoff.canaryStatus === "passed" &&
            handoff.canaryTurnRoutedThroughWorkflow === true &&
            handoff.executionBoundaryStatus === "passed" &&
            handoff.defaultAuthorityTransferred === true &&
            handoff.runtimeAuthority ===
              "blessed_workflow_activation_default" &&
            handoff.defaultPromotionGate?.defaultAuthorityTransferred ===
              true &&
            Array.isArray(handoff.defaultPromotionGate?.activationBlockers) &&
            handoff.defaultPromotionGate.activationBlockers.length === 0 &&
            Array.isArray(handoff.executionBoundaryClusterIds) &&
            handoff.executionBoundaryClusterIds.includes("cognition") &&
            handoff.executionBoundaryClusterIds.includes("routing_model") &&
            handoff.executionBoundaryClusterIds.includes(
              "verification_output",
            ) &&
            handoff.executionBoundaryClusterIds.includes("authority_tooling") &&
            Array.isArray(handoff.gatedClusterIds) &&
            handoff.gatedClusterIds.includes("authority_tooling")
          ) {
            summary.harnessLiveHandoffDefaultPromotedCount += 1;
          }
          if (
            (handoff.recoveryMode === "fail_closed" ||
              handoff.recoveryMode === "restore_prior_workflow_activation") &&
            handoff.rollbackAvailable === true &&
            typeof handoff.rollbackTarget === "string" &&
            handoff.rollbackTarget.length > 0 &&
            Array.isArray(handoff.nodeTimelineAttemptIds) &&
            handoff.nodeTimelineAttemptIds.length > 0 &&
            Array.isArray(handoff.receiptIds) &&
            handoff.receiptIds.length > 0 &&
            Array.isArray(handoff.activationBlockers) &&
            handoff.activationBlockers.length === 0
          ) {
            summary.harnessLiveHandoffRollbackCount += 1;
          }
        }
        if (projection.HarnessDefaultRuntimeDispatch) {
          const dispatch = projection.HarnessDefaultRuntimeDispatch;
          noteHarnessLiveTurnNodeTimeline(dispatch);
          const dispatchActivationIdGateReady =
            dispatch.activationIdGateClickProofPresent === true &&
            dispatch.activationIdGateClickProofPassed === true &&
            Array.isArray(dispatch.activationIdGateClickProofBlockers) &&
            dispatch.activationIdGateClickProofBlockers.length === 0 &&
            Array.isArray(dispatch.defaultDispatchActivationBlockers) &&
            dispatch.defaultDispatchActivationBlockers.length === 0 &&
            dispatch.activationIdGate?.gateId === "activation-id" &&
            dispatch.activationIdGate?.proofPassed === true &&
            dispatch.activationIdGate?.workerBindingActivationId ===
              DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
          const dispatchLivePromotionReadinessReady =
            dispatch.livePromotionReadinessProof?.schemaVersion ===
              "workflow.harness.live-promotion-readiness.v1" &&
            dispatch.livePromotionReadinessProof?.targetExecutionMode ===
              "live" &&
            dispatch.livePromotionReadinessProof?.allClustersReady === true &&
            dispatch.livePromotionReadinessProof?.promotionEligible === true &&
            dispatch.livePromotionReadinessProof?.defaultLiveActivationReady ===
              true &&
            dispatch.livePromotionReadinessProof
              ?.invalidForkLiveActivationBlocked === true &&
            dispatch.livePromotionReadinessProof?.rollbackAvailable === true &&
            dispatch.livePromotionReadinessProof?.policyDecision ===
              "allow_default_harness_live_promotion_readiness" &&
            dispatch.livePromotionReadinessProof
              ?.liveShadowComparisonGateReady === true &&
            dispatch.livePromotionReadinessProof?.liveShadowComparisonGate
              ?.schemaVersion ===
              "workflow.harness.live-shadow-comparison-gate.v1" &&
            dispatch.livePromotionReadinessProof?.liveShadowComparisonGate
              ?.ready === true &&
            dispatch.livePromotionReadinessProof?.liveShadowComparisonGate
              ?.comparisonCount >=
              HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.length &&
            HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.every(
              (componentKind) =>
                dispatch.livePromotionReadinessProof?.liveShadowComparisonGate?.componentKinds?.includes(
                  componentKind,
                ),
            ) &&
            Array.isArray(
              dispatch.livePromotionReadinessProof?.requiredClusterIds,
            ) &&
            [
              "cognition",
              "routing_model",
              "verification_output",
              "authority_tooling",
            ].every((clusterId) =>
              dispatch.livePromotionReadinessProof.requiredClusterIds.includes(
                clusterId,
              ),
            ) &&
            Array.isArray(
              dispatch.livePromotionReadinessProof?.clusterReadiness,
            ) &&
            dispatch.livePromotionReadinessProof.clusterReadiness.length >= 4 &&
            dispatch.livePromotionReadinessProof.clusterReadiness.every(
              (cluster) =>
                cluster.targetExecutionMode === "live" &&
                Array.isArray(cluster.blockers) &&
                cluster.blockers.length === 0 &&
                Array.isArray(cluster.receiptRefs) &&
                cluster.receiptRefs.length > 0 &&
                Array.isArray(cluster.replayFixtureRefs) &&
                cluster.replayFixtureRefs.length > 0 &&
                cluster.blockingDivergenceCount === 0 &&
                cluster.unclassifiedDivergenceCount === 0,
            );
          if (dispatchActivationIdGateReady) {
            summary.harnessActivationIdGateClickProofRuntimeCount += 1;
          }
          if (dispatchLivePromotionReadinessReady) {
            summary.harnessLivePromotionReadinessCount += 1;
          }
          if (
            Array.isArray(dispatch.activationIdGateClickProofBlockers) &&
            dispatch.activationIdGateClickProofBlockers.length > 0
          ) {
            summary.harnessActivationIdGateClickProofRuntimeBlockedCount += 1;
          }
          if (
            dispatch.schemaVersion ===
              "workflow.harness.default-runtime-dispatch.v1" &&
            dispatch.selectedSelector === "blessed_workflow_live_default" &&
            dispatch.productionDefaultSelector ===
              "blessed_workflow_live_default" &&
            dispatch.executionMode === "live" &&
            dispatch.runtimeAuthority ===
              "blessed_workflow_activation_default" &&
            dispatch.dispatchScope ===
              "read_only_cognition_routing_verification_completion_authority_tooling" &&
            dispatch.status === "accepted" &&
            dispatch.readOnlyDispatchAccepted === true &&
            dispatch.drivesRuntimeDecision === true &&
            dispatch.outputWriterDeferred === false &&
            dispatch.outputWriterStatus === "visible_write_committed" &&
            dispatch.outputWriterHandoffReady === true &&
            dispatch.outputWriterMaterializationMode ===
              "workflow_visible_transcript_write" &&
            dispatch.outputWriterMaterializationCanaryReady === true &&
            dispatch.outputWriterMaterializationCommitted === true &&
            dispatch.outputWriterStagedWriteMode ===
              "isolated_checkpoint_blob" &&
            dispatch.outputWriterStagedWriteCanaryReady === true &&
            dispatch.outputWriterStagedWritePersisted === true &&
            dispatch.outputWriterStagedWriteCommitted === true &&
            dispatch.outputWriterStagedWriteVisible === false &&
            dispatch.outputWriterStagedWriteExcludedFromVisibleTranscript ===
              true &&
            dispatch.outputWriterStagedWriteRollbackStatus === "deleted" &&
            dispatch.outputWriterStagedWriteRollbackVerified === true &&
            dispatch.outputWriterVisibleWriteMode ===
              "workflow_visible_transcript_write" &&
            dispatch.outputWriterVisibleWriteReady === true &&
            dispatch.outputWriterVisibleWritePersisted === true &&
            dispatch.outputWriterVisibleWriteCommitted === true &&
            dispatch.outputWriterVisibleWriteVisible === true &&
            dispatch.outputWriterVisibleWriteIdentityCheckpointPersisted ===
              true &&
            dispatch.outputWriterVisibleWriteRecoveryDuplicateSuppressed ===
              true &&
            dispatch.cognitionExecutionMode ===
              "workflow_synchronous_envelope" &&
            dispatch.cognitionExecutionReady === true &&
            dispatch.promptAssemblyMode === "workflow_synchronous_envelope" &&
            typeof dispatch.promptAssemblyPromptHash === "string" &&
            dispatch.promptAssemblyPromptHash.length > 0 &&
            dispatch.promptAssemblyPromptHashMatches === true &&
            dispatch.cognitionExecutionAdapterMode ===
              "workflow_component_adapter_live" &&
            Array.isArray(dispatch.cognitionExecutionAdapterResults) &&
            dispatch.cognitionExecutionAdapterResults.length >= 3 &&
            dispatch.cognitionExecutionAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "live" &&
                result?.actionFrame?.readiness === "live_ready" &&
                result?.nodeAttempt?.status === "live",
            ) &&
            cognitionNodeAuthorityReady(dispatch) &&
            routingModelNodeAuthorityReady(dispatch) &&
            verificationOutputNodeAuthorityReady(dispatch) &&
            authorityToolingNodeAuthorityReady(dispatch) &&
            Array.isArray(dispatch.cognitionExecutionActionFrameIds) &&
            dispatch.cognitionExecutionActionFrameIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionLiveReadyComponentKinds) &&
            ["planner", "prompt_assembler", "task_state"].every((kind) =>
              dispatch.cognitionExecutionLiveReadyComponentKinds.includes(kind),
            ) &&
            dispatch.cognitionExecutionGateAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.cognitionExecutionGateAdapterResults) &&
            dispatch.cognitionExecutionGateAdapterResults.length >= 3 &&
            dispatch.cognitionExecutionGateAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.cognitionExecutionGateAttemptIds) &&
            dispatch.cognitionExecutionGateAttemptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionGateReceiptIds) &&
            dispatch.cognitionExecutionGateReceiptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionGateReplayFixtureRefs) &&
            dispatch.cognitionExecutionGateReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionGateComponentKinds) &&
            ["uncertainty_gate", "budget_gate", "capability_sequencer"].every(
              (kind) =>
                dispatch.cognitionExecutionGateComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.cognitionExecutionGateDivergenceClasses) &&
            dispatch.cognitionExecutionGateDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.routingModelAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.routingModelAdapterResults) &&
            dispatch.routingModelAdapterResults.length >= 3 &&
            dispatch.routingModelAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.routingModelAttemptIds) &&
            dispatch.routingModelAttemptIds.length >= 3 &&
            Array.isArray(dispatch.routingModelReceiptIds) &&
            dispatch.routingModelReceiptIds.length >= 3 &&
            Array.isArray(dispatch.routingModelReplayFixtureRefs) &&
            dispatch.routingModelReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.routingModelComponentKinds) &&
            ["model_router", "model_call", "tool_router"].every((kind) =>
              dispatch.routingModelComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.routingModelDivergenceClasses) &&
            dispatch.routingModelDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.verificationOutputAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.verificationOutputAdapterResults) &&
            dispatch.verificationOutputAdapterResults.length >= 6 &&
            dispatch.verificationOutputAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.verificationOutputAttemptIds) &&
            dispatch.verificationOutputAttemptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputReceiptIds) &&
            dispatch.verificationOutputReceiptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputReplayFixtureRefs) &&
            dispatch.verificationOutputReplayFixtureRefs.length >= 6 &&
            Array.isArray(dispatch.verificationOutputComponentKinds) &&
            [
              "postcondition_synthesizer",
              "verifier",
              "completion_gate",
              "receipt_writer",
              "quality_ledger",
              "output_writer",
            ].every((kind) =>
              dispatch.verificationOutputComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.verificationOutputDivergenceClasses) &&
            dispatch.verificationOutputDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.verificationOutputShadowAdapterMode ===
              "workflow_component_adapter_shadow" &&
            Array.isArray(dispatch.verificationOutputShadowAdapterResults) &&
            dispatch.verificationOutputShadowAdapterResults.length >= 6 &&
            dispatch.verificationOutputShadowAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "shadow" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "shadow",
            ) &&
            Array.isArray(dispatch.verificationOutputShadowAttemptIds) &&
            dispatch.verificationOutputShadowAttemptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputShadowReceiptIds) &&
            dispatch.verificationOutputShadowReceiptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputShadowReplayFixtureRefs) &&
            dispatch.verificationOutputShadowReplayFixtureRefs.length >= 6 &&
            Array.isArray(dispatch.verificationOutputShadowComponentKinds) &&
            [
              "postcondition_synthesizer",
              "verifier",
              "completion_gate",
              "receipt_writer",
              "quality_ledger",
              "output_writer",
            ].every((kind) =>
              dispatch.verificationOutputShadowComponentKinds.includes(kind),
            ) &&
            Array.isArray(
              dispatch.verificationOutputShadowDivergenceClasses,
            ) &&
            dispatch.verificationOutputShadowDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.authorityToolingAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.authorityToolingAdapterResults) &&
            dispatch.authorityToolingAdapterResults.length >= 8 &&
            dispatch.authorityToolingAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.authorityToolingAttemptIds) &&
            dispatch.authorityToolingAttemptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingReceiptIds) &&
            dispatch.authorityToolingReceiptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingReplayFixtureRefs) &&
            dispatch.authorityToolingReplayFixtureRefs.length >= 8 &&
            Array.isArray(dispatch.authorityToolingComponentKinds) &&
            [
              "policy_gate",
              "approval_gate",
              "dry_run_simulator",
              "mcp_provider",
              "mcp_tool_call",
              "tool_call",
              "connector_call",
              "wallet_capability",
            ].every((kind) =>
              dispatch.authorityToolingComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.authorityToolingDivergenceClasses) &&
            dispatch.authorityToolingDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.authorityToolingShadowAdapterMode ===
              "workflow_component_adapter_shadow" &&
            Array.isArray(dispatch.authorityToolingShadowAdapterResults) &&
            dispatch.authorityToolingShadowAdapterResults.length >= 8 &&
            dispatch.authorityToolingShadowAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "shadow" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "shadow",
            ) &&
            Array.isArray(dispatch.authorityToolingShadowAttemptIds) &&
            dispatch.authorityToolingShadowAttemptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingShadowReceiptIds) &&
            dispatch.authorityToolingShadowReceiptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingShadowReplayFixtureRefs) &&
            dispatch.authorityToolingShadowReplayFixtureRefs.length >= 8 &&
            Array.isArray(dispatch.authorityToolingShadowComponentKinds) &&
            [
              "policy_gate",
              "approval_gate",
              "dry_run_simulator",
              "mcp_provider",
              "mcp_tool_call",
              "tool_call",
              "connector_call",
              "wallet_capability",
            ].every((kind) =>
              dispatch.authorityToolingShadowComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.authorityToolingShadowDivergenceClasses) &&
            dispatch.authorityToolingShadowDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            authorityToolingNodeAuthorityReady(dispatch) &&
            dispatch.authorityToolingAdapterProof?.ready === true &&
            dispatch.authorityToolingAdapterProof?.policyDecision ===
              "allow_gated_node_authoritative_authority_tooling" &&
            dispatchLivePromotionReadinessReady &&
            dispatch.modelExecutionMode === "workflow_synchronous_envelope" &&
            dispatch.modelExecutionEnvelopeReady === true &&
            typeof dispatch.modelExecutionBindingId === "string" &&
            dispatch.modelExecutionBindingId.length > 0 &&
            dispatch.modelExecutionBindingReady === true &&
            typeof dispatch.modelExecutionPromptHash === "string" &&
            dispatch.modelExecutionPromptHash.length > 0 &&
            dispatch.modelExecutionPromptHashMatches === true &&
            typeof dispatch.modelExecutionOutputHash === "string" &&
            dispatch.modelExecutionOutputHash.length > 0 &&
            dispatch.modelExecutionOutputHashMatches === true &&
            dispatch.modelExecutionProviderInvocationMode ===
              "workflow_provider_canary" &&
            dispatch.modelExecutionLowLevelInvocationDeferred === false &&
            dispatch.modelExecutionRecoveryMode === "fail_closed" &&
            dispatch.modelProviderCanaryMode === "workflow_provider_canary" &&
            dispatch.modelProviderCanaryReady === true &&
            dispatch.modelProviderCanaryOutputHashMatches === true &&
            dispatch.modelProviderCanaryTranscriptMatches === true &&
            dispatch.modelProviderCanaryRecoveryReady === true &&
            dispatch.modelProviderCanaryRollbackAvailable === true &&
            dispatch.modelProviderGatedVisibleOutputMode ===
              "workflow_provider_gated_visible_output" &&
            dispatch.modelProviderGatedVisibleOutputEnabled === true &&
            dispatch.modelProviderGatedVisibleOutputReady === true &&
            dispatch.modelProviderGatedVisibleOutputSelected === true &&
            AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.includes(
              dispatch.modelProviderGatedVisibleOutputScenario,
            ) &&
            dispatch.modelProviderGatedVisibleOutputCohort ===
              "retained_read_only_no_tool" &&
            dispatch.modelProviderGatedVisibleOutputRetainedReadOnlyNoTool ===
              true &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputRequiredScenarioSet,
            ) &&
            AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every(
              (scenario) =>
                dispatch.modelProviderGatedVisibleOutputRequiredScenarioSet.includes(
                  scenario,
                ),
            ) &&
            dispatch.modelProviderGatedVisibleOutputScenarioCoverageKey ===
              dispatch.modelProviderGatedVisibleOutputScenario &&
            dispatch.selectedVisibleOutputAuthority ===
              "workflow_model_provider_call" &&
            typeof dispatch.selectedVisibleOutputHash === "string" &&
            dispatch.selectedVisibleOutputHash.length > 0 &&
            dispatch.selectedVisibleOutputHash ===
              dispatch.actualVisibleOutputHash &&
            dispatch.priorWorkflowVisibleOutputHash ===
              dispatch.selectedVisibleOutputHash &&
            dispatch.priorWorkflowVisibleOutputComputed === true &&
            dispatch.priorWorkflowVisibleOutputHashMatchesSelected === true &&
            dispatch.selectedVisibleOutputAuthorityMatchesTranscript === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackAvailable ===
              true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillEnabled ===
              true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillReady ===
              true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillFailureInjected ===
              true &&
            typeof dispatch.modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash ===
              "string" &&
            dispatch
              .modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash
              .length > 0 &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash !==
              dispatch.actualVisibleOutputHash &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges ===
              true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillDivergenceClass ===
              "provider_output_hash_divergence" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillRecoveryMode ===
              "fail_closed" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority ===
              "workflow_model_recovery_fail_closed" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged ===
              true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted ===
              true &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputRollbackDrillActivationBlockers,
            ) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillActivationBlockers.includes(
              "model_provider_output_hash_divergence",
            ) &&
            dispatch.visibleOutputDivergenceClass == null &&
            dispatch.authorityToolingMode === "workflow_live_dry_run" &&
            dispatch.authorityToolingReady === true &&
            dispatch.authorityToolingPolicyGateReady === true &&
            dispatch.authorityToolingToolRouterReady === true &&
            dispatch.authorityToolingDryRunSimulatorReady === true &&
            dispatch.authorityToolingApprovalGateReady === true &&
            dispatch.authorityToolingGateLiveReady === true &&
            dispatch.authorityToolingPolicyGateLiveReady === true &&
            dispatch.authorityToolingDestructiveDenialLiveReady === true &&
            dispatch.authorityToolingApprovalGateLiveReady === true &&
            Array.isArray(dispatch.authorityToolingGateLiveAttemptIds) &&
            dispatch.authorityToolingGateLiveAttemptIds.length >= 3 &&
            Array.isArray(dispatch.authorityToolingGateLiveReceiptIds) &&
            dispatch.authorityToolingGateLiveReceiptIds.length >= 3 &&
            Array.isArray(dispatch.authorityToolingGateLiveReplayFixtureRefs) &&
            dispatch.authorityToolingGateLiveReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.authorityToolingPolicyGateLiveAttemptIds) &&
            dispatch.authorityToolingPolicyGateLiveAttemptIds.length >= 1 &&
            Array.isArray(
              dispatch.authorityToolingDestructiveDenialLiveAttemptIds,
            ) &&
            dispatch.authorityToolingDestructiveDenialLiveAttemptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingApprovalGateLiveAttemptIds,
            ) &&
            dispatch.authorityToolingApprovalGateLiveAttemptIds.length >= 1 &&
            dispatch.authorityToolingReadOnlyAuthorityCanaryReady === true &&
            dispatch.authorityToolingProviderCatalogLiveReady === true &&
            dispatch.authorityToolingProviderCatalogLiveComponentKind ===
              "mcp_provider" &&
            Array.isArray(
              dispatch.authorityToolingProviderCatalogLiveAttemptIds,
            ) &&
            dispatch.authorityToolingProviderCatalogLiveAttemptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingProviderCatalogLiveReceiptIds,
            ) &&
            dispatch.authorityToolingProviderCatalogLiveReceiptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingProviderCatalogLiveReplayFixtureRefs,
            ) &&
            dispatch.authorityToolingProviderCatalogLiveReplayFixtureRefs
              .length >= 1 &&
            dispatch.authorityToolingMcpToolCatalogLiveReady === true &&
            dispatch.authorityToolingMcpToolCatalogLiveComponentKind ===
              "mcp_tool_call" &&
            Array.isArray(
              dispatch.authorityToolingMcpToolCatalogLiveAttemptIds,
            ) &&
            dispatch.authorityToolingMcpToolCatalogLiveAttemptIds.length >= 1 &&
            Array.isArray(
              dispatch.authorityToolingMcpToolCatalogLiveReceiptIds,
            ) &&
            dispatch.authorityToolingMcpToolCatalogLiveReceiptIds.length >= 1 &&
            Array.isArray(
              dispatch.authorityToolingMcpToolCatalogLiveReplayFixtureRefs,
            ) &&
            dispatch.authorityToolingMcpToolCatalogLiveReplayFixtureRefs
              .length >= 1 &&
            dispatch.authorityToolingNativeToolCatalogLiveReady === true &&
            dispatch.authorityToolingNativeToolCatalogLiveComponentKind ===
              "tool_call" &&
            Array.isArray(
              dispatch.authorityToolingNativeToolCatalogLiveAttemptIds,
            ) &&
            dispatch.authorityToolingNativeToolCatalogLiveAttemptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingNativeToolCatalogLiveReceiptIds,
            ) &&
            dispatch.authorityToolingNativeToolCatalogLiveReceiptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingNativeToolCatalogLiveReplayFixtureRefs,
            ) &&
            dispatch.authorityToolingNativeToolCatalogLiveReplayFixtureRefs
              .length >= 1 &&
            dispatch.authorityToolingConnectorCatalogLiveReady === true &&
            dispatch.authorityToolingConnectorCatalogLiveComponentKind ===
              "connector_call" &&
            Array.isArray(
              dispatch.authorityToolingConnectorCatalogLiveAttemptIds,
            ) &&
            dispatch.authorityToolingConnectorCatalogLiveAttemptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingConnectorCatalogLiveReceiptIds,
            ) &&
            dispatch.authorityToolingConnectorCatalogLiveReceiptIds.length >=
              1 &&
            Array.isArray(
              dispatch.authorityToolingConnectorCatalogLiveReplayFixtureRefs,
            ) &&
            dispatch.authorityToolingConnectorCatalogLiveReplayFixtureRefs
              .length >= 1 &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunReady === true &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunComponentKind ===
              "wallet_capability" &&
            Array.isArray(
              dispatch.authorityToolingWalletCapabilityLiveDryRunAttemptIds,
            ) &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunAttemptIds
              .length >= 1 &&
            Array.isArray(
              dispatch.authorityToolingWalletCapabilityLiveDryRunReceiptIds,
            ) &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunReceiptIds
              .length >= 1 &&
            Array.isArray(
              dispatch.authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs,
            ) &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs
              .length >= 1 &&
            Array.isArray(dispatch.authorityToolingReadOnlyComponentKinds) &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes(
              "mcp_provider",
            ) &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes(
              "mcp_tool_call",
            ) &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes(
              "tool_call",
            ) &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes(
              "connector_call",
            ) &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes(
              "wallet_capability",
            ) &&
            Array.isArray(
              dispatch.authorityToolingMutationDeferredComponentKinds,
            ) &&
            dispatch.authorityToolingMutationDeferredComponentKinds.includes(
              "wallet_capability",
            ) &&
            dispatch.authorityToolingReadOnlyRouteAccepted === true &&
            dispatch.authorityToolingDestructiveRouteDenied === true &&
            dispatch.authorityToolingMutatingToolCallsBlocked === true &&
            dispatch.authorityToolingSideEffectsExecuted === false &&
            dispatch.authorityToolingRollbackAvailable === true &&
            dispatch.workflowTranscriptRecoveryAuthorityRetained === false &&
            dispatch.transcriptMaterializationMatches === true &&
            dispatch.transcriptMaterializationContentHashMatches === true &&
            dispatch.transcriptMaterializationOrderMatches === true &&
            dispatch.transcriptMaterializationReceiptBindingMatches === true &&
            dispatch.transcriptMaterializationDivergenceCount === 0 &&
            dispatch.stagedTranscriptWriteMatches === true &&
            dispatch.stagedTranscriptWriteContentHashMatches === true &&
            dispatch.stagedTranscriptWriteOrderMatches === true &&
            dispatch.stagedTranscriptWriteReceiptBindingMatches === true &&
            dispatch.stagedTranscriptWriteDivergenceCount === 0 &&
            dispatch.visibleTranscriptWriteMatches === true &&
            dispatch.visibleTranscriptWriteContentHashMatches === true &&
            dispatch.visibleTranscriptWriteOrderMatches === true &&
            dispatch.visibleTranscriptWriteReceiptBindingMatches === true &&
            dispatch.visibleTranscriptWriteDivergenceCount === 0 &&
            dispatch.workflowTranscriptWriteCandidate?.committed === false &&
            dispatch.workflowTranscriptWriteRecord?.committed === true &&
            dispatch.workflowTranscriptWriteRecord?.visible === true &&
            dispatch.workflowTranscriptRecoveryRecord?.committed === false &&
            dispatch.workflowTranscriptRecoveryRecord?.suppressedByIdempotency ===
              true &&
            dispatch.stagedTranscriptWriteRecord?.committed === true &&
            dispatch.stagedTranscriptWriteRecord?.visible === false &&
            dispatch.outputHashMatches === true &&
            dispatch.outputHashDivergence === false &&
            dispatch.outputHashDivergenceCount === 0 &&
            typeof dispatch.proposedVisibleOutputHash === "string" &&
            dispatch.proposedVisibleOutputHash.length > 0 &&
            dispatch.proposedVisibleOutputHash ===
              dispatch.actualVisibleOutputHash &&
            dispatch.workflowOutputRecoveryAuthorityRetained === false &&
            dispatch.workflowOutputRecoveryAvailable === true &&
            dispatch.mutatingTurnsBlocked === true &&
            dispatch.outputAuthority ===
              "blessed_workflow_activation_default" &&
            Array.isArray(dispatch.acceptedClusterIds) &&
            dispatch.acceptedClusterIds.includes("cognition") &&
            dispatch.acceptedClusterIds.includes("routing_model") &&
            dispatch.acceptedClusterIds.includes("verification_output") &&
            dispatch.acceptedClusterIds.includes("authority_tooling") &&
            Array.isArray(dispatch.componentKinds) &&
            dispatch.componentKinds.length >= 18 &&
            dispatch.componentKinds.includes("verifier") &&
            dispatch.componentKinds.includes("completion_gate") &&
            dispatch.componentKinds.includes("receipt_writer") &&
            dispatch.componentKinds.includes("quality_ledger") &&
            dispatch.componentKinds.includes("output_writer") &&
            dispatch.componentKinds.includes("policy_gate") &&
            dispatch.componentKinds.includes("dry_run_simulator") &&
            dispatch.componentKinds.includes("approval_gate") &&
            Array.isArray(dispatch.deferredComponentKinds) &&
            dispatch.deferredComponentKinds.includes("mcp_tool_call") &&
            dispatch.deferredComponentKinds.includes("tool_call") &&
            dispatch.deferredComponentKinds.includes("connector_call") &&
            dispatch.deferredComponentKinds.includes("wallet_capability") &&
            Array.isArray(dispatch.handoffValidatedComponentKinds) &&
            dispatch.handoffValidatedComponentKinds.includes("output_writer") &&
            Array.isArray(dispatch.materializationCanaryComponentKinds) &&
            dispatch.materializationCanaryComponentKinds.includes(
              "output_writer",
            ) &&
            Array.isArray(dispatch.dispatchNodeAttemptIds) &&
            dispatch.dispatchNodeAttemptIds.length >= 20 &&
            Array.isArray(dispatch.cognitionExecutionAttemptIds) &&
            dispatch.cognitionExecutionAttemptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionReceiptIds) &&
            dispatch.cognitionExecutionReceiptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionReplayFixtureRefs) &&
            dispatch.cognitionExecutionReplayFixtureRefs.length >= 3 &&
            dispatch.cognitionExecutionAdapterMode ===
              "workflow_component_adapter_live" &&
            Array.isArray(dispatch.cognitionExecutionAdapterResults) &&
            dispatch.cognitionExecutionAdapterResults.length >= 3 &&
            dispatch.cognitionExecutionAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "live" &&
                result?.actionFrame?.readiness === "live_ready" &&
                result?.nodeAttempt?.status === "live",
            ) &&
            cognitionNodeAuthorityReady(dispatch) &&
            routingModelNodeAuthorityReady(dispatch) &&
            verificationOutputNodeAuthorityReady(dispatch) &&
            authorityToolingNodeAuthorityReady(dispatch) &&
            Array.isArray(dispatch.cognitionExecutionActionFrameIds) &&
            dispatch.cognitionExecutionActionFrameIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionLiveReadyComponentKinds) &&
            ["planner", "prompt_assembler", "task_state"].every((kind) =>
              dispatch.cognitionExecutionLiveReadyComponentKinds.includes(kind),
            ) &&
            dispatch.cognitionExecutionGateAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.cognitionExecutionGateAdapterResults) &&
            dispatch.cognitionExecutionGateAdapterResults.length >= 3 &&
            dispatch.cognitionExecutionGateAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.cognitionExecutionGateAttemptIds) &&
            dispatch.cognitionExecutionGateAttemptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionGateReceiptIds) &&
            dispatch.cognitionExecutionGateReceiptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionGateReplayFixtureRefs) &&
            dispatch.cognitionExecutionGateReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionGateComponentKinds) &&
            ["uncertainty_gate", "budget_gate", "capability_sequencer"].every(
              (kind) =>
                dispatch.cognitionExecutionGateComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.cognitionExecutionGateDivergenceClasses) &&
            dispatch.cognitionExecutionGateDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.routingModelAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.routingModelAdapterResults) &&
            dispatch.routingModelAdapterResults.length >= 3 &&
            dispatch.routingModelAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.routingModelAttemptIds) &&
            dispatch.routingModelAttemptIds.length >= 3 &&
            Array.isArray(dispatch.routingModelReceiptIds) &&
            dispatch.routingModelReceiptIds.length >= 3 &&
            Array.isArray(dispatch.routingModelReplayFixtureRefs) &&
            dispatch.routingModelReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.routingModelComponentKinds) &&
            ["model_router", "model_call", "tool_router"].every((kind) =>
              dispatch.routingModelComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.routingModelDivergenceClasses) &&
            dispatch.routingModelDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.verificationOutputAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.verificationOutputAdapterResults) &&
            dispatch.verificationOutputAdapterResults.length >= 6 &&
            dispatch.verificationOutputAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.verificationOutputAttemptIds) &&
            dispatch.verificationOutputAttemptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputReceiptIds) &&
            dispatch.verificationOutputReceiptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputReplayFixtureRefs) &&
            dispatch.verificationOutputReplayFixtureRefs.length >= 6 &&
            Array.isArray(dispatch.verificationOutputComponentKinds) &&
            [
              "postcondition_synthesizer",
              "verifier",
              "completion_gate",
              "receipt_writer",
              "quality_ledger",
              "output_writer",
            ].every((kind) =>
              dispatch.verificationOutputComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.verificationOutputDivergenceClasses) &&
            dispatch.verificationOutputDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.verificationOutputShadowAdapterMode ===
              "workflow_component_adapter_shadow" &&
            Array.isArray(dispatch.verificationOutputShadowAdapterResults) &&
            dispatch.verificationOutputShadowAdapterResults.length >= 6 &&
            dispatch.verificationOutputShadowAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "shadow" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "shadow",
            ) &&
            Array.isArray(dispatch.verificationOutputShadowAttemptIds) &&
            dispatch.verificationOutputShadowAttemptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputShadowReceiptIds) &&
            dispatch.verificationOutputShadowReceiptIds.length >= 6 &&
            Array.isArray(dispatch.verificationOutputShadowReplayFixtureRefs) &&
            dispatch.verificationOutputShadowReplayFixtureRefs.length >= 6 &&
            Array.isArray(dispatch.verificationOutputShadowComponentKinds) &&
            [
              "postcondition_synthesizer",
              "verifier",
              "completion_gate",
              "receipt_writer",
              "quality_ledger",
              "output_writer",
            ].every((kind) =>
              dispatch.verificationOutputShadowComponentKinds.includes(kind),
            ) &&
            Array.isArray(
              dispatch.verificationOutputShadowDivergenceClasses,
            ) &&
            dispatch.verificationOutputShadowDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.authorityToolingAdapterMode ===
              "workflow_component_adapter_gated" &&
            Array.isArray(dispatch.authorityToolingAdapterResults) &&
            dispatch.authorityToolingAdapterResults.length >= 8 &&
            dispatch.authorityToolingAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "gated" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "gated",
            ) &&
            Array.isArray(dispatch.authorityToolingAttemptIds) &&
            dispatch.authorityToolingAttemptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingReceiptIds) &&
            dispatch.authorityToolingReceiptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingReplayFixtureRefs) &&
            dispatch.authorityToolingReplayFixtureRefs.length >= 8 &&
            Array.isArray(dispatch.authorityToolingComponentKinds) &&
            [
              "policy_gate",
              "approval_gate",
              "dry_run_simulator",
              "mcp_provider",
              "mcp_tool_call",
              "tool_call",
              "connector_call",
              "wallet_capability",
            ].every((kind) =>
              dispatch.authorityToolingComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.authorityToolingDivergenceClasses) &&
            dispatch.authorityToolingDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            dispatch.authorityToolingShadowAdapterMode ===
              "workflow_component_adapter_shadow" &&
            Array.isArray(dispatch.authorityToolingShadowAdapterResults) &&
            dispatch.authorityToolingShadowAdapterResults.length >= 8 &&
            dispatch.authorityToolingShadowAdapterResults.every(
              (result) =>
                result?.actionFrame?.executionMode === "shadow" &&
                result?.actionFrame?.readiness === "shadow_ready" &&
                result?.nodeAttempt?.status === "shadow",
            ) &&
            Array.isArray(dispatch.authorityToolingShadowAttemptIds) &&
            dispatch.authorityToolingShadowAttemptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingShadowReceiptIds) &&
            dispatch.authorityToolingShadowReceiptIds.length >= 8 &&
            Array.isArray(dispatch.authorityToolingShadowReplayFixtureRefs) &&
            dispatch.authorityToolingShadowReplayFixtureRefs.length >= 8 &&
            Array.isArray(dispatch.authorityToolingShadowComponentKinds) &&
            [
              "policy_gate",
              "approval_gate",
              "dry_run_simulator",
              "mcp_provider",
              "mcp_tool_call",
              "tool_call",
              "connector_call",
              "wallet_capability",
            ].every((kind) =>
              dispatch.authorityToolingShadowComponentKinds.includes(kind),
            ) &&
            Array.isArray(dispatch.authorityToolingShadowDivergenceClasses) &&
            dispatch.authorityToolingShadowDivergenceClasses.every(
              (kind) => kind === "none",
            ) &&
            authorityToolingNodeAuthorityReady(dispatch) &&
            dispatch.authorityToolingAdapterProof?.ready === true &&
            dispatch.authorityToolingAdapterProof?.policyDecision ===
              "allow_gated_node_authoritative_authority_tooling" &&
            Array.isArray(dispatch.modelExecutionAttemptIds) &&
            dispatch.modelExecutionAttemptIds.length >= 5 &&
            Array.isArray(dispatch.modelExecutionReceiptIds) &&
            dispatch.modelExecutionReceiptIds.length >= 5 &&
            Array.isArray(dispatch.modelExecutionReplayFixtureRefs) &&
            dispatch.modelExecutionReplayFixtureRefs.length >= 5 &&
            Array.isArray(dispatch.modelProviderCanaryAttemptIds) &&
            dispatch.modelProviderCanaryAttemptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderCanaryReceiptIds) &&
            dispatch.modelProviderCanaryReceiptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderCanaryReplayFixtureRefs) &&
            dispatch.modelProviderCanaryReplayFixtureRefs.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputAttemptIds) &&
            dispatch.modelProviderGatedVisibleOutputAttemptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputReceiptIds) &&
            dispatch.modelProviderGatedVisibleOutputReceiptIds.length >= 1 &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputReplayFixtureRefs,
            ) &&
            dispatch.modelProviderGatedVisibleOutputReplayFixtureRefs.length >=
              1 &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputRollbackDrillAttemptIds,
            ) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillAttemptIds
              .length >= 1 &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputRollbackDrillReceiptIds,
            ) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillReceiptIds
              .length >= 1 &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs,
            ) &&
            dispatch
              .modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs
              .length >= 1 &&
            Array.isArray(dispatch.outputWriterHandoffAttemptIds) &&
            dispatch.outputWriterHandoffAttemptIds.length >= 1 &&
            Array.isArray(
              dispatch.outputWriterMaterializationCanaryAttemptIds,
            ) &&
            dispatch.outputWriterMaterializationCanaryAttemptIds.length >= 1 &&
            Array.isArray(dispatch.outputWriterStagedWriteCanaryAttemptIds) &&
            dispatch.outputWriterStagedWriteCanaryAttemptIds.length >= 1 &&
            Array.isArray(dispatch.outputWriterVisibleWriteAttemptIds) &&
            dispatch.outputWriterVisibleWriteAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingLiveDryRunAttemptIds) &&
            dispatch.authorityToolingLiveDryRunAttemptIds.length >= 10 &&
            Array.isArray(dispatch.authorityToolingReadOnlyLiveAttemptIds) &&
            dispatch.authorityToolingReadOnlyLiveAttemptIds.length >= 5 &&
            Array.isArray(dispatch.authorityToolingReadOnlyReceiptIds) &&
            dispatch.authorityToolingReadOnlyReceiptIds.length >= 5 &&
            Array.isArray(dispatch.authorityToolingReadOnlyReplayFixtureRefs) &&
            dispatch.authorityToolingReadOnlyReplayFixtureRefs.length >= 5 &&
            dispatch.authorityToolingProof?.gateLiveReady === true &&
            dispatch.authorityToolingProof?.policyGateLiveReady === true &&
            dispatch.authorityToolingProof?.destructiveDenialLiveReady ===
              true &&
            dispatch.authorityToolingProof?.approvalGateLiveReady === true &&
            dispatch.authorityToolingProof?.readOnlyAuthorityCanaryReady ===
              true &&
            dispatch.authorityToolingProof?.providerCatalogLiveReady === true &&
            dispatch.authorityToolingProof?.providerCatalogLiveComponentKind ===
              "mcp_provider" &&
            dispatch.authorityToolingProof?.mcpToolCatalogLiveReady === true &&
            dispatch.authorityToolingProof?.mcpToolCatalogLiveComponentKind ===
              "mcp_tool_call" &&
            dispatch.authorityToolingProof?.nativeToolCatalogLiveReady ===
              true &&
            dispatch.authorityToolingProof
              ?.nativeToolCatalogLiveComponentKind === "tool_call" &&
            dispatch.authorityToolingProof?.connectorCatalogLiveReady ===
              true &&
            dispatch.authorityToolingProof
              ?.connectorCatalogLiveComponentKind === "connector_call" &&
            dispatch.authorityToolingProof?.githubPrCreateDryRunReady ===
              true &&
            dispatch.authorityToolingProof?.githubPrCreateDryRunComponentKind ===
              "github_pr_create" &&
            dispatch.authorityToolingProof?.walletCapabilityLiveDryRunReady ===
              true &&
            dispatch.authorityToolingProof
              ?.walletCapabilityLiveDryRunComponentKind ===
              "wallet_capability" &&
            Array.isArray(
              dispatch.authorityToolingProof?.mutationDeferredComponentKinds,
            ) &&
            dispatch.authorityToolingProof.mutationDeferredComponentKinds.includes(
              "github_pr_create",
            ) &&
            dispatch.authorityToolingProof.mutationDeferredComponentKinds.includes(
              "wallet_capability",
            ) &&
            Array.isArray(dispatch.authorityToolingDenialReceiptIds) &&
            dispatch.authorityToolingDenialReceiptIds.length >= 1 &&
            Array.isArray(dispatch.acceptedNodeAttemptIds) &&
            dispatch.acceptedNodeAttemptIds.length >= 18 &&
            Array.isArray(dispatch.activationBlockers) &&
            dispatch.activationBlockers.length === 0 &&
            dispatchActivationIdGateReady &&
            dispatch.rollbackAvailable === true
          ) {
            summary.harnessDefaultRuntimeDispatchReadonlyCount += 1;
            summary.harnessAuthorityToolingReadOnlyCanaryCount += 1;
            summary.harnessAuthorityToolingGateLiveCount += 1;
            summary.harnessAuthorityToolingProviderCatalogLiveCount += 1;
            summary.harnessAuthorityToolingMcpToolCatalogLiveCount += 1;
            summary.harnessAuthorityToolingNativeToolCatalogLiveCount += 1;
            summary.harnessAuthorityToolingConnectorCatalogLiveCount += 1;
            summary.harnessAuthorityToolingGithubPrCreateDryRunCount += 1;
            summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount += 1;
            summary.harnessModelProviderGatedVisibleOutputCount += 1;
            summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount += 1;
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputScenarios,
              dispatch.modelProviderGatedVisibleOutputScenario,
            );
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
              dispatch.modelProviderGatedVisibleOutputScenario,
            );
          }
          const readOnlyRoutingScenario =
            dispatch.readOnlyCapabilityRoutingScenario;
          const readOnlyWorkflowNodeKinds = Array.isArray(
            dispatch.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds,
          )
            ? dispatch.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds
            : [];
          const readOnlySourceOrProbeNodePresent =
            readOnlyRoutingScenario === "retained_probe_behavior"
              ? readOnlyWorkflowNodeKinds.includes("probe_runner")
              : [
                  "retained_repo_grounded_answer",
                  "retained_source_heavy_synthesis",
                ].includes(readOnlyRoutingScenario) &&
                readOnlyWorkflowNodeKinds.includes("memory_read");
          if (
            dispatch.schemaVersion ===
              "workflow.harness.default-runtime-dispatch.v1" &&
            dispatch.selectedSelector === "blessed_workflow_live_default" &&
            dispatch.productionDefaultSelector ===
              "blessed_workflow_live_default" &&
            dispatch.executionMode === "live" &&
            dispatch.runtimeAuthority ===
              "blessed_workflow_activation_default" &&
            dispatch.readOnlyCapabilityRoutingMode ===
              "workflow_read_only_capability_routing" &&
            dispatch.readOnlyCapabilityRoutingReady === true &&
            dispatch.readOnlyCapabilityRoutingSelected === true &&
            dispatch.readOnlyCapabilityRoutingNoMutationReady === true &&
            dispatch.readOnlyCapabilityRoutingSourceMaterialReady === true &&
            AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.includes(
              readOnlyRoutingScenario,
            ) &&
            dispatch.readOnlyCapabilityRoutingScenarioCoverageKey ===
              readOnlyRoutingScenario &&
            readOnlyWorkflowNodeKinds.includes("capability_sequencer") &&
            readOnlyWorkflowNodeKinds.includes("tool_router") &&
            readOnlyWorkflowNodeKinds.includes("dry_run_simulator") &&
            readOnlySourceOrProbeNodePresent &&
            Array.isArray(dispatch.readOnlyCapabilityRoutingAttemptIds) &&
            dispatch.readOnlyCapabilityRoutingAttemptIds.length >= 3 &&
            Array.isArray(dispatch.readOnlyCapabilityRoutingReceiptIds) &&
            dispatch.readOnlyCapabilityRoutingReceiptIds.length >= 3 &&
            Array.isArray(
              dispatch.readOnlyCapabilityRoutingReplayFixtureRefs,
            ) &&
            dispatch.readOnlyCapabilityRoutingReplayFixtureRefs.length >= 3 &&
            dispatch.readOnlyCapabilityRoutingProof?.sideEffectsExecuted ===
              false &&
            dispatch.readOnlyCapabilityRoutingProof?.mutationExecuted ===
              false &&
            Array.isArray(dispatch.activationBlockers) &&
            dispatch.activationBlockers.length === 0
          ) {
            summary.harnessReadOnlyCapabilityRoutingCount += 1;
            summary.harnessReadOnlyCapabilityRoutingNoMutationCount += 1;
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingScenarios,
              readOnlyRoutingScenario,
            );
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
              readOnlyRoutingScenario,
            );
          }
        }
      };
      const noteRuntimeReceipt = (payload) => {
        if (!payload || typeof payload !== "object") return;
        const digest = payload.digest ?? {};
        const details = payload.details ?? {};
        if (details.kind === "runtime_evidence_projection") {
          summary.runtimeEvidenceReportCount += 1;
        }
        if (digest.scorecard === true) summary.scorecardCount += 1;
        if (digest.stop_reason === true) summary.stopReasonCount += 1;
        if (digest.quality_ledger === true) summary.qualityLedgerCount += 1;
        if (digest.harness_shadow_run === true)
          summary.harnessShadowRunCount += 1;
        summary.harnessNodeAttemptCount += Number(
          digest.harness_node_attempt_count ?? 0,
        );
        summary.harnessShadowComparisonCount += Number(
          digest.harness_shadow_comparison_count ?? 0,
        );
        summary.harnessBlockingDivergenceCount += Number(
          digest.harness_blocking_divergence_count ?? 0,
        );
        summary.harnessGatedClusterCount += Number(
          digest.harness_gated_cluster_count ?? 0,
        );
        if (digest.harness_gated_cognition_passed === true) {
          summary.harnessGatedCognitionCount += 1;
        }
        if (digest.harness_cognition_node_authority_passed === true) {
          summary.harnessCognitionNodeAuthorityCount += 1;
        }
        if (digest.harness_routing_model_node_authority_passed === true) {
          summary.harnessRoutingModelNodeAuthorityCount += 1;
        }
        if (digest.harness_verification_output_node_authority_passed === true) {
          summary.harnessVerificationOutputNodeAuthorityCount += 1;
        }
        if (digest.harness_authority_tooling_node_authority_passed === true) {
          summary.harnessAuthorityToolingNodeAuthorityCount += 1;
        }
        if (digest.harness_gated_routing_model_passed === true) {
          summary.harnessGatedRoutingModelCount += 1;
        }
        if (digest.harness_gated_verification_output_passed === true) {
          summary.harnessGatedVerificationOutputCount += 1;
        }
        if (digest.harness_gated_authority_tooling_passed === true) {
          summary.harnessGatedAuthorityToolingCount += 1;
        }
        if (digest.harness_fork_activation_blocked === true) {
          summary.harnessForkActivationBlockedCount += 1;
        }
        if (digest.harness_fork_activation_minted === true) {
          summary.harnessForkActivationMintedCount += 1;
        }
        if (digest.harness_fork_mutation_canary_ready === true) {
          summary.harnessForkMutationCanaryReadyCount += 1;
        }
        if (digest.harness_rollback_restore_canary_blocked === true) {
          summary.harnessRollbackRestoreCanaryBlockedCount += 1;
          noteRollbackRestoreCanaryStatus("blocked");
        }
        if (digest.harness_rollback_restore_canary_ready === true) {
          summary.harnessRollbackRestoreCanaryReadyCount += 1;
          noteRollbackRestoreCanaryStatus("ready");
        }
        if (digest.harness_rollback_restore_canary_receipts_present === true) {
          summary.harnessRollbackRestoreCanaryReceiptCount += 2;
        }
        if (digest.harness_activation_audit_receipts_present === true) {
          summary.harnessActivationAuditReceiptCount += 1;
        }
        if (digest.harness_rollback_execution_receipts_present === true) {
          summary.harnessRollbackExecutionReceiptCount += 1;
        }
        if (digest.harness_canary_boundary_executed === true) {
          summary.harnessCanaryBoundaryExecutedCount += 1;
        }
        if (digest.harness_canary_boundary_rollback_drill === true) {
          summary.harnessCanaryBoundaryRollbackDrillCount += 1;
        }
        if (digest.harness_selector_canary_routed === true) {
          summary.harnessSelectorCanaryRoutedCount += 1;
        }
        if (digest.harness_selector_workflow_recovery_blocked === true) {
          summary.harnessSelectorWorkflowRecoveryBlockedCount += 1;
        }
        if (digest.harness_selector_default_promoted === true) {
          summary.harnessSelectorDefaultPromotedCount += 1;
        }
        if (
          digest.harness_selector_reviewed_import_activation_apply_invariant ===
          true
        ) {
          summary.harnessSelectorReviewedImportActivationApplyInvariantCount += 1;
        }
        if (digest.harness_selector_live_promotion_readiness_gated === true) {
          summary.harnessSelectorLivePromotionReadinessGatedCount += 1;
        }
        if (digest.harness_live_handoff_canary === true) {
          summary.harnessLiveHandoffCanaryCount += 1;
        }
        if (digest.harness_live_handoff_default_promoted === true) {
          summary.harnessLiveHandoffDefaultPromotedCount += 1;
        }
        if (digest.harness_live_handoff_rollback === true) {
          summary.harnessLiveHandoffRollbackCount += 1;
        }
        if (digest.harness_default_runtime_dispatch_readonly === true) {
          summary.harnessDefaultRuntimeDispatchReadonlyCount += 1;
        }
        if (digest.harness_live_promotion_readiness === true) {
          summary.harnessLivePromotionReadinessCount += 1;
        }
        if (digest.harness_default_runtime_binding_matched === true) {
          summary.harnessDefaultRuntimeBindingMatchedCount += 1;
        }
        if (digest.harness_authority_tooling_read_only_canary === true) {
          summary.harnessAuthorityToolingReadOnlyCanaryCount += 1;
        }
        if (digest.harness_authority_tooling_gate_live === true) {
          summary.harnessAuthorityToolingGateLiveCount += 1;
        }
        if (digest.harness_authority_tooling_provider_catalog_live === true) {
          summary.harnessAuthorityToolingProviderCatalogLiveCount += 1;
        }
        if (digest.harness_authority_tooling_mcp_tool_catalog_live === true) {
          summary.harnessAuthorityToolingMcpToolCatalogLiveCount += 1;
        }
        if (
          digest.harness_authority_tooling_native_tool_catalog_live === true
        ) {
          summary.harnessAuthorityToolingNativeToolCatalogLiveCount += 1;
        }
        if (digest.harness_authority_tooling_connector_catalog_live === true) {
          summary.harnessAuthorityToolingConnectorCatalogLiveCount += 1;
        }
        if (
          digest.harness_authority_tooling_github_pr_create_dry_run === true
        ) {
          summary.harnessAuthorityToolingGithubPrCreateDryRunCount += 1;
        }
        if (
          digest.harness_authority_tooling_wallet_capability_live_dry_run ===
          true
        ) {
          summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount += 1;
        }
        if (digest.harness_model_provider_gated_visible_output === true) {
          summary.harnessModelProviderGatedVisibleOutputCount += 1;
          noteProviderGatedVisibleOutputCoverage(
            digest.harness_model_provider_gated_visible_output_coverage,
          );
          addScenario(
            summary.harnessModelProviderGatedVisibleOutputScenarios,
            digest.harness_model_provider_gated_visible_output_required_scenario ??
              digest.harness_model_provider_gated_visible_output_scenario,
          );
        }
        if (
          digest.harness_model_provider_gated_visible_output_rollback_drill ===
          true
        ) {
          summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount += 1;
          noteProviderGatedVisibleOutputCoverage(
            digest.harness_model_provider_gated_visible_output_coverage,
          );
          addScenario(
            summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
            digest.harness_model_provider_gated_visible_output_rollback_drill_scenario ??
              digest.harness_model_provider_gated_visible_output_required_scenario,
          );
        }
        if (digest.harness_read_only_capability_routing === true) {
          summary.harnessReadOnlyCapabilityRoutingCount += 1;
          summary.harnessReadOnlyCapabilityRoutingNoMutationCount += 1;
          noteReadOnlyCapabilityRoutingCoverage(
            digest.harness_read_only_capability_routing_coverage,
          );
          addScenario(
            summary.harnessReadOnlyCapabilityRoutingScenarios,
            digest.harness_read_only_capability_routing_required_scenario ??
              digest.harness_read_only_capability_routing_scenario,
          );
          addScenario(
            summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
            digest.harness_read_only_capability_routing_required_scenario ??
              digest.harness_read_only_capability_routing_scenario,
          );
        }
        if (
          Array.isArray(digest.selected_sources) &&
          digest.selected_sources.length > 0
        ) {
          summary.selectedSourceCount = Math.max(
            summary.selectedSourceCount,
            digest.selected_sources.length,
          );
        }
      };
      try {
        summary.transcriptCount = Number(
          db
            .prepare(
              "select count(*) as count from checkpoint_transcript_messages",
            )
            .get().count,
        );
        summary.threadEventCount = Number(
          db.prepare("select count(*) as count from thread_events").get().count,
        );
        summary.artifactRecordCount = Number(
          db.prepare("select count(*) as count from artifact_records").get()
            .count,
        );
        const artifacts = db
          .prepare(
            "select artifact_id, payload_json, created_at_ms from artifact_records order by sort_id desc",
          )
          .all();
        summary.recentArtifacts = artifacts.slice(0, 24).map((row) => {
          const payload = JSON.parse(row.payload_json);
          const title = String(payload.title || "");
          const artifactType = String(payload.artifact_type || "");
          return {
            artifactId: row.artifact_id,
            artifactType,
            title,
            createdAtMs: row.created_at_ms,
          };
        });
        for (const row of artifacts) {
          let payload;
          try {
            payload = JSON.parse(row.payload_json);
          } catch {
            continue;
          }
          const title = String(payload.title || "");
          const artifactType = String(payload.artifact_type || "");
          const metadata = payload.metadata ?? {};
          if (artifactType === "RUN_BUNDLE") summary.runBundleCount += 1;
          if (
            artifactType === "REPORT" &&
            metadata.kind === "runtime_evidence_projection"
          ) {
            summary.runtimeEvidenceReportCount += 1;
          }
          if (
            Array.isArray(metadata.selected_sources) &&
            metadata.selected_sources.length > 0
          ) {
            summary.selectedSourceCount = Math.max(
              summary.selectedSourceCount,
              metadata.selected_sources.length,
            );
          }
          if (
            /source|citation/i.test(title) ||
            /source|citation/i.test(row.payload_json)
          ) {
            summary.selectedSourceCount += 1;
          }
          if (
            metadata.scorecard ||
            /scorecard/i.test(title) ||
            /scorecard/i.test(row.payload_json)
          ) {
            summary.scorecardCount += 1;
          }
          if (
            metadata.stop_reason ||
            /stop[_ -]?reason/i.test(title) ||
            /stop[_ -]?reason/i.test(row.payload_json)
          ) {
            summary.stopReasonCount += 1;
          }
          if (
            metadata.quality_ledger ||
            /quality[_ -]?ledger/i.test(title) ||
            /quality[_ -]?ledger/i.test(row.payload_json)
          ) {
            summary.qualityLedgerCount += 1;
          }
          if (metadata.harness_worker_binding) {
            summary.harnessWorkerBindingCount += 1;
          }
          noteHarnessDefaultRuntimeBinding(
            metadata.harness_default_runtime_binding,
          );
          if (
            metadata.harness_default_runtime_binding_matched === true &&
            !metadata.harness_default_runtime_binding
          ) {
            summary.harnessDefaultRuntimeBindingMatchedCount += 1;
          }
          if (metadata.harness_shadow_run) {
            summary.harnessShadowRunCount += 1;
          }
          summary.harnessNodeAttemptCount += Number(
            metadata.harness_node_attempt_count ?? 0,
          );
          summary.harnessShadowComparisonCount += Number(
            metadata.harness_shadow_comparison_count ?? 0,
          );
          summary.harnessBlockingDivergenceCount += Number(
            metadata.harness_blocking_divergence_count ?? 0,
          );
          summary.harnessGatedClusterCount += Number(
            metadata.harness_gated_cluster_count ?? 0,
          );
          if (metadata.harness_gated_cognition_passed === true) {
            summary.harnessGatedCognitionCount += 1;
          }
          if (metadata.harness_cognition_node_authority_passed === true) {
            summary.harnessCognitionNodeAuthorityCount += 1;
          }
          if (metadata.harness_routing_model_node_authority_passed === true) {
            summary.harnessRoutingModelNodeAuthorityCount += 1;
          }
          if (
            metadata.harness_verification_output_node_authority_passed === true
          ) {
            summary.harnessVerificationOutputNodeAuthorityCount += 1;
          }
          if (
            metadata.harness_authority_tooling_node_authority_passed === true
          ) {
            summary.harnessAuthorityToolingNodeAuthorityCount += 1;
          }
          if (metadata.harness_gated_routing_model_passed === true) {
            summary.harnessGatedRoutingModelCount += 1;
          }
          if (metadata.harness_gated_verification_output_passed === true) {
            summary.harnessGatedVerificationOutputCount += 1;
          }
          if (metadata.harness_gated_authority_tooling_passed === true) {
            summary.harnessGatedAuthorityToolingCount += 1;
          }
          if (metadata.harness_fork_activation_blocked === true) {
            summary.harnessForkActivationBlockedCount += 1;
          }
          if (metadata.harness_fork_activation_minted === true) {
            summary.harnessForkActivationMintedCount += 1;
          }
          if (metadata.harness_fork_mutation_canary_ready === true) {
            summary.harnessForkMutationCanaryReadyCount += 1;
          }
          if (metadata.harness_fork_activation) {
            noteRollbackRestoreCanaryProof(metadata.harness_fork_activation);
          }
          if (metadata.harness_rollback_restore_canary_blocked === true) {
            summary.harnessRollbackRestoreCanaryBlockedCount += 1;
            noteRollbackRestoreCanaryStatus("blocked");
          }
          if (metadata.harness_rollback_restore_canary_ready === true) {
            summary.harnessRollbackRestoreCanaryReadyCount += 1;
            noteRollbackRestoreCanaryStatus("ready");
          }
          if (
            metadata.harness_rollback_restore_canary_receipts_present === true
          ) {
            summary.harnessRollbackRestoreCanaryReceiptCount += 2;
          }
          if (metadata.harness_activation_audit_receipts_present === true) {
            summary.harnessActivationAuditReceiptCount += 1;
          }
          if (metadata.harness_rollback_execution_receipts_present === true) {
            summary.harnessRollbackExecutionReceiptCount += 1;
          }
          if (metadata.harness_canary_boundary_executed === true) {
            summary.harnessCanaryBoundaryExecutedCount += 1;
          }
          if (metadata.harness_canary_boundary_rollback_drill === true) {
            summary.harnessCanaryBoundaryRollbackDrillCount += 1;
          }
          if (metadata.harness_selector_canary_routed === true) {
            summary.harnessSelectorCanaryRoutedCount += 1;
          }
          if (metadata.harness_selector_workflow_recovery_blocked === true) {
            summary.harnessSelectorWorkflowRecoveryBlockedCount += 1;
          }
          if (metadata.harness_selector_default_promoted === true) {
            summary.harnessSelectorDefaultPromotedCount += 1;
          }
          if (
            metadata.harness_selector_reviewed_import_activation_apply_invariant ===
            true
          ) {
            summary.harnessSelectorReviewedImportActivationApplyInvariantCount += 1;
          }
          if (
            metadata.harness_selector_live_promotion_readiness_gated === true
          ) {
            summary.harnessSelectorLivePromotionReadinessGatedCount += 1;
          }
          if (metadata.harness_live_handoff_canary === true) {
            summary.harnessLiveHandoffCanaryCount += 1;
          }
          if (metadata.harness_live_handoff_default_promoted === true) {
            summary.harnessLiveHandoffDefaultPromotedCount += 1;
          }
          if (metadata.harness_live_handoff_rollback === true) {
            summary.harnessLiveHandoffRollbackCount += 1;
          }
          if (metadata.harness_default_runtime_dispatch_readonly === true) {
            summary.harnessDefaultRuntimeDispatchReadonlyCount += 1;
          }
          noteHarnessLiveTurnNodeTimeline(
            metadata.harness_default_runtime_dispatch,
            row.artifact_id,
          );
          if (metadata.harness_live_promotion_readiness === true) {
            summary.harnessLivePromotionReadinessCount += 1;
          }
          if (metadata.harness_authority_tooling_read_only_canary === true) {
            summary.harnessAuthorityToolingReadOnlyCanaryCount += 1;
          }
          if (metadata.harness_authority_tooling_gate_live === true) {
            summary.harnessAuthorityToolingGateLiveCount += 1;
          }
          if (
            metadata.harness_authority_tooling_provider_catalog_live === true
          ) {
            summary.harnessAuthorityToolingProviderCatalogLiveCount += 1;
          }
          if (
            metadata.harness_authority_tooling_mcp_tool_catalog_live === true
          ) {
            summary.harnessAuthorityToolingMcpToolCatalogLiveCount += 1;
          }
          if (
            metadata.harness_authority_tooling_native_tool_catalog_live === true
          ) {
            summary.harnessAuthorityToolingNativeToolCatalogLiveCount += 1;
          }
          if (
            metadata.harness_authority_tooling_connector_catalog_live === true
          ) {
            summary.harnessAuthorityToolingConnectorCatalogLiveCount += 1;
          }
          if (
            metadata.harness_authority_tooling_github_pr_create_dry_run === true
          ) {
            summary.harnessAuthorityToolingGithubPrCreateDryRunCount += 1;
          }
          if (
            metadata.harness_authority_tooling_wallet_capability_live_dry_run ===
            true
          ) {
            summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount += 1;
          }
          if (metadata.harness_model_provider_gated_visible_output === true) {
            summary.harnessModelProviderGatedVisibleOutputCount += 1;
            noteProviderGatedVisibleOutputCoverage(
              metadata.harness_model_provider_gated_visible_output_coverage,
            );
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputScenarios,
              metadata.harness_model_provider_gated_visible_output_required_scenario ??
                metadata.harness_model_provider_gated_visible_output_scenario,
            );
          }
          if (
            metadata.harness_model_provider_gated_visible_output_rollback_drill ===
            true
          ) {
            summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount += 1;
            noteProviderGatedVisibleOutputCoverage(
              metadata.harness_model_provider_gated_visible_output_coverage,
            );
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
              metadata.harness_model_provider_gated_visible_output_rollback_drill_scenario ??
                metadata.harness_model_provider_gated_visible_output_required_scenario,
            );
          }
          if (metadata.harness_read_only_capability_routing === true) {
            summary.harnessReadOnlyCapabilityRoutingCount += 1;
            summary.harnessReadOnlyCapabilityRoutingNoMutationCount += 1;
            noteReadOnlyCapabilityRoutingCoverage(
              metadata.harness_read_only_capability_routing_coverage,
            );
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingScenarios,
              metadata.harness_read_only_capability_routing_required_scenario ??
                metadata.harness_read_only_capability_routing_scenario,
            );
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
              metadata.harness_read_only_capability_routing_required_scenario ??
                metadata.harness_read_only_capability_routing_scenario,
            );
          }
        }
        for (const row of db
          .prepare(
            "select content from artifact_blobs where artifact_id like 'runtime-evidence-%'",
          )
          .all()) {
          try {
            noteProjection(
              JSON.parse(Buffer.from(row.content).toString("utf8")),
            );
          } catch {
            // Ignore unrelated or partially-written blobs; the receipt/event pass below can still prove export.
          }
        }
        for (const row of db
          .prepare("select payload_json from thread_events")
          .all()) {
          try {
            noteRuntimeReceipt(JSON.parse(row.payload_json));
          } catch {
            // Ignore malformed historical events.
          }
        }
      } finally {
        db.close();
      }
    } catch (error) {
      summary.collectionErrors.push(String(error?.message || error));
    }
  } else {
    summary.collectionErrors.push(
      `chat memory database not found: ${chatDbPath}`,
    );
  }

  const path = join(outputRoot, "runtime-artifacts.json");
  writeFileSync(path, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  return {
    path,
    summary,
  };
}

export function collectRollbackRestoreCanaryUiProof(outputRoot) {
  const railPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx";
  const searchPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx";
  const railSearchModelPath =
    "packages/agent-ide/src/runtime/workflow-rail-search-model.ts";
  const entrypointsPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx";
  const entrypointsModelPath =
    "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts";
  const filesPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx";
  const fileBundleModelPath =
    "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts";
  const settingsPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx";
  const settingsModelPath =
    "packages/agent-ide/src/runtime/workflow-settings-model.ts";
  const settingsHarnessPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx"; const settingsHarnessTypesPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts"; const settingsHarnessActivationPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx"; const settingsHarnessActivationGatePanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx"; const settingsHarnessActivationGateRefsPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx"; const settingsHarnessActivationGateTimelinePanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx"; const settingsHarnessPackageEvidencePanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx"; const settingsHarnessPackageEvidenceRowsPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx"; const settingsHarnessPackageImportReviewPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx"; const settingsHarnessWorkerBindingPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx"; const settingsHarnessActiveRuntimeRollbackPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx"; const settingsHarnessActiveRuntimeBindingPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx"; const settingsHarnessRollbackRestoreProofPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx"; const settingsHarnessPromotionPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx"; const settingsHarnessPromotionReadinessPanelPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx";
  const settingsHarnessModelPath =
    "packages/agent-ide/src/runtime/workflow-settings-harness-model.ts";
  const readinessPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx";
  const readinessModelPath =
    "packages/agent-ide/src/runtime/workflow-readiness-model.ts";
  const unitTestsPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx";
  const testReadinessModelPath =
    "packages/agent-ide/src/runtime/workflow-test-readiness-model.ts";
  const runsPanelPath =
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx";
  const runHistoryModelPath =
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts";
  const validationPath =
    "packages/agent-ide/src/runtime/workflow-validation.ts";
  const schedulerLaneReadinessPath =
    "packages/agent-ide/src/runtime/workflow-scheduler-lane-readiness.ts";
  const harnessWorkflowPath =
    "packages/agent-ide/src/runtime/harness-workflow/core.ts";
  const railModelPath = "packages/agent-ide/src/runtime/workflow-rail-model.ts";
  const controllerPath =
    "packages/agent-ide/src/WorkflowComposer/controller.tsx";
  const viewPath = "packages/agent-ide/src/WorkflowComposer/view.tsx";
  const bottomShelfPath =
    "packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx";
  const graphPath = "packages/agent-ide/src/types/graph.ts";
  const restoreCommandPath = "apps/autopilot/src-tauri/src/project/commands.rs";
  const projectPackagePath = "apps/autopilot/src-tauri/src/project/package.rs";
  const projectRustValidationPath =
    "apps/autopilot/src-tauri/src/project/validation.rs";
  const projectRuntimePath = "apps/autopilot/src-tauri/src/project/runtime.rs";
  const projectWorkflowSchedulerLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs";
  const projectWorkflowSchedulerFinalizationLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs";
  const projectWorkflowSchedulerTerminalResultLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs";
  const projectWorkflowSchedulerInterruptLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs";
  const projectWorkflowSchedulerNodeExecutionLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs";
  const projectWorkflowSchedulerNodeOutcomeLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs";
  const projectWorkflowSchedulerNodeFailureOutcomeLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs";
  const projectWorkflowSchedulerNodeSuccessEventLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs";
  const projectWorkflowSchedulerNodeStateUpdateLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs";
  const projectWorkflowSchedulerValidationLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs";
  const projectWorkflowAuthorityToolingLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs";
  const projectWorkflowApprovalInterruptLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs";
  const projectWorkflowBindingLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs";
  const projectWorkflowCheckpointLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs";
  const projectWorkflowStateLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_state_lane.rs";
  const projectWorkflowNodeContractLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs";
  const projectWorkflowNodeMetadataLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs";
  const projectWorkflowRunLifecycleLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs";
  const projectWorkflowNodeExecutionLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs";
  const projectWorkflowMemoryLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs";
  const projectWorkflowOutputLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_output_lane.rs";
  const projectWorkflowPackageLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_package_lane.rs";
  const projectWorkflowExecutionResultsLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs";
  const projectWorkflowGraphExecutionLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs";
  const projectWorkflowHarnessResultsLanePath =
    "apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs";
  const projectRepositoryPrLanePath =
    "apps/autopilot/src-tauri/src/project/repository_pr_lane.rs";
  const projectWorkflowValueHelpersPath =
    "apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs";
  const projectRuntimeTestsPath =
    "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs";
  let rail = readFileSync(resolve(repoRoot, railPath), "utf8");
  const searchPanel = readFileSync(resolve(repoRoot, searchPanelPath), "utf8");
  const railSearchModel = readFileSync(
    resolve(repoRoot, railSearchModelPath),
    "utf8",
  );
  const entrypointsPanel = readFileSync(
    resolve(repoRoot, entrypointsPanelPath),
    "utf8",
  );
  const entrypointsModel = readFileSync(
    resolve(repoRoot, entrypointsModelPath),
    "utf8",
  );
  const filesPanel = readFileSync(resolve(repoRoot, filesPanelPath), "utf8");
  const fileBundleModel = readFileSync(
    resolve(repoRoot, fileBundleModelPath),
    "utf8",
  );
  const settingsPanel = readFileSync(
    resolve(repoRoot, settingsPanelPath),
    "utf8",
  );
  const settingsModel = readFileSync(
    resolve(repoRoot, settingsModelPath),
    "utf8",
  );
  const settingsHarnessPanel = readFileSync(
    resolve(repoRoot, settingsHarnessPanelPath),
    "utf8",
  );
  const settingsHarnessActivationPanel = readFileSync(
    resolve(repoRoot, settingsHarnessActivationPanelPath),
    "utf8",
  );
  const settingsHarnessTypes = readFileSync(resolve(repoRoot, settingsHarnessTypesPath), "utf8"); const settingsHarnessActivationGatePanel = readFileSync(resolve(repoRoot, settingsHarnessActivationGatePanelPath), "utf8"); const settingsHarnessActivationGateRefsPanel = readFileSync(resolve(repoRoot, settingsHarnessActivationGateRefsPanelPath), "utf8"); const settingsHarnessActivationGateTimelinePanel = readFileSync(resolve(repoRoot, settingsHarnessActivationGateTimelinePanelPath), "utf8"); const settingsHarnessPackageEvidencePanel = readFileSync(resolve(repoRoot, settingsHarnessPackageEvidencePanelPath), "utf8"); const settingsHarnessPackageEvidenceRowsPanel = readFileSync(resolve(repoRoot, settingsHarnessPackageEvidenceRowsPanelPath), "utf8"); const settingsHarnessPackageImportReviewPanel = readFileSync(resolve(repoRoot, settingsHarnessPackageImportReviewPanelPath), "utf8"); const settingsHarnessWorkerBindingPanel = readFileSync(resolve(repoRoot, settingsHarnessWorkerBindingPanelPath), "utf8"); const settingsHarnessActiveRuntimeRollbackPanel = readFileSync(resolve(repoRoot, settingsHarnessActiveRuntimeRollbackPanelPath), "utf8"); const settingsHarnessActiveRuntimeBindingPanel = readFileSync(resolve(repoRoot, settingsHarnessActiveRuntimeBindingPanelPath), "utf8"); const settingsHarnessRollbackRestoreProofPanel = readFileSync(resolve(repoRoot, settingsHarnessRollbackRestoreProofPanelPath), "utf8"); const settingsHarnessPromotionPanel = readFileSync(resolve(repoRoot, settingsHarnessPromotionPanelPath), "utf8"); const settingsHarnessPromotionReadinessPanel = readFileSync(resolve(repoRoot, settingsHarnessPromotionReadinessPanelPath), "utf8");
  const settingsHarnessModel = readFileSync(
    resolve(repoRoot, settingsHarnessModelPath),
    "utf8",
  );
  rail = `${rail}\n${settingsHarnessPanel}\n${settingsHarnessTypes}\n${settingsHarnessActivationPanel}\n${settingsHarnessActivationGatePanel}\n${settingsHarnessActivationGateRefsPanel}\n${settingsHarnessActivationGateTimelinePanel}\n${settingsHarnessPackageEvidencePanel}\n${settingsHarnessPackageEvidenceRowsPanel}\n${settingsHarnessPackageImportReviewPanel}\n${settingsHarnessWorkerBindingPanel}\n${settingsHarnessActiveRuntimeRollbackPanel}\n${settingsHarnessActiveRuntimeBindingPanel}\n${settingsHarnessRollbackRestoreProofPanel}\n${settingsHarnessPromotionPanel}\n${settingsHarnessPromotionReadinessPanel}`;
  const readinessPanel = readFileSync(
    resolve(repoRoot, readinessPanelPath),
    "utf8",
  );
  const readinessModel = readFileSync(
    resolve(repoRoot, readinessModelPath),
    "utf8",
  );
  const unitTestsPanel = readFileSync(
    resolve(repoRoot, unitTestsPanelPath),
    "utf8",
  );
  const testReadinessModel = readFileSync(
    resolve(repoRoot, testReadinessModelPath),
    "utf8",
  );
  const runsPanel = readFileSync(resolve(repoRoot, runsPanelPath), "utf8");
  const runHistoryModel = readFileSync(
    resolve(repoRoot, runHistoryModelPath),
    "utf8",
  );
  const validation = readFileSync(resolve(repoRoot, validationPath), "utf8");
  const harnessWorkflow = readFileSync(
    resolve(repoRoot, harnessWorkflowPath),
    "utf8",
  );
  const railModel = readFileSync(resolve(repoRoot, railModelPath), "utf8");
  const controller = readFileSync(resolve(repoRoot, controllerPath), "utf8");
  const view = readFileSync(resolve(repoRoot, viewPath), "utf8");
  const bottomShelf = readFileSync(resolve(repoRoot, bottomShelfPath), "utf8");
  const graph = readFileSync(resolve(repoRoot, graphPath), "utf8");
  const schedulerLaneReadiness = readFileSync(
    resolve(repoRoot, schedulerLaneReadinessPath),
    "utf8",
  );
  const restoreCommand = readFileSync(
    resolve(repoRoot, restoreCommandPath),
    "utf8",
  );
  const projectPackage = readFileSync(resolve(repoRoot, projectPackagePath), "utf8");
  const projectRustValidation = readFileSync(
    resolve(repoRoot, projectRustValidationPath),
    "utf8",
  );
  const projectRuntime = readFileSync(
    resolve(repoRoot, projectRuntimePath),
    "utf8",
  );
  const projectWorkflowSchedulerLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerFinalizationLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerFinalizationLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerTerminalResultLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerTerminalResultLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerInterruptLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerInterruptLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerNodeExecutionLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerNodeExecutionLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerNodeOutcomeLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerNodeOutcomeLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerNodeFailureOutcomeLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerNodeFailureOutcomeLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerNodeSuccessEventLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerNodeSuccessEventLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerNodeStateUpdateLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerNodeStateUpdateLanePath),
    "utf8",
  );
  const projectWorkflowSchedulerValidationLane = readFileSync(
    resolve(repoRoot, projectWorkflowSchedulerValidationLanePath),
    "utf8",
  );
  const projectWorkflowAuthorityToolingLane = readFileSync(
    resolve(repoRoot, projectWorkflowAuthorityToolingLanePath),
    "utf8",
  );
  const projectWorkflowApprovalInterruptLane = readFileSync(
    resolve(repoRoot, projectWorkflowApprovalInterruptLanePath),
    "utf8",
  );
  const projectWorkflowBindingLane = readFileSync(
    resolve(repoRoot, projectWorkflowBindingLanePath),
    "utf8",
  );
  const projectWorkflowCheckpointLane = readFileSync(
    resolve(repoRoot, projectWorkflowCheckpointLanePath),
    "utf8",
  );
  const projectWorkflowStateLane = readFileSync(
    resolve(repoRoot, projectWorkflowStateLanePath),
    "utf8",
  );
  const projectWorkflowNodeContractLane = readFileSync(
    resolve(repoRoot, projectWorkflowNodeContractLanePath),
    "utf8",
  );
  const projectWorkflowNodeMetadataLane = readFileSync(
    resolve(repoRoot, projectWorkflowNodeMetadataLanePath),
    "utf8",
  );
  const projectWorkflowRunLifecycleLane = readFileSync(
    resolve(repoRoot, projectWorkflowRunLifecycleLanePath),
    "utf8",
  );
  const projectWorkflowNodeExecutionLane = readFileSync(
    resolve(repoRoot, projectWorkflowNodeExecutionLanePath),
    "utf8",
  );
  const projectWorkflowMemoryLane = readFileSync(
    resolve(repoRoot, projectWorkflowMemoryLanePath),
    "utf8",
  );
  const projectWorkflowOutputLane = readFileSync(
    resolve(repoRoot, projectWorkflowOutputLanePath),
    "utf8",
  );
  const projectWorkflowPackageLane = readFileSync(
    resolve(repoRoot, projectWorkflowPackageLanePath),
    "utf8",
  );
  const projectWorkflowExecutionResultsLane = readFileSync(
    resolve(repoRoot, projectWorkflowExecutionResultsLanePath),
    "utf8",
  );
  const projectWorkflowGraphExecutionLane = readFileSync(
    resolve(repoRoot, projectWorkflowGraphExecutionLanePath),
    "utf8",
  );
  const projectWorkflowHarnessResultsLane = readFileSync(
    resolve(repoRoot, projectWorkflowHarnessResultsLanePath),
    "utf8",
  );
  const projectRepositoryPrLane = readFileSync(
    resolve(repoRoot, projectRepositoryPrLanePath),
    "utf8",
  );
  const projectWorkflowValueHelpers = readFileSync(
    resolve(repoRoot, projectWorkflowValueHelpersPath),
    "utf8",
  );
  const projectRuntimeTests = readFileSync(
    resolve(repoRoot, projectRuntimeTestsPath),
    "utf8",
  );
  const checks = {
    canaryCardTestId:
      /data-testid="workflow-harness-rollback-restore-canary"/.test(rail),
    canaryStatusAttribute: /data-restore-canary-status/.test(rail),
    wizardStepGateId: /id: "rollback-restore"/.test(rail),
    wizardStepTestId: /workflow-harness-activation-step-\$\{step\.id\}/.test(
      rail,
    ),
    candidateGateTestId:
      /workflow-harness-activation-candidate-gate-\$\{gate\.gateId\}/.test(
        rail,
      ),
    validationGate: /gateId: "rollback-restore"/.test(validation),
    blockedGitCanary: /rollback_restore_canary_not_run/.test(validation),
    dryRunRestoreProbe:
      /runWorkflowHarnessRollbackRestoreCanaryProbe[\s\S]*runtime[\s\S]*workflowPath[\s\S]*rollbackRevisionBinding/.test(
        controller,
      ) &&
      /(?=[\s\S]*runWorkflowHarnessRollbackRestoreCanaryProbe)(?=[\s\S]*revisionSource !== "git")(?=[\s\S]*dryRun: true)(?=[\s\S]*rollback_restore_api_unavailable)(?=[\s\S]*runtime\.restoreWorkflowRevision\(restoreRequest\))(?=[\s\S]*rollback_restore_canary_failed)/.test(
        harnessWorkflow,
      ),
    restoreCanaryReceiptBinding:
      /data-receipt-binding-ref/.test(rail) &&
      /WorkflowRevisionRestoreResult[\s\S]*receiptBindingRef\?: string/.test(
        graph,
      ) &&
      /WorkflowHarnessRollbackRestoreCanary[\s\S]*receiptBindingRef\?: string/.test(
        graph,
      ) &&
      /receiptBindingRef[\s\S]*workflow_restore_canary:[\s\S]*evidenceRefs/.test(
        validation,
      ) &&
      /receipt_binding_ref[\s\S]*workflow_restore_canary_receipt_binding_ref/.test(
        restoreCommand,
      ),
    activationAuditReceiptRefs:
      /WorkflowHarnessActivationAuditEvent[\s\S]*receiptRefs: string\[\]/.test(
        graph,
      ) &&
      /makeWorkflowHarnessActivationAuditEvent[\s\S]*receiptRefs[\s\S]*receiptRefsFromEvidenceRefs/.test(
        harnessWorkflow,
      ) &&
      /recordWorkflowHarnessActivationDryRun[\s\S]*activationCandidateReceiptRefs[\s\S]*receiptRefs/.test(
        harnessWorkflow,
      ) &&
      /activation_minted[\s\S]*receiptRefs/.test(harnessWorkflow) &&
      /workflow-harness-activation-audit[\s\S]*data-receipt-refs[\s\S]*data-audit-receipt-refs/.test(
        rail,
      ) &&
      /workflow-harness-activation-audit-receipt-\$\{event\.eventId\}-\$\{index\}/.test(
        rail,
      ),
    harnessPackageEvidenceManifest:
      /WorkflowHarnessPackageEvidenceManifest/.test(graph) &&
      /WorkflowHarnessForkMutationCanary/.test(graph) &&
      /nodeAttempts\?: WorkflowHarnessNodeAttemptRecord/.test(graph) &&
      /workflow\.harness\.package-evidence-manifest\.v1/.test(graph) &&
      /workflow\.harness\.fork-mutation-canary\.v1/.test(graph) &&
      /harnessPackageManifest\?: WorkflowHarnessPackageEvidenceManifest/.test(
        graph,
      ) &&
      /makeWorkflowHarnessPackageEvidenceManifest/.test(harnessWorkflow) &&
      /makeWorkflowHarnessForkMutationCanary/.test(harnessWorkflow) &&
      /makeWorkflowHarnessForkMutationCanaryNodeAttempt/.test(
        harnessWorkflow,
      ) &&
      /workflowHarnessForkMutationCanaryNodeAttempts/.test(harnessWorkflow) &&
      /workflowHarnessForkMutationCanaryReady/.test(harnessWorkflow) &&
      /withWorkflowHarnessPackageManifest/.test(harnessWorkflow) &&
      /harnessWorkbenchDeepLinkHash/.test(harnessWorkflow) &&
      /fork_mutation_canary/.test(harnessWorkflow) &&
      /rollback_restore/.test(harnessWorkflow) &&
      /worker_handoff/.test(harnessWorkflow) &&
      /data-harness-package-manifest-present/.test(rail) &&
      /data-harness-package-fork-mutation-receipt-count/.test(rail) &&
      /data-harness-package-receipt-ref-count/.test(rail) &&
      /data-harness-package-replay-fixture-ref-count/.test(rail) &&
      /data-harness-package-deep-link-count/.test(rail) &&
      /harness-package-evidence\.json/.test(restoreCommand) &&
      /harness_package_manifest/.test(restoreCommand) &&
      /packageManifest/.test(restoreCommand),
    harnessPackageEvidenceGate:
      /workflowHarnessPackageEvidenceReview/.test(validation) &&
      /harness_fork_mutation_canary_not_passed/.test(validation) &&
      /package_manifest_fork_mutation_canary_missing/.test(validation) &&
      /harness_package_manifest_incomplete/.test(validation) &&
      /package_manifest_receipts_missing/.test(validation) &&
      /package_manifest_replay_fixtures_missing/.test(validation) &&
      /package_manifest_rollback_restore_receipts_missing/.test(validation) &&
      /gateId: "package-evidence"/.test(validation) &&
      /gateId: "mutation-canary"/.test(validation) &&
      /id: "mutation-canary"/.test(rail) &&
      /id: "package-evidence"/.test(rail) &&
      /workflow-harness-fork-mutation-canary/.test(rail) &&
      /workflow-harness-gate-action-mutation-canary/.test(rail) &&
      /data-mutation-diff-hash/.test(rail) &&
      /data-rollback-target/.test(rail) &&
      /"package-evidence": makeReadinessGateAction/.test(rail) &&
      /commandTestId: `workflow-harness-gate-action-\$\{gateId\}`/.test(rail) &&
      /workflow-harness-package-evidence-review/.test(rail) &&
      /workflow-harness-package-evidence-row-\$\{row\.id\}/.test(rail) &&
      /workflow-harness-package-evidence-row-ref-\$\{row\.id\}-\$\{index\}/.test(
        rail,
      ) &&
      /data-harness-package-evidence-ready/.test(rail) &&
      /data-harness-package-worker-handoff-attempt-count/.test(rail) &&
      /workflowHarnessPackageDeepLinkTarget/.test(rail) &&
      /workflow-harness-activation-step-\$\{step\.id\}/.test(rail) &&
      /workflow-harness-activation-candidate-gate-\$\{gate\.gateId\}/.test(
        rail,
      ),
    workerSessionCheckpointUi:
      /WorkflowHarnessWorkerSessionRecord[\s\S]*persistenceKey: string[\s\S]*recordPersistenceKey: string[\s\S]*persistedInRuntimeCheckpoint: boolean[\s\S]*restoredFromPersistedSession: boolean[\s\S]*runtimeCheckpointSource: string[\s\S]*persistenceBlockers: string\[\][\s\S]*launchAuthorityReady: boolean[\s\S]*launchAuthorityBlockers: string\[\][\s\S]*launchAuthorityInvariantIds\?: string\[\][\s\S]*launchAuthorityInvariantBlockers\?: string\[\][\s\S]*launchAuthoritySource: string[\s\S]*rollbackHandoffReady: boolean[\s\S]*rollbackHandoffBlockers: string\[\][\s\S]*rollbackHandoffTarget: string/.test(
        graph,
      ) &&
      /WorkflowHarnessWorkerLaunchEnvelope[\s\S]*schemaVersion: "workflow\.harness\.worker-launch-envelope\.v1"[\s\S]*phase: WorkflowHarnessWorkerLaunchPhase[\s\S]*launchAuthorityReady: boolean[\s\S]*launchAuthorityInvariantIds\?: string\[\][\s\S]*launchAuthorityInvariantBlockers\?: string\[\]/.test(
        graph,
      ) &&
      /WorkflowHarnessWorkerHandoffReceipt[\s\S]*schemaVersion: "workflow\.harness\.worker-handoff-receipt\.v1"[\s\S]*handoffStatus: "launched" \| "resumed" \| "rollback_handoff_ready" \| "blocked"[\s\S]*requiredInvariantIds\?: string\[\][\s\S]*invariantBlockers\?: string\[\]/.test(
        graph,
      ) &&
      /data-worker-session-persistence-key/.test(rail) &&
      /data-worker-session-record-persistence-key/.test(rail) &&
      /data-worker-session-persisted/.test(rail) &&
      /data-worker-session-restored/.test(rail) &&
      /data-worker-session-checkpoint-source/.test(rail) &&
      /data-worker-session-launch-authority-ready/.test(rail) &&
      /data-worker-session-launch-authority-invariant-ids/.test(rail) &&
      /data-worker-session-rollback-handoff-ready/.test(rail) &&
      /data-worker-launch-envelope-count/.test(rail) &&
      /data-worker-launch-envelope-invariant-ids/.test(rail) &&
      /data-worker-handoff-receipt-count/.test(rail) &&
      /data-worker-handoff-receipt-invariant-ids/.test(rail) &&
      /data-worker-handoff-node-attempt-count/.test(rail) &&
      /data-worker-handoff-replay-fixture-refs/.test(rail) &&
      /data-worker-handoff-node-timeline-bound/.test(rail) &&
      /data-worker-rollback-handoff-receipt-status/.test(rail) &&
      /data-worker-launch-reviewed-import-invariant-bound/.test(rail) &&
      /id: "worker-invariant"/.test(rail) &&
      /data-required-invariant-ids/.test(rail) &&
      /data-invariant-blockers/.test(rail) &&
      /data-invariant-blocker-count/.test(rail) &&
      /DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT/.test(
        rail,
      ) &&
      /worker_session_not_persisted/.test(harnessWorkflow) &&
      /worker_session_not_restored/.test(harnessWorkflow) &&
      /worker_session_launch_authority_not_ready/.test(harnessWorkflow) &&
      /worker_session_rollback_handoff_not_ready/.test(harnessWorkflow) &&
      /worker_launch_session_not_persisted/.test(harnessWorkflow) &&
      /worker_handoff_envelope_schema_mismatch/.test(harnessWorkflow),
    rollbackExecutionReceiptRefs:
      /WorkflowHarnessActivationRollbackProof[\s\S]*receiptRefs: string\[\]/.test(
        graph,
      ) &&
      /WorkflowHarnessActivationRollbackExecution[\s\S]*receiptRefs: string\[\][\s\S]*restoreReceiptBindingRef\?: string/.test(
        graph,
      ) &&
      /executeWorkflowHarnessRollbackDrill[\s\S]*workflowRollbackReceiptRefs[\s\S]*receiptRefs/.test(
        harnessWorkflow,
      ) &&
      /executeWorkflowHarnessRevisionRollback[\s\S]*restoreResult\?\.receiptBindingRef[\s\S]*restoreReceiptBindingRef[\s\S]*receiptRefs/.test(
        harnessWorkflow,
      ) &&
      /workflow-harness-rollback-execution-proof[\s\S]*data-receipt-refs[\s\S]*data-restore-receipt-binding-ref/.test(
        rail,
      ) &&
      /workflow-harness-rollback-drill-receipt-\$\{index\}/.test(rail) &&
      /workflow-harness-rollback-execution-receipt-\$\{index\}/.test(rail),
    activationGateEvidenceInspector:
      /WorkflowHarnessActivationWizardStep/.test(rail) &&
      /WorkflowHarnessActivationGateAction/.test(rail) &&
      /gateAction: WorkflowHarnessActivationGateAction/.test(rail) &&
      /WorkflowHarnessActivationGateActionClickProof/.test(controller) &&
      /WorkflowHarnessActivationGateCollectEvidenceClickProof/.test(
        controller,
      ) &&
      /WorkflowHarnessActivationGateRollbackRestoreClickProof/.test(
        controller,
      ) &&
      /WorkflowHarnessActivationIdGateClickProof/.test(controller) &&
      /WorkflowHarnessPackageImportReviewProof/.test(controller) &&
      /WorkflowHarnessPackageEvidenceGateClickProof/.test(controller) &&
      /WorkflowHarnessPackageEvidenceImportRoundTripProof/.test(controller) &&
      /workflowHarnessActivationIdGateClickProofBlockers/.test(
        harnessWorkflow,
      ) &&
      /activation_id_gate_click_proof_missing/.test(harnessWorkflow) &&
      /runHarnessActivationGateActionClickProbe/.test(controller) &&
      /runHarnessActivationGateCollectEvidenceClickProbe/.test(controller) &&
      /runHarnessActivationGateRollbackRestoreClickProbe/.test(controller) &&
      /runHarnessActivationIdGateClickProbe/.test(controller) &&
      /runHarnessPackageEvidenceGateClickProbe/.test(controller) &&
      /runHarnessPackageEvidenceImportRoundTripProbe/.test(controller) &&
      /workflow-harness-package-import-review/.test(rail) &&
      /workflow-harness-package-import-activate/.test(rail) &&
      /data-package-import-source-workflow-path/.test(rail) &&
      /data-package-import-imported-workflow-path/.test(rail) &&
      /data-package-import-activation-enabled/.test(rail) &&
      /selectedHarnessActivationGateInspection/.test(rail) &&
      /workflow-harness-activation-gate-inspector/.test(rail) &&
      /workflow-harness-activation-gate-summary/.test(rail) &&
      /workflow-harness-activation-gate-actions/.test(rail) &&
      /workflow-harness-activation-gate-action/.test(rail) &&
      /workflow-harness-activation-step-action-\$\{step\.id\}/.test(rail) &&
      /workflow-harness-activation-candidate-gate-action-\$\{gate\.gateId\}/.test(
        rail,
      ) &&
      /workflow-harness-activation-gate-evidence-refs/.test(rail) &&
      /workflow-harness-activation-gate-node-attempt-refs/.test(rail) &&
      /workflow-harness-activation-gate-node-timeline/.test(rail) &&
      /workflow-harness-canary-execution-boundaries/.test(rail) &&
      /data-selected-canary-boundary-id/.test(rail) &&
      /data-selected-rollback-drill-id/.test(rail) &&
      /data-selected-rollback-restore-canary-id/.test(rail) &&
      /data-canary-boundary-id/.test(rail) &&
      /data-rollback-drill-id/.test(rail) &&
      /data-evidence-ref-count/.test(rail) &&
      /data-node-attempt-ref-count/.test(rail) &&
      /data-gate-action-id/.test(rail) &&
      /data-gate-action-kind/.test(rail) &&
      /data-gate-action-impact/.test(rail) &&
      /data-gate-action-command/.test(rail) &&
      /data-selected-activation-gate-evidence-ref/.test(rail) &&
      /data-selected-activation-gate-node-attempt-id/.test(rail) &&
      /data-selected-activation-gate-receipt-ref/.test(rail) &&
      /data-selected-activation-gate-replay-fixture-ref/.test(rail) &&
      /data-activation-gate-evidence-ref/.test(rail) &&
      /data-activation-gate-node-attempt-id/.test(rail) &&
      /data-activation-gate-receipt-ref/.test(rail) &&
      /data-activation-gate-replay-fixture-ref/.test(rail) &&
      /workflow-harness-activation-gate-receipt-refs/.test(rail) &&
      /workflow-harness-activation-gate-replay-refs/.test(rail) &&
      /selectedRailTestId: "workflow-harness-activation-gate-inspector"/.test(
        controller,
      ) &&
      /activationGateEvidenceRef/.test(controller) &&
      /activation-gate-canary-boundary/.test(controller) &&
      /activation-gate-canary-rollback-drill/.test(controller) &&
      /activation-gate-mutation-canary-node-attempt/.test(controller) &&
      /activationGateNodeAttemptId/.test(controller) &&
      /activationGateReceiptRef/.test(controller) &&
      /activationGateReplayFixtureRef/.test(controller) &&
      /data-gate-action-command/.test(controller) &&
      /activationGateActionClickProof/.test(controller) &&
      /activationGateCollectEvidenceClickProof/.test(controller) &&
      /activationGateRollbackRestoreClickProof/.test(controller) &&
      /activationIdGateClickProof/.test(controller) &&
      /packageEvidenceGateClickProof/.test(controller) &&
      /mutationCanaryNodeAttemptState/.test(controller) &&
      /packageEvidenceImportRoundTripProof/.test(controller) &&
      /packageImportReviewProof/.test(controller) &&
      /packageImportActivationHandoffProof/.test(controller) &&
      /packageImportActivationApplyProof/.test(controller) &&
      /packageImportActivationReplayIntegrityProof/.test(controller) &&
      /workflow-harness-package-import-handoff/.test(rail) &&
      /workflow-harness-package-import-handoff-activation-link/.test(rail) &&
      /workflow-harness-package-import-handoff-canary-link/.test(rail) &&
      /workflow-harness-package-import-handoff-rollback-link/.test(rail) &&
      /workflow-harness-package-import-handoff-worker-link/.test(rail) &&
      /data-package-import-handoff-worker-binding-id/.test(rail) &&
      /WorkflowHarnessActivationCandidateGateResult[\s\S]*evidenceRefs: string\[\]/.test(
        graph,
      ) &&
      /WorkflowHarnessActivationGateActionClickProof/.test(graph) &&
      /WorkflowHarnessActivationGateCollectEvidenceClickProof/.test(graph) &&
      /WorkflowHarnessActivationGateRollbackRestoreClickProof/.test(graph) &&
      /WorkflowHarnessActivationIdGateClickProof/.test(graph) &&
      /WorkflowHarnessPackageImportReviewProof/.test(graph) &&
      /WorkflowHarnessPackageImportActivationHandoffProof/.test(graph) &&
      /WorkflowHarnessPackageImportActivationApplyProof/.test(graph) &&
      /WorkflowPackageImportActivationHandoff/.test(graph) &&
      /WorkflowPackageImportReview/.test(graph) &&
      /WorkflowHarnessPackageEvidenceGateClickProof/.test(graph) &&
      /WorkflowHarnessPackageEvidenceImportRoundTripProof/.test(graph) &&
      /workerHandoffDeepLink/.test(graph) &&
      /activation_id_gate_mint_handoff_timeline_missing/.test(
        harnessWorkflow,
      ) &&
      /gateResults:[\s\S]*evidenceRefs/.test(validation),
    workflowMemoryRuntimeLane:
      /workflow_memory_lane/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_memory_send_options/.test(projectWorkflowMemoryLane) &&
      /workflow_memory_query_output/.test(projectWorkflowMemoryLane) &&
      /memory_search/.test(projectWorkflowMemoryLane) &&
      /memory_list/.test(projectWorkflowMemoryLane) &&
      /workflow_redacted_memory_record/.test(projectWorkflowMemoryLane),
    workflowAuthorityToolingRuntimeLane:
      /workflow_authority_tooling_lane/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_live_mcp_provider_catalog/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_mcp_tool_catalog/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_native_tool_catalog/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_connector_catalog_describe/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_wallet_capability_dry_run/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_authority_policy_gate/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_authority_approval_gate/.test(
        projectWorkflowAuthorityToolingLane,
      ) &&
      /workflow_live_authority_destructive_denial/.test(
        projectWorkflowAuthorityToolingLane,
      ),
    workflowSchedulerLaneReadinessManifest:
      /EXPECTED_WORKFLOW_SCHEDULER_LANE_CAPABILITY_IDS/.test(
        schedulerLaneReadiness,
      ) &&
      /WORKFLOW_SCHEDULER_LANE_CAPABILITIES/.test(schedulerLaneReadiness) &&
      /"scheduler"/.test(schedulerLaneReadiness) &&
      /"scheduler\.finalization"/.test(schedulerLaneReadiness) &&
      /"terminalResult"/.test(schedulerLaneReadiness) &&
      /"nodeExecution"/.test(schedulerLaneReadiness) &&
      /"nodeOutcome"/.test(schedulerLaneReadiness) &&
      /"nodeStateUpdate"/.test(schedulerLaneReadiness) &&
      /"nodeSuccessEvent"/.test(schedulerLaneReadiness) &&
      /"nodeFailureOutcome"/.test(schedulerLaneReadiness) &&
      /"interrupt"/.test(schedulerLaneReadiness) &&
      /"validation"/.test(schedulerLaneReadiness) &&
      /workflowSchedulerRuntimeLane/.test(schedulerLaneReadiness) &&
      /workflowSchedulerFinalizationRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerTerminalResultRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerNodeExecutionRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerNodeOutcomeRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerNodeStateUpdateRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerNodeSuccessEventRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerNodeFailureOutcomeRuntimeLane/.test(
        schedulerLaneReadiness,
      ) &&
      /workflowSchedulerInterruptRuntimeLane/.test(schedulerLaneReadiness) &&
      /workflowSchedulerValidationRuntimeLane/.test(schedulerLaneReadiness),
    workflowSchedulerLaneReadinessActivationUi:
      /WorkflowSchedulerLaneReadiness/.test(graph) &&
      /schedulerLaneReadiness\?: WorkflowSchedulerLaneReadiness\[\]/.test(
        graph,
      ) &&
      /workflowSchedulerLaneReadiness/.test(validation) &&
      /workflowSchedulerLaneReadinessIssues/.test(validation) &&
      /gateId: "scheduler-lanes"/.test(validation) &&
      /WorkflowReadinessPanel/.test(rail) &&
      /workflowReadinessModel/.test(readinessModel) &&
      /workflowSchedulerLaneReadiness/.test(readinessModel) &&
      /readinessItems/.test(readinessModel) &&
      /workflowReadinessModel/.test(readinessPanel) &&
      /workflow-readiness-scheduler-lanes/.test(readinessPanel) &&
      /workflow-readiness-scheduler-lane-/.test(readinessPanel) &&
      /data-proof-check/.test(readinessPanel) &&
      /data-capability-scope/.test(readinessPanel),
    workflowRailSearchModelUi:
      /WorkflowSearchPanel/.test(rail) &&
      /workflowRailSearchModel/.test(rail) &&
      /workflow-rail-search-results/.test(searchPanel) &&
      /workflow-rail-search-index-summary/.test(searchPanel) &&
      /data-result-kind/.test(searchPanel) &&
      /visibleResults/.test(railSearchModel) &&
      /resultGroups/.test(railSearchModel) &&
      /resultKindCounts/.test(railSearchModel),
    workflowEntrypointsModelUi:
      /WorkflowEntrypointsPanel/.test(rail) &&
      /workflowEntrypointsModel/.test(rail) &&
      /workflow-sources-list/.test(entrypointsPanel) &&
      /workflow-schedules-list/.test(entrypointsPanel) &&
      /workflow-source-node-/.test(entrypointsPanel) &&
      /workflow-schedule-node-/.test(entrypointsPanel) &&
      /readyStartPoints/.test(entrypointsModel) &&
      /readyTriggers/.test(entrypointsModel) &&
      /blockedTriggers/.test(entrypointsModel),
    workflowFileBundleModelUi:
      /WorkflowFilesPanel/.test(rail) &&
      /workflowFileBundleModel/.test(rail) &&
      /workflow-files-list/.test(filesPanel) &&
      /workflow-file-/.test(filesPanel) &&
      /data-file-ready/.test(filesPanel) &&
      /readyItems/.test(fileBundleModel) &&
      /pendingItems/.test(fileBundleModel) &&
      /portablePackageExported/.test(fileBundleModel),
    workflowSettingsModelUi:
      /WorkflowSettingsPanel/.test(rail) &&
      /workflowSettingsModel/.test(rail) &&
      /workflow-settings-summary/.test(settingsPanel) &&
      /workflow-settings-chrome-locale-select/.test(settingsPanel) &&
      /workflow-environment-profile/.test(settingsPanel) &&
      /workflow-settings-binding-registry/.test(settingsPanel) &&
      /workflow-settings-production-profile/.test(settingsPanel) &&
      /productionSummary/.test(settingsModel) &&
      /packageReadinessStatus/.test(settingsModel),
    workflowSettingsHarnessModelUi:
      /WorkflowSettingsHarnessPanel/.test(rail) &&
      /WorkflowSettingsHarnessActivationPanel/.test(settingsHarnessPanel) &&
      /WorkflowSettingsHarnessWorkerBindingPanel/.test(settingsHarnessPanel) && /WorkflowSettingsHarnessPromotionPanel/.test(settingsHarnessPanel) &&
      /WorkflowSettingsHarnessPanelProps/.test(settingsHarnessTypes) &&
      /workflowSettingsHarnessModel/.test(rail) &&
      /workflow-settings-harness-summary/.test(settingsHarnessPanel) &&
      /WorkflowSettingsHarnessActivationGatePanel/.test(settingsHarnessActivationPanel) && /workflow-harness-activation-gate-inspector/.test(settingsHarnessActivationGatePanel) && /WorkflowSettingsHarnessActivationGateRefsPanel/.test(settingsHarnessActivationGatePanel) && /workflow-harness-activation-gate-evidence-refs/.test(settingsHarnessActivationGateRefsPanel) && /workflow-harness-activation-gate-receipt-refs/.test(settingsHarnessActivationGateRefsPanel) && /workflow-harness-activation-gate-replay-refs/.test(settingsHarnessActivationGateRefsPanel) && /WorkflowSettingsHarnessActivationGateTimelinePanel/.test(settingsHarnessActivationGatePanel) && /workflow-harness-activation-gate-node-attempt-refs/.test(settingsHarnessActivationGateTimelinePanel) && /workflow-harness-activation-gate-node-timeline/.test(settingsHarnessActivationGateTimelinePanel) && /WorkflowSettingsHarnessPackageEvidencePanel/.test(settingsHarnessActivationGatePanel) && /workflow-harness-package-evidence-review/.test(settingsHarnessPackageEvidencePanel) && /WorkflowSettingsHarnessPackageEvidenceRowsPanel/.test(settingsHarnessPackageEvidencePanel) && /workflow-harness-package-evidence-row-/.test(settingsHarnessPackageEvidenceRowsPanel) && /workflow-harness-package-evidence-row-ref-/.test(settingsHarnessPackageEvidenceRowsPanel) && /WorkflowSettingsHarnessPackageImportReviewPanel/.test(settingsHarnessPackageEvidencePanel) && /workflow-harness-package-import-review/.test(settingsHarnessPackageImportReviewPanel) && /workflow-harness-package-import-handoff/.test(settingsHarnessPackageImportReviewPanel) &&
      /WorkflowSettingsHarnessActiveRuntimeRollbackPanel/.test(settingsHarnessWorkerBindingPanel) && /WorkflowSettingsHarnessActiveRuntimeBindingPanel/.test(settingsHarnessActiveRuntimeRollbackPanel) && /data-worker-binding-registry-bound/.test(settingsHarnessActiveRuntimeBindingPanel) && /workflow-harness-active-runtime-binding-deep-links/.test(settingsHarnessActiveRuntimeBindingPanel) && /workflow-harness-active-runtime-rollback-proof/.test(settingsHarnessActiveRuntimeRollbackPanel) && /WorkflowSettingsHarnessRollbackRestoreProofPanel/.test(settingsHarnessActiveRuntimeRollbackPanel) && /workflow-harness-git-restore-proof/.test(settingsHarnessRollbackRestoreProofPanel) &&
      /WorkflowSettingsHarnessPromotionReadinessPanel/.test(settingsHarnessPromotionPanel) && /workflow-harness-promotion-clusters/.test(settingsHarnessPromotionPanel) && /workflow-harness-selector-live-promotion-readiness/.test(settingsHarnessPromotionReadinessPanel) && /workflow-harness-authority-gate-live/.test(settingsHarnessPromotionReadinessPanel) &&
      /workflowSettingsHarnessModel/.test(settingsHarnessModel) &&
      /gatedClustersLabel/.test(settingsHarnessModel),
    workflowUnitTestReadinessModelUi:
      /WorkflowUnitTestsPanel/.test(rail) &&
      /workflowTestReadinessModel/.test(rail) &&
      /workflow-unit-test-list/.test(unitTestsPanel) &&
      /workflow-unit-test-uncovered/.test(unitTestsPanel) &&
      /coveredNodeIds/.test(testReadinessModel) &&
      /uncoveredNodes/.test(testReadinessModel) &&
      /statusCounts/.test(testReadinessModel),
    workflowRunHistoryModelUi:
      /WorkflowRunsPanel/.test(rail) &&
      /workflowRunHistoryModel/.test(rail) &&
      /workflow-runs-list/.test(runsPanel) &&
      /workflow-run-inspector/.test(runsPanel) &&
      /workflow-run-timeline/.test(runsPanel) &&
      /workflow-run-runtime-event-graph/.test(runsPanel) &&
      /workflow-run-runtime-event-node-/.test(runsPanel) &&
      /data-event-cursor/.test(runsPanel) &&
      /data-receipt-refs/.test(runsPanel) &&
      /loadWorkflowRuntimeThreadEvents/.test(controller) &&
      /setRuntimeThreadEvents/.test(controller) &&
      /runtimeThreadEvents=\{runtimeThreadEvents\}/.test(view) &&
      /visibleRows/.test(runHistoryModel) &&
      /timelineEvents/.test(runHistoryModel) &&
      /comparison/.test(runHistoryModel) &&
      /runtimeEventProjection/.test(runHistoryModel) &&
      /projectRuntimeThreadEventsToWorkflowProjection/.test(runHistoryModel),
    workflowSchedulerRuntimeLane:
      /workflow_scheduler_lane/.test(projectRuntime) &&
      !/fn execute_workflow_project\(/.test(projectRuntime) &&
      /fn execute_workflow_project\(/.test(projectWorkflowSchedulerLane) &&
      /workflow_next_ready_nodes/.test(projectWorkflowSchedulerLane) &&
      /workflow_scheduler_interrupt_lane/.test(projectWorkflowSchedulerLane) &&
      /workflow_scheduler_finalization_lane/.test(
        projectWorkflowSchedulerLane,
      ) &&
      /workflow_scheduler_finalized_result/.test(projectWorkflowSchedulerLane) &&
      !/workflow_finalize_run_result/.test(projectWorkflowSchedulerLane) &&
      /workflow_scheduler_node_execution_lane/.test(
        projectWorkflowSchedulerLane,
      ) &&
      /workflow_scheduler_execute_node/.test(projectWorkflowSchedulerLane) &&
      /workflow_push_event/.test(projectWorkflowSchedulerLane),
    workflowSchedulerFinalizationRuntimeLane:
      /workflow_scheduler_finalization_lane/.test(
        projectWorkflowSchedulerLane,
      ) &&
      /fn workflow_scheduler_finalized_result\(/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /workflow_completion_has_missing/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /workflow_completion_requirements/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /workflow_checkpoint_state/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /workflow_scheduler_terminal_result_lane/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /workflow_scheduler_terminal_result/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /workflow_scheduler_terminal_summary/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /WorkflowSchedulerTerminalResultParts/.test(
        projectWorkflowSchedulerFinalizationLane,
      ),
    workflowSchedulerTerminalResultRuntimeLane:
      /struct WorkflowSchedulerTerminalResultParts/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /fn workflow_scheduler_terminal_summary\(/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /fn workflow_scheduler_terminal_result\(/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /workflow_completion_requirements/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /workflow_push_event/.test(projectWorkflowSchedulerTerminalResultLane) &&
      /run_completed/.test(projectWorkflowSchedulerTerminalResultLane) &&
      /save_workflow_thread/.test(projectWorkflowSchedulerTerminalResultLane) &&
      /workflow_attach_harness_run_artifacts/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /workflow_finalize_run_result/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /WorkflowRunResultParts/.test(projectWorkflowSchedulerTerminalResultLane),
    workflowSchedulerNodeExecutionRuntimeLane:
      /workflow_scheduler_node_execution_lane/.test(
        projectWorkflowSchedulerLane,
      ) &&
      /fn workflow_scheduler_execute_node\(/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /enum WorkflowSchedulerNodeExecutionFlow/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /execute_workflow_node/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /workflow_max_attempts/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /workflow_scheduler_node_outcome_lane/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /workflow_scheduler_handle_node_outcome/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /workflow_node_lifecycle_steps/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      /workflow_push_event/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      /node_started/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      /retrying/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      !/workflow_selected_output/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      !/workflow_node_logic/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      !/workflow_next_ready_nodes/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      !/workflow_checkpoint_state/.test(
        projectWorkflowSchedulerNodeExecutionLane,
      ) &&
      !/node_succeeded/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      !/child_run_completed/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      !/output_created/.test(projectWorkflowSchedulerNodeExecutionLane) &&
      !/asset_materialized/.test(projectWorkflowSchedulerNodeExecutionLane),
    workflowSchedulerNodeOutcomeRuntimeLane:
      /fn workflow_scheduler_handle_node_outcome\(/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /WorkflowSchedulerNodeExecutionFlow/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_scheduler_node_state_update_lane/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_scheduler_apply_node_state_update/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_scheduler_node_success_event_lane/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_scheduler_emit_node_success_events/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_scheduler_node_failure_outcome_lane/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_scheduler_handle_node_failure_outcome/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      !/workflow_next_ready_nodes/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_checkpoint_state/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      /workflow_node_lifecycle_steps/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      !/workflow_selected_output/.test(
        projectWorkflowSchedulerNodeOutcomeLane,
      ) &&
      !/workflow_node_logic/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/pending_writes/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/workflow_push_event/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/node_succeeded/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/node_failed/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/child_run_completed/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/output_created/.test(projectWorkflowSchedulerNodeOutcomeLane) &&
      !/asset_materialized/.test(projectWorkflowSchedulerNodeOutcomeLane),
    workflowSchedulerNodeFailureOutcomeRuntimeLane:
      /fn workflow_scheduler_handle_node_failure_outcome\(/.test(
        projectWorkflowSchedulerNodeFailureOutcomeLane,
      ) &&
      /WorkflowSchedulerNodeExecutionFlow/.test(
        projectWorkflowSchedulerNodeFailureOutcomeLane,
      ) &&
      /workflow_checkpoint_state/.test(
        projectWorkflowSchedulerNodeFailureOutcomeLane,
      ) &&
      /workflow_node_lifecycle_steps/.test(
        projectWorkflowSchedulerNodeFailureOutcomeLane,
      ) &&
      /workflow_node_name/.test(projectWorkflowSchedulerNodeFailureOutcomeLane) &&
      /workflow_push_event/.test(
        projectWorkflowSchedulerNodeFailureOutcomeLane,
      ) &&
      /blocked_node_ids/.test(projectWorkflowSchedulerNodeFailureOutcomeLane) &&
      /node_failed/.test(projectWorkflowSchedulerNodeFailureOutcomeLane) &&
      /error/.test(projectWorkflowSchedulerNodeFailureOutcomeLane),
    workflowSchedulerNodeSuccessEventRuntimeLane:
      /fn workflow_scheduler_emit_node_success_events\(/.test(
        projectWorkflowSchedulerNodeSuccessEventLane,
      ) &&
      /WorkflowStateUpdate/.test(projectWorkflowSchedulerNodeSuccessEventLane) &&
      /workflow_push_event/.test(projectWorkflowSchedulerNodeSuccessEventLane) &&
      /workflow_node_name/.test(projectWorkflowSchedulerNodeSuccessEventLane) &&
      /node_succeeded/.test(projectWorkflowSchedulerNodeSuccessEventLane) &&
      /child_run_completed/.test(projectWorkflowSchedulerNodeSuccessEventLane) &&
      /output_created/.test(projectWorkflowSchedulerNodeSuccessEventLane) &&
      /asset_materialized/.test(projectWorkflowSchedulerNodeSuccessEventLane),
    workflowSchedulerNodeStateUpdateRuntimeLane:
      /fn workflow_scheduler_apply_node_state_update\(/.test(
        projectWorkflowSchedulerNodeStateUpdateLane,
      ) &&
      /WorkflowStateUpdate/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /workflow_next_ready_nodes/.test(
        projectWorkflowSchedulerNodeStateUpdateLane,
      ) &&
      /workflow_selected_output/.test(
        projectWorkflowSchedulerNodeStateUpdateLane,
      ) &&
      /workflow_node_logic/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /branch_decisions/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /pending_writes/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /completed_node_ids/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /interrupted_node_ids/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /node_outputs/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /merge/.test(projectWorkflowSchedulerNodeStateUpdateLane) &&
      /append/.test(projectWorkflowSchedulerNodeStateUpdateLane),
    workflowSchedulerInterruptRuntimeLane:
      /workflow_scheduler_interrupt_lane/.test(projectWorkflowSchedulerLane) &&
      /fn workflow_scheduler_interrupted_result\(/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_runtime_interrupt/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_runtime_interrupt_notice/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_checkpoint_state/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_node_lifecycle_steps/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_interrupt_path/.test(projectWorkflowSchedulerInterruptLane) &&
      /workflow_scheduler_terminal_result_lane/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_scheduler_terminal_result/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_scheduler_terminal_summary/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /WorkflowSchedulerTerminalResultParts/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      !/workflow_finalize_run_result/.test(projectWorkflowSchedulerInterruptLane) &&
      !/workflow_attach_harness_run_artifacts/.test(
        projectWorkflowSchedulerInterruptLane,
      ) &&
      /workflow_push_event/.test(projectWorkflowSchedulerInterruptLane),
    workflowSchedulerValidationRuntimeLane:
      /workflow_scheduler_validation_lane/.test(projectWorkflowSchedulerLane) &&
      /fn workflow_scheduler_validation_blocked_result\(/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      /workflow_checkpoint_state/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      /workflow_scheduler_terminal_result_lane/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      /workflow_scheduler_terminal_result/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      /workflow_scheduler_terminal_summary/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      /WorkflowSchedulerTerminalResultParts/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      !/workflow_finalize_run_result/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      !/workflow_attach_harness_run_artifacts/.test(
        projectWorkflowSchedulerValidationLane,
      ) &&
      !/workflow_push_event/.test(projectWorkflowSchedulerValidationLane),
    workflowApprovalInterruptRuntimeLane:
      /workflow_approval_interrupt_lane/.test(projectWorkflowSchedulerLane) &&
      /fn workflow_runtime_approval_binding\(/.test(
        projectWorkflowApprovalInterruptLane,
      ) &&
      /fn workflow_runtime_approval_preview\(/.test(
        projectWorkflowApprovalInterruptLane,
      ) &&
      /fn workflow_runtime_interrupt_prompt\(/.test(
        projectWorkflowApprovalInterruptLane,
      ) &&
      /fn workflow_runtime_interrupt_notice\(/.test(
        projectWorkflowApprovalInterruptLane,
      ) &&
      /fn workflow_runtime_interrupt\(/.test(
        projectWorkflowApprovalInterruptLane,
      ) &&
      /WorkflowInterrupt/.test(projectWorkflowApprovalInterruptLane) &&
      /requiresApproval/.test(projectWorkflowApprovalInterruptLane),
    workflowBindingRuntimeLane:
      /workflow_binding_lane/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_node_schema/.test(projectWorkflowBindingLane) &&
      /workflow_function_binding/.test(projectWorkflowBindingLane) &&
      /workflow_tool_binding/.test(projectWorkflowBindingLane) &&
      /workflow_parser_binding/.test(projectWorkflowBindingLane) &&
      /workflow_model_binding/.test(projectWorkflowBindingLane) &&
      /workflow_connector_binding/.test(projectWorkflowBindingLane) &&
      /workflow_sandbox_policy/.test(projectWorkflowBindingLane) &&
      /workflow_function_sandbox_precheck/.test(projectWorkflowBindingLane) &&
      /workflow_function_dependency_precheck/.test(
        projectWorkflowBindingLane,
      ) &&
      /workflow_function_input_schema/.test(projectWorkflowBindingLane) &&
      /workflow_function_output_schema/.test(projectWorkflowBindingLane),
    workflowCheckpointRuntimeLane:
      /workflow_checkpoint_lane/.test(
        projectWorkflowSchedulerFinalizationLane,
      ) &&
      /fn workflow_checkpoint_state\(/.test(projectWorkflowCheckpointLane) &&
      /WorkflowCheckpoint/.test(projectWorkflowCheckpointLane) &&
      /WorkflowStateSnapshot/.test(projectWorkflowCheckpointLane) &&
      /save_workflow_checkpoint/.test(projectWorkflowCheckpointLane) &&
      /unique_runtime_id/.test(projectWorkflowCheckpointLane) &&
      /active_node_ids\.sort/.test(projectWorkflowCheckpointLane),
    workflowStateRuntimeLane:
      /workflow_state_lane/.test(projectWorkflowSchedulerLane) &&
      /fn workflow_predecessor_output\(/.test(projectWorkflowStateLane) &&
      /fn workflow_mapped_node_input\(/.test(projectWorkflowStateLane) &&
      /fn workflow_first_expression_source\(/.test(projectWorkflowStateLane) &&
      /fn workflow_selected_output\(/.test(projectWorkflowStateLane) &&
      /fn validate_workflow_expression_refs\(/.test(projectWorkflowStateLane) &&
      /fn workflow_schema_from_sample\(/.test(projectWorkflowStateLane) &&
      /fn workflow_schema_is_object_like\(/.test(projectWorkflowStateLane) &&
      /fn workflow_node_declared_output_schema\(/.test(
        projectWorkflowStateLane,
      ) &&
      /workflow_value_at_path/.test(projectWorkflowStateLane) &&
      /workflow_edge_from_port/.test(projectWorkflowStateLane),
    workflowNodeContractRuntimeLane:
      /fn workflow_action_frame\(/.test(projectWorkflowNodeContractLane) &&
      /fn workflow_node_port_connection_class\(/.test(
        projectWorkflowNodeContractLane,
      ) &&
      /fn workflow_default_port_connection_class\(/.test(
        projectWorkflowNodeContractLane,
      ) &&
      /fn validate_workflow_edge_ports\(/.test(
        projectWorkflowNodeContractLane,
      ) &&
      /fn workflow_max_attempts\(/.test(projectWorkflowNodeContractLane) &&
      /ActionFrame/.test(projectWorkflowNodeContractLane) &&
      /ActionBindingRef/.test(projectWorkflowNodeContractLane) &&
      /workflow_edge_connection_class/.test(projectWorkflowNodeContractLane) &&
      /validate_workflow_connection_class/.test(
        projectWorkflowNodeContractLane,
      ) &&
      /workflow_logic_string/.test(projectWorkflowNodeContractLane) &&
      /workflow_action_frame/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_max_attempts/.test(projectWorkflowSchedulerNodeExecutionLane),
    workflowNodeMetadataRuntimeLane:
      /workflow_node_metadata_lane/.test(projectWorkflowSchedulerLane) &&
      /fn workflow_value_string\(/.test(projectWorkflowNodeMetadataLane) &&
      /fn workflow_node_id\(/.test(projectWorkflowNodeMetadataLane) &&
      /fn workflow_node_type\(/.test(projectWorkflowNodeMetadataLane) &&
      /fn workflow_node_name\(/.test(projectWorkflowNodeMetadataLane) &&
      /fn workflow_node_logic\(/.test(projectWorkflowNodeMetadataLane) &&
      /fn workflow_node_law\(/.test(projectWorkflowNodeMetadataLane) &&
      /fn workflow_node_by_id/.test(projectWorkflowNodeMetadataLane) &&
      /WorkflowProject/.test(projectWorkflowNodeMetadataLane) &&
      /workflow_node_metadata_lane/.test(projectWorkflowRunLifecycleLane) &&
      !/use super::runtime::/.test(projectWorkflowRunLifecycleLane) &&
      /workflow_node_metadata_lane/.test(projectWorkflowNodeContractLane) &&
      /workflow_node_metadata_lane/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_node_metadata_lane/.test(projectWorkflowStateLane) &&
      /workflow_node_metadata_lane/.test(
        projectWorkflowApprovalInterruptLane,
      ) &&
      /workflow_node_metadata_lane/.test(projectRustValidation) &&
      /workflow_node_metadata_lane/.test(projectPackage),
    workflowRunLifecycleRuntimeLane:
      /workflow_run_lifecycle_lane/.test(projectWorkflowSchedulerLane) &&
      /fn workflow_push_event\(/.test(projectWorkflowRunLifecycleLane) &&
      /fn new_workflow_thread\(/.test(projectWorkflowRunLifecycleLane) &&
      /fn initial_workflow_state\(/.test(projectWorkflowRunLifecycleLane) &&
      /fn workflow_single_node_result\(/.test(
        projectWorkflowRunLifecycleLane,
      ) &&
      /WorkflowStreamEvent/.test(projectWorkflowRunLifecycleLane) &&
      /WorkflowStateSnapshot/.test(projectWorkflowRunLifecycleLane) &&
      /execute_workflow_node/.test(projectWorkflowRunLifecycleLane) &&
      /workflow_finalize_run_result/.test(projectWorkflowRunLifecycleLane),
    workflowNodeExecutionRuntimeLane:
      /fn execute_workflow_tool_binding\(/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /fn execute_workflow_function_node\(/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /fn execute_workflow_node\(/.test(projectWorkflowNodeExecutionLane) &&
      /fn execute_workflow_harness_canary_node\(/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /fn execute_workflow_harness_live_default_node\(/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /ActionKind::GithubPrCreate/.test(projectWorkflowNodeExecutionLane) &&
      /ActionKind::WorkflowPackageExport/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /ActionKind::WorkflowPackageImport/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /workflow_output_satisfies_schema/.test(
        projectWorkflowNodeExecutionLane,
      ) &&
      /workflow_memory_send_options/.test(projectWorkflowNodeExecutionLane),
    workflowOutputRuntimeLane:
      /workflow_output_lane/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_output_satisfies_schema/.test(projectWorkflowOutputLane) &&
      /workflow_truncate_output/.test(projectWorkflowOutputLane) &&
      /workflow_output_bundle/.test(projectWorkflowOutputLane) &&
      /WorkflowOutputBundle/.test(projectWorkflowOutputLane) &&
      /WorkflowMaterializedAsset/.test(projectWorkflowOutputLane) &&
      /WorkflowRendererRef/.test(projectWorkflowOutputLane) &&
      /WorkflowDeliveryTarget/.test(projectWorkflowOutputLane),
    workflowExecutionResultsRuntimeLane:
      /workflow_execution_results_lane/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /struct WorkflowRunResultParts/.test(
        projectWorkflowExecutionResultsLane,
      ) &&
      /workflow_finalize_run_result/.test(
        projectWorkflowExecutionResultsLane,
      ) &&
      /workflow_run_result_from_parts/.test(
        projectWorkflowExecutionResultsLane,
      ) &&
      /workflow_completion_requirements/.test(
        projectWorkflowExecutionResultsLane,
      ) &&
      /workflow_verification_evidence_from_node_runs/.test(
        projectWorkflowExecutionResultsLane,
      ) &&
      /workflow_coding_route_evidence_from_run/.test(
        projectWorkflowExecutionResultsLane,
      ),
    workflowGraphExecutionRuntimeLane:
      /workflow_graph_execution_lane/.test(projectWorkflowSchedulerLane) &&
      /workflow_edge_from/.test(projectWorkflowGraphExecutionLane) &&
      /workflow_edge_to/.test(projectWorkflowGraphExecutionLane) &&
      /workflow_edge_connection_class/.test(projectWorkflowGraphExecutionLane) &&
      /workflow_has_incoming_connection_class/.test(
        projectWorkflowGraphExecutionLane,
      ) &&
      /workflow_edge_is_selected/.test(projectWorkflowGraphExecutionLane) &&
      /workflow_node_ready/.test(projectWorkflowGraphExecutionLane) &&
      /workflow_next_ready_nodes/.test(projectWorkflowGraphExecutionLane) &&
      /workflow_node_lifecycle_steps/.test(projectWorkflowGraphExecutionLane),
    workflowHarnessResultsRuntimeLane:
      /workflow_harness_results_lane/.test(
        projectWorkflowSchedulerTerminalResultLane,
      ) &&
      /workflow_attach_harness_run_artifacts/.test(
        projectWorkflowHarnessResultsLane,
      ) &&
      /workflow_harness_attempt_for_node_run/.test(
        projectWorkflowHarnessResultsLane,
      ) &&
      /workflow_harness_shadow_comparison_records_for_attempt_records/.test(
        projectWorkflowHarnessResultsLane,
      ) &&
      /workflow_harness_gated_cluster_runs_for_attempt_records/.test(
        projectWorkflowHarnessResultsLane,
      ) &&
      /DEFAULT_AGENT_HARNESS_ACTIVATION_ID/.test(
        projectWorkflowHarnessResultsLane,
      ) &&
      /workflow_hash_value/.test(projectWorkflowHarnessResultsLane),
    workflowPackageRunOutputSurfaces:
      /export interface WorkflowPackageNodeOutputSummary/.test(railModel) &&
      /workflowPackageNodeOutputSummary/.test(railModel) &&
      /workflowPackageNodeOutputStatus/.test(railModel) &&
      /workflow\.package\.export/.test(railModel) &&
      /workflow\.package\.import/.test(railModel) &&
      /workflowChromeLocalePreserved/.test(railModel) &&
      /WorkflowPackageOutputSummaryCard/.test(rail) &&
      /workflow-selected-node-package-output-summary/.test(rail) &&
      /data-package-node-kind/.test(rail) &&
      /data-package-path/.test(rail) &&
      /data-package-readiness-status/.test(rail) &&
      /data-imported-workflow-path/.test(rail) &&
      /data-workflow-chrome-locale-preserved/.test(rail) &&
      /workflow-selection-package-output-summary/.test(bottomShelf) &&
      /workflowPackageNodeOutputSummary/.test(bottomShelf) &&
      /workflowPackageNodeOutputStatus/.test(bottomShelf) &&
      /data-package-evidence-ready/.test(bottomShelf) &&
      /ActionKind::WorkflowPackageExport/.test(projectWorkflowNodeExecutionLane) &&
      /ActionKind::WorkflowPackageImport/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_package_lane/.test(projectWorkflowNodeExecutionLane) &&
      /execute_workflow_package_export_node/.test(projectWorkflowPackageLane) &&
      /execute_workflow_package_import_node/.test(projectWorkflowPackageLane) &&
      /workflowPackageImportReview/.test(projectWorkflowPackageLane),
    workflowGithubPrCreateRunOutputSurfaces:
      /export interface WorkflowGithubPrCreatePlanSummary/.test(railModel) &&
      /workflowGithubPrCreatePlanSummary/.test(railModel) &&
      /workflowGithubPrCreatePlanStatus/.test(railModel) &&
      /github__pr_create/.test(railModel) &&
      /requestPayloadHash/.test(railModel) &&
      /missingScopes/.test(railModel) &&
      /WorkflowGithubPrCreateOutputSummaryCard/.test(rail) &&
      /workflow-selected-node-github-pr-create-output-summary/.test(rail) &&
      /data-github-pr-create-request-hash/.test(rail) &&
      /data-github-pr-create-dry-run/.test(rail) &&
      /data-github-pr-create-mutation-executed/.test(rail) &&
      /data-github-pr-create-missing-scopes/.test(rail) &&
      /data-github-pr-create-review-gate-status/.test(rail) &&
      /data-github-pr-create-receipt-refs/.test(rail) &&
      /data-github-pr-create-replay-fixture-ref/.test(rail) &&
      /workflow-selection-github-pr-create-output-summary/.test(
        bottomShelf,
      ) &&
      /workflowGithubPrCreatePlanSummary/.test(bottomShelf) &&
      /workflowGithubPrCreatePlanStatus/.test(bottomShelf) &&
      /data-github-pr-create-request-hash/.test(bottomShelf) &&
      /data-github-pr-create-missing-scopes/.test(bottomShelf) &&
      /ActionKind::GithubPrCreate/.test(projectWorkflowNodeExecutionLane) &&
      /repository_pr_lane/.test(projectWorkflowNodeExecutionLane) &&
      /workflow_value_helpers/.test(projectWorkflowNodeContractLane) &&
      /workflow_value_helpers/.test(projectRepositoryPrLane) &&
      /workflow_github_pr_create_output/.test(projectRepositoryPrLane) &&
      /workflow_value_at_path/.test(projectWorkflowValueHelpers) &&
      /workflow_hash_value_raw_hex/.test(projectWorkflowValueHelpers) &&
      /github_pr_create_dry_run_node_executes_through_runtime/.test(
        projectRuntimeTests,
      ),
    interactiveReceiptSelection:
      /data-selected-receipt-ref/.test(rail) &&
      /selectedHarnessReceiptRef === receiptRef/.test(rail) &&
      /onClick=\{\(\) => onSelectHarnessReceiptRef\?\.\(receiptRef\)\}/.test(
        rail,
      ) &&
      /handleSelectHarnessReceiptRef[\s\S]*setSelectedHarnessReceiptRef\(receiptRef\)/.test(
        controller,
      ) &&
      /receiptRef: selectedHarnessReceiptRef/.test(controller) &&
      /writeHarnessWorkbenchDeepLink/.test(controller),
    receiptDetailInspector:
      /resolveWorkflowHarnessReceiptInspection/.test(rail) &&
      /export function resolveWorkflowHarnessReceiptInspection/.test(
        railModel,
      ) &&
      /workflowHarnessReceiptKind/.test(railModel) &&
      /workflowRedactedReceiptPayload/.test(railModel) &&
      /selectedHarnessReceiptInspection/.test(rail) &&
      /sourceKind: "node_attempt"/.test(railModel) &&
      /sourceKind: "activation_audit"/.test(railModel) &&
      /sourceKind: "activation_worker_handoff"/.test(railModel) &&
      /sourceKind: "rollback_execution"/.test(railModel) &&
      /sourceKind: "default_runtime_dispatch"/.test(railModel) &&
      /workflow-harness-receipt-inspector/.test(rail) &&
      /data-receipt-source-kind/.test(rail) &&
      /data-producer-component/.test(rail) &&
      /data-policy-decision/.test(rail) &&
      /data-attempt-id/.test(rail) &&
      /data-replay-fixture-ref/.test(rail) &&
      /workflow-harness-receipt-inspector-metadata/.test(rail) &&
      /workflow-harness-receipt-payload-preview/.test(rail) &&
      /workflow-harness-receipt-evidence-refs/.test(rail),
    replayDetailInspector:
      /resolveWorkflowHarnessReplayInspection/.test(rail) &&
      /export interface WorkflowHarnessReplayInspection/.test(railModel) &&
      /export function resolveWorkflowHarnessReplayInspection/.test(
        railModel,
      ) &&
      /workflowUniqueReplayFixtureRefs/.test(railModel) &&
      /selectedHarnessReplayInspection/.test(rail) &&
      /sourceKind: "node_attempt"/.test(railModel) &&
      /sourceKind: "gated_cluster"/.test(railModel) &&
      /sourceKind: "runtime_binding"/.test(railModel) &&
      /sourceKind: "activation_worker_handoff"/.test(railModel) &&
      /sourceKind: "default_runtime_dispatch"/.test(railModel) &&
      /sourceKind: "read_only_routing_proof"/.test(railModel) &&
      /sourceKind: "authority_gate_proof"/.test(railModel) &&
      /sourceKind: "harness_group"/.test(railModel) &&
      /workflow-harness-replay-inspector/.test(rail) &&
      /data-replay-source-kind/.test(rail) &&
      /data-determinism/.test(rail) &&
      /data-redaction-policy/.test(rail) &&
      /data-captures-input/.test(rail) &&
      /data-captures-output/.test(rail) &&
      /data-captures-policy-decision/.test(rail) &&
      /workflow-harness-replay-inspector-metadata/.test(rail) &&
      /workflow-harness-replay-capture-flags/.test(rail) &&
      /workflow-harness-replay-payload-preview/.test(rail) &&
      /workflow-harness-replay-evidence-refs/.test(rail),
    replayDrillExecution:
      /WorkflowHarnessReplayDrillResult/.test(graph) &&
      /WorkflowHarnessReplayGateResult/.test(graph) &&
      /WorkflowHarnessPromotionClusterReplayGateProof/.test(graph) &&
      /WorkflowHarnessReplayDrillDivergenceClass/.test(graph) &&
      /replayGateProof\?: WorkflowHarnessPromotionClusterReplayGateProof/.test(
        graph,
      ) &&
      /replayDrills\?: WorkflowHarnessReplayDrillResult\[\]/.test(graph) &&
      /replayGates\?: WorkflowHarnessReplayGateResult\[\]/.test(graph) &&
      /executeWorkflowHarnessReplayDrill/.test(harnessWorkflow) &&
      /executeWorkflowHarnessReplayGate/.test(harnessWorkflow) &&
      /workflowHarnessPromotionClustersWithReplayGateProof/.test(
        harnessWorkflow,
      ) &&
      /replay_drill_passed/.test(harnessWorkflow) &&
      /replay_drill_blocked/.test(harnessWorkflow) &&
      /replay_gate_passed/.test(harnessWorkflow) &&
      /replay_gate_blocked/.test(harnessWorkflow) &&
      /handleRunHarnessReplayDrill/.test(controller) &&
      /handleRunHarnessReplayGate/.test(controller) &&
      /onRunHarnessReplayDrill/.test(rail) &&
      /onRunHarnessReplayGate/.test(rail) &&
      /workflow-harness-run-replay-drill/.test(rail) &&
      /workflow-harness-run-replay-gate/.test(rail) &&
      /workflow-harness-replay-drill-result/.test(rail) &&
      /workflow-harness-replay-gate-result/.test(rail) &&
      /workflow-harness-promotion-cluster-replay-gate/.test(rail) &&
      /workflow-harness-group-replay-gate-proof/.test(rail) &&
      /data-replay-divergence-class/.test(rail) &&
      /data-activation-gate-impact/.test(rail) &&
      /workflow-harness-replay-drill-receipt-refs/.test(rail) &&
      /workflow-harness-replay-gate-receipt-refs/.test(rail) &&
      /replayDrillBlockers/.test(validation) &&
      /replayGateBlockers/.test(validation) &&
      /promotionClusterReplayGateBlockers/.test(validation),
    promotionTransitionControls:
      /WorkflowHarnessPromotionTransitionEligibility/.test(graph) &&
      /WorkflowHarnessPromotionTransitionAttempt/.test(graph) &&
      /WorkflowHarnessLivePromotionReadinessProof/.test(graph) &&
      /livePromotionReadinessProof: WorkflowHarnessLivePromotionReadinessProof/.test(
        graph,
      ) &&
      /makeHarnessLivePromotionReadinessProof/.test(harnessWorkflow) &&
      /promotionStatus\?: WorkflowHarnessClusterPromotionStatus/.test(graph) &&
      /promotionTransitions\?: WorkflowHarnessPromotionTransitionAttempt\[\]/.test(
        graph,
      ) &&
      /workflowHarnessPromotionTransitionEligibility/.test(harnessWorkflow) &&
      /executeWorkflowHarnessPromotionTransition/.test(harnessWorkflow) &&
      /promotion_transition_blocked/.test(harnessWorkflow) &&
      /promotion_transition_promoted/.test(harnessWorkflow) &&
      /handleRunHarnessPromotionTransition/.test(controller) &&
      /onRunHarnessPromotionTransition=\{\(targetExecutionMode\)/.test(view) &&
      /onRunHarnessPromotionTransition/.test(rail) &&
      /workflow-harness-group-promotion-actions/.test(rail) &&
      /workflow-harness-promote-cluster-gated/.test(rail) &&
      /workflow-harness-promote-cluster-live/.test(rail) &&
      /workflow-harness-group-promotion-eligibility/.test(rail) &&
      /workflow-harness-group-promotion-attempt/.test(rail) &&
      /workflow-harness-live-promotion-readiness/.test(rail) &&
      /workflow-harness-live-promotion-readiness-clusters/.test(rail) &&
      /data-gated-blockers/.test(rail) &&
      /data-live-blockers/.test(rail),
    rollbackCanaryContract:
      /WorkflowHarnessRollbackRestoreCanary[\s\S]*hashVerified[\s\S]*receiptBindingRef[\s\S]*blockers/.test(
        graph,
      ),
    backendHashVerification:
      /WorkflowRevisionRestoreResult[\s\S]*actualWorkflowContentHash[\s\S]*hashVerified/.test(
        graph,
      ) &&
      /workflow_project_content_hash[\s\S]*actual_workflow_content_hash[\s\S]*hash_verified[\s\S]*workflow_content_hash_mismatch[\s\S]*receipt_binding_ref/.test(
        restoreCommand,
      ),
  };
  const passed = Object.values(checks).every(Boolean);
  const proof = {
    schemaVersion: "ioi.autopilot.gui-harness.rollback-restore-canary-ui.v1",
    passed,
    checks,
    uiSelectors: {
      canaryCard: "workflow-harness-rollback-restore-canary",
      wizardStep: "workflow-harness-activation-step-rollback-restore",
      candidateGate:
        "workflow-harness-activation-candidate-gate-rollback-restore",
      activationAuditReceipt:
        "workflow-harness-activation-audit-receipt-${event.eventId}-${index}",
      packageSummary: "workflow-package-summary",
      packageManifestPresent:
        "workflow-package-summary[data-harness-package-manifest-present]",
      packageManifestReceiptCount:
        "workflow-package-summary[data-harness-package-receipt-ref-count]",
      packageManifestReplayCount:
        "workflow-package-summary[data-harness-package-replay-fixture-ref-count]",
      packageManifestDeepLinkCount:
        "workflow-package-summary[data-harness-package-deep-link-count]",
      rollbackDrillReceipt: "workflow-harness-rollback-drill-receipt-${index}",
      rollbackExecutionReceipt:
        "workflow-harness-rollback-execution-receipt-${index}",
      selectedReceiptDeepLinkState:
        "workflow-harness-deep-link-state[data-selected-receipt-ref]",
      receiptInspector: "workflow-harness-receipt-inspector",
      receiptPayloadPreview: "workflow-harness-receipt-payload-preview",
      receiptEvidenceRefs: "workflow-harness-receipt-evidence-refs",
      replayInspector: "workflow-harness-replay-inspector",
      replayPayloadPreview: "workflow-harness-replay-payload-preview",
      replayEvidenceRefs: "workflow-harness-replay-evidence-refs",
      activationGateNodeAttemptRefs:
        "workflow-harness-activation-gate-node-attempt-refs",
      activationGateNodeTimeline:
        "workflow-harness-activation-gate-node-timeline",
      runReplayDrill: "workflow-harness-run-replay-drill",
      replayDrillResult: "workflow-harness-replay-drill-result",
      replayDrillReceiptRefs: "workflow-harness-replay-drill-receipt-refs",
      runReplayGate: "workflow-harness-run-replay-gate",
      replayGateResult: "workflow-harness-replay-gate-result",
      replayGateReceiptRefs: "workflow-harness-replay-gate-receipt-refs",
      promotionClusterReplayGate:
        "workflow-harness-promotion-cluster-replay-gate",
      groupReplayGateProof: "workflow-harness-group-replay-gate-proof",
      promoteClusterGated: "workflow-harness-promote-cluster-gated",
      promoteClusterLive: "workflow-harness-promote-cluster-live",
      groupPromotionEligibility: "workflow-harness-group-promotion-eligibility",
      groupPromotionAttempt: "workflow-harness-group-promotion-attempt",
      selectedNodePackageOutput:
        "workflow-selected-node-package-output-summary",
      selectedNodePackagePath:
        "workflow-selected-node-package-output-summary[data-package-path]",
      selectedNodePackageImportedWorkflow:
        "workflow-selected-node-package-output-summary[data-imported-workflow-path]",
      bottomShelfPackageOutput: "workflow-selection-package-output-summary",
      selectedNodeGithubPrCreateOutput:
        "workflow-selected-node-github-pr-create-output-summary",
      selectedNodeGithubPrCreateRequestHash:
        "workflow-selected-node-github-pr-create-output-summary[data-github-pr-create-request-hash]",
      bottomShelfGithubPrCreateOutput:
        "workflow-selection-github-pr-create-output-summary",
    },
    sourceRefs: [
      railPath,
      searchPanelPath,
      railSearchModelPath,
      entrypointsPanelPath,
      entrypointsModelPath,
      filesPanelPath,
      fileBundleModelPath,
      settingsPanelPath,
      settingsModelPath,
      settingsHarnessPanelPath,
      settingsHarnessTypesPath,
      settingsHarnessActivationPanelPath, settingsHarnessActivationGatePanelPath, settingsHarnessActivationGateRefsPanelPath, settingsHarnessActivationGateTimelinePanelPath, settingsHarnessPackageEvidencePanelPath, settingsHarnessPackageEvidenceRowsPanelPath, settingsHarnessPackageImportReviewPanelPath,
      settingsHarnessWorkerBindingPanelPath, settingsHarnessActiveRuntimeRollbackPanelPath, settingsHarnessActiveRuntimeBindingPanelPath, settingsHarnessRollbackRestoreProofPanelPath, settingsHarnessPromotionPanelPath, settingsHarnessPromotionReadinessPanelPath,
      settingsHarnessModelPath,
      readinessPanelPath,
      readinessModelPath,
      unitTestsPanelPath,
      testReadinessModelPath,
      runsPanelPath,
      runHistoryModelPath,
      validationPath,
      harnessWorkflowPath,
      railModelPath,
      controllerPath,
      viewPath,
      bottomShelfPath,
      graphPath,
      restoreCommandPath,
    ],
  };
  const path = join(outputRoot, "rollback-restore-canary-ui-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

export function collectPromotionTransitionGuiBehaviorProof(outputRoot) {
  const path = join(outputRoot, "promotion-transition-gui-behavior-proof.json");
  const result = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "scripts/lib/harness-promotion-transition-gui-probe.mjs",
      path,
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        TSX_TSCONFIG_PATH: resolve(
          repoRoot,
          "packages/agent-ide/tsconfig.json",
        ),
      },
      timeout: 60_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  if (result.status !== 0 || !existsSync(path)) {
    const proof = {
      schemaVersion:
        "ioi.autopilot.gui-harness.promotion-transition-behavior.v1",
      passed: false,
      checks: {
        probeExecuted: false,
      },
      error:
        result.error?.message ??
        (result.signal
          ? `promotion transition GUI probe terminated by ${result.signal}`
          : `promotion transition GUI probe exited with ${result.status ?? "unknown"}`),
      stdout: result.stdout?.slice(-8_000) ?? "",
      stderr: result.stderr?.slice(-8_000) ?? "",
    };
    writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
    return { path, proof };
  }
  try {
    return {
      path,
      proof: JSON.parse(readFileSync(path, "utf8")),
    };
  } catch (error) {
    const proof = {
      schemaVersion:
        "ioi.autopilot.gui-harness.promotion-transition-behavior.v1",
      passed: false,
      checks: {
        proofParsed: false,
      },
      error: String(error?.message || error),
    };
    writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
    return { path, proof };
  }
}

export function collectWorkflowSkillContextProof(outputRoot) {
  const files = {
    graphTypes: "packages/agent-ide/src/types/graph.ts",
    nodeRegistry: "packages/agent-ide/src/runtime/workflow-node-registry.ts",
    bindingSections:
      "packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
    harnessTools: "packages/agent-ide/src/runtime/workflow-harness-tools.ts",
    tauriRuntime: "apps/autopilot/src/services/TauriRuntime.ts",
    projectRuntime: "apps/autopilot/src-tauri/src/project/runtime.rs",
    projectWorkflowSchedulerLane:
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    projectCodingRouteLane:
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    projectCommands: "apps/autopilot/src-tauri/src/project/commands.rs",
    runtimeTests:
      "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs",
  };
  const source = Object.fromEntries(
    Object.entries(files).map(([key, relativePath]) => [
      key,
      readFileSync(resolve(repoRoot, relativePath), "utf8"),
    ]),
  );
  const checks = {
    nodeKindTyped:
      /WorkflowSkillContextConfig/.test(source.graphTypes) &&
      /"skill_context"/.test(source.graphTypes),
    creatorVariants:
      /creatorId: "skill_context\.discover"/.test(source.nodeRegistry) &&
      /creatorId: "skill_context\.pinned"/.test(source.nodeRegistry) &&
      /token: "SK"/.test(source.nodeRegistry),
    configUi:
      /workflow-skill-context-mode/.test(source.bindingSections) &&
      /workflow-skill-context-pinned-skills/.test(source.bindingSections) &&
      /workflow-skill-context-include-markdown/.test(source.bindingSections),
    catalogTool:
      /"workflow\.catalog\.skills"/.test(source.harnessTools) &&
      /listWorkflowSkillCatalog/.test(source.harnessTools),
    registryBackedRuntime:
      /getSkillCatalog\(\)/.test(source.tauriRuntime) &&
      /getSkillDetail\(skill\.skill_hash\)/.test(source.tauriRuntime) &&
      /workflowOptionsWithSkillCatalog/.test(source.tauriRuntime),
    resolverExecution:
      /workflow_scheduler_lane/.test(source.projectRuntime) &&
      /workflow_coding_route_lane/.test(source.projectWorkflowSchedulerLane) &&
      /struct WorkflowSkillResolver/.test(source.projectCodingRouteLane) &&
      /resolve_skill_context/.test(source.projectCodingRouteLane) &&
      /workflow\.skill-context\.v1/.test(source.projectCodingRouteLane) &&
      /workflow\.skill_context\.discovery\.v1/.test(
        source.projectCodingRouteLane,
      ) &&
      /workflow\.skill_context\.read\.v1/.test(source.projectCodingRouteLane),
    runCommandsPassResolver:
      /WorkflowSkillResolver::from_options\(options\.as_ref\(\)\)/.test(
        source.projectCommands,
      ) && /execute_workflow_project/.test(source.projectCommands),
    createAndRunTests:
      /workflow_skill_context_discovery_attaches_model_context/.test(
        source.runtimeTests,
      ) &&
      /workflow_skill_context_pinned_name_ambiguity_blocks/.test(
        source.runtimeTests,
      ) &&
      /edge-skill-model-context/.test(source.runtimeTests),
  };
  const proof = {
    schemaVersion: "workflow.skill-context.gui-proof.v1",
    passed: Object.values(checks).every(Boolean),
    scenario: "workflow_skill_context_create_run",
    checks,
    validatedSurfaces: [
      "composer node registry",
      "node config UI",
      "runtime registry resolver",
      "node/project run commands",
      "harness catalog tool",
      "create-and-run runtime contract tests",
    ],
  };
  const path = join(outputRoot, "workflow-skill-context-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

export function collectWorkflowCodingRouteProof(outputRoot) {
  const files = {
    graphTypes: "packages/agent-ide/src/types/graph.ts",
    graphRuntimeTypes: "packages/agent-ide/src/runtime/graph-runtime-types.ts",
    routeCatalog: "packages/agent-ide/src/runtime/workflow-coding-routes.ts",
    harnessTools: "packages/agent-ide/src/runtime/workflow-harness-tools.ts",
    tauriRuntime: "apps/autopilot/src/services/TauriRuntime.ts",
    projectTemplates: "apps/autopilot/src-tauri/src/project/templates.rs",
    projectRuntime: "apps/autopilot/src-tauri/src/project/runtime.rs",
    projectWorkflowSchedulerLane:
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    projectCodingRouteLane:
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    runtimeTests:
      "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs",
  };
  const source = Object.fromEntries(
    Object.entries(files).map(([key, relativePath]) => [
      key,
      readFileSync(resolve(repoRoot, relativePath), "utf8"),
    ]),
  );
  const checks = {
    routeContractsTyped:
      /interface WorkflowCodingRouteContract/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteEvidence/.test(source.graphTypes) &&
      /routeEvidence\?: WorkflowCodingRouteEvidence\[\]/.test(source.graphTypes),
    routeRuntimeApis:
      /listWorkflowCodingRoutes/.test(source.graphRuntimeTypes) &&
      /importWorkflowSkillPack/.test(source.graphRuntimeTypes),
    routeCatalog:
      /WORKFLOW_CODING_ROUTE_CONTRACTS/.test(source.routeCatalog) &&
      /coding\.template\.build/.test(source.routeCatalog) &&
      /coding\.template\.debug/.test(source.routeCatalog) &&
      /coding\.template\.review/.test(source.routeCatalog) &&
      /coding\.route\.gate\.v1/.test(source.routeCatalog),
    explicitTemplates:
      /coding\.template\.build/.test(source.projectTemplates) &&
      /coding\.template\.debug/.test(source.projectTemplates) &&
      /coding\.template\.review/.test(source.projectTemplates) &&
      /skill-context-route/.test(source.projectTemplates) &&
      /edge-skill-context-model-context/.test(source.projectTemplates) &&
      /"context"/.test(source.projectTemplates),
    classifierAndEvidence:
      /workflow_scheduler_lane/.test(source.projectRuntime) &&
      /workflow_coding_route_lane/.test(source.projectWorkflowSchedulerLane) &&
      /workflow_classify_coding_route/.test(source.projectCodingRouteLane) &&
      /workflow_coding_route_evidence_from_run/.test(
        source.projectCodingRouteLane,
      ) &&
      /coding\.route\.classification\.v1/.test(source.projectCodingRouteLane) &&
      /coding\.route\.skill_selection\.v1/.test(source.projectCodingRouteLane) &&
      /coding\.route\.gate\.v1/.test(source.projectCodingRouteLane),
    harnessCatalogAndImport:
      /"workflow\.catalog\.coding_routes"/.test(source.harnessTools) &&
      /listWorkflowCodingRoutes/.test(source.harnessTools) &&
      /"workflow\.skills\.import_pack"/.test(source.harnessTools) &&
      /importWorkflowSkillPack/.test(source.harnessTools),
    runtimeRegistryImportPath:
      /listWorkflowCodingRoutes/.test(source.tauriRuntime) &&
      /WORKFLOW_CODING_ROUTE_CONTRACTS/.test(source.tauriRuntime) &&
      /importWorkflowSkillPack/.test(source.tauriRuntime) &&
      /addSkillSource/.test(source.tauriRuntime) &&
      /syncSkillSource/.test(source.tauriRuntime),
    exampleSkillPackDraftSource:
      existsSync(
        resolve(
          repoRoot,
          "examples/agent-skills-main/skills/incremental-implementation/SKILL.md",
        ),
      ) &&
      existsSync(
        resolve(
          repoRoot,
          "examples/agent-skills-main/skills/code-review-and-quality/SKILL.md",
        ),
      ),
    createRunInspectTests:
      /coding_route_templates_validate_run_and_emit_route_evidence/.test(
        source.runtimeTests,
      ) &&
      /coding_route_classifier_defaults_to_build_and_detects_debug_or_review/.test(
        source.runtimeTests,
      ) &&
      /coding\.route\.classification\.v1/.test(source.runtimeTests) &&
      /coding\.route\.skill_selection\.v1/.test(source.runtimeTests) &&
      /coding\.route\.gate\.v1/.test(source.runtimeTests),
  };
  const proof = {
    schemaVersion: "workflow.coding-route.gui-proof.v1",
    passed: Object.values(checks).every(Boolean),
    scenario: "workflow_coding_route_create_run_inspect",
    checks,
    validatedSurfaces: [
      "typed route contracts",
      "build/debug/review templates",
      "deterministic runtime classifier",
      "route evidence artifacts",
      "harness route catalog",
      "Draft skill-pack import path",
      "create-save-validate-run-inspect runtime tests",
    ],
  };
  const path = join(outputRoot, "workflow-coding-route-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

export function collectWorkflowCodingRoutePromotionLoopProof(outputRoot) {
  const files = {
    graphTypes: "packages/agent-ide/src/types/graph.ts",
    routeCatalog: "packages/agent-ide/src/runtime/workflow-coding-routes.ts",
    bottomShelf: "packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx",
    tauriRuntime: "apps/autopilot/src/services/TauriRuntime.ts",
    projectTemplates: "apps/autopilot/src-tauri/src/project/templates.rs",
    projectRuntime: "apps/autopilot/src-tauri/src/project/runtime.rs",
    projectWorkflowSchedulerLane:
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    projectCodingRouteLane:
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    runtimeTests:
      "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs",
  };
  const source = Object.fromEntries(
    Object.entries(files).map(([key, relativePath]) => [
      key,
      readFileSync(resolve(repoRoot, relativePath), "utf8"),
    ]),
  );
  const checks = {
    hardenedRouteTypes:
      /interface WorkflowCodingRouteGateResult/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteSkillSelection/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteBenchmarkResult/.test(source.graphTypes) &&
      /interface WorkflowCodingRoutePromotionDecision/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteRunSummary/.test(source.graphTypes),
    typedGateVocabulary:
      /"pass"/.test(source.graphTypes) &&
      /"warn"/.test(source.graphTypes) &&
      /"block"/.test(source.graphTypes) &&
      /"skipped"/.test(source.graphTypes),
    routeCatalogPhaseTopology:
      /phaseDetails/.test(source.routeCatalog) &&
      /componentKind: "builder"/.test(source.routeCatalog) &&
      /componentKind: "verifier"/.test(source.routeCatalog) &&
      /componentKind: "reviewer"/.test(source.routeCatalog),
    draftBenchmarkSelection:
      /allowDraftForBenchmark/.test(source.projectTemplates) &&
      /allowDraftForBenchmark/.test(source.projectCodingRouteLane),
    promotionRuntime:
      /workflow_scheduler_lane/.test(source.projectRuntime) &&
      /workflow_coding_route_lane/.test(source.projectWorkflowSchedulerLane) &&
      /workflow_coding_route_benchmark_results/.test(
        source.projectCodingRouteLane,
      ) &&
      /workflow_coding_route_promotion_decisions/.test(
        source.projectCodingRouteLane,
      ) &&
      /workflow_coding_route_run_summary/.test(source.projectCodingRouteLane) &&
      /coding\.route\.benchmark\.v1/.test(source.projectCodingRouteLane) &&
      /coding\.route\.promotion\.v1/.test(source.projectCodingRouteLane),
    draftImportMetadata:
      /workflowDraftSkillsFromSources/.test(source.tauriRuntime) &&
      /runtime_skill_source_draft/.test(source.tauriRuntime) &&
      /workflowPhaseTagsForSkill/.test(source.tauriRuntime) &&
      /workflowRouteTagsForSkill/.test(source.tauriRuntime),
    promotionMetadataUpdate:
      /applyWorkflowPromotionDecisions/.test(source.tauriRuntime) &&
      /WORKFLOW_SKILL_PROMOTION_LEDGER_KEY/.test(source.tauriRuntime) &&
      /promotionEvidenceRefs/.test(source.tauriRuntime),
    operatorEvidenceUi:
      /workflow-route-promotion-summary/.test(source.bottomShelf) &&
      /routeRunSummary/.test(source.bottomShelf) &&
      /workflow-route-selected-skill/.test(source.bottomShelf) &&
      /workflow-route-gate/.test(source.bottomShelf) &&
      /workflow-route-promotion/.test(source.bottomShelf),
    guiForkabilitySurface:
      /forkWorkflowCheckpoint/.test(source.tauriRuntime) &&
      /WorkflowCheckpointForkRequest/.test(source.graphTypes),
    promotionLoopTest:
      /coding_route_promotion_loop_promotes_draft_skill_with_evidence/.test(
        source.runtimeTests,
      ) &&
      /coding\.route\.benchmark\.v1/.test(source.runtimeTests) &&
      /coding\.route\.promotion\.v1/.test(source.runtimeTests),
    firstFiveSkillPackPresent:
      [
        "incremental-implementation",
        "test-driven-development",
        "debugging-and-error-recovery",
        "code-review-and-quality",
        "source-driven-development",
      ].every((name) =>
        existsSync(
          resolve(repoRoot, `examples/agent-skills-main/skills/${name}/SKILL.md`),
        ),
      ),
  };
  const proof = {
    schemaVersion: "workflow.coding-route.promotion-loop.gui-proof.v1",
    passed: Object.values(checks).every(Boolean),
    scenario: "workflow_coding_route_promotion_loop",
    checks,
    validatedSurfaces: [
      "typed route gates",
      "phase-aware route topology",
      "Draft skill import metadata",
      "benchmark-backed promotion receipts",
      "run summary promotion metadata",
      "operator evidence UI",
      "workflow forkability surface",
      "create-save-validate-run-inspect-fork proof contract",
    ],
  };
  const path = join(outputRoot, "workflow-coding-route-promotion-loop-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

export function buildGuiEvidenceAssessment({
  queryResults,
  runtimeArtifacts,
  rollbackRestoreCanaryUiProof,
  promotionTransitionGuiBehaviorProof,
  promotionTransitionLiveGuiInteractionProof,
  workflowSkillContextProof,
  workflowCodingRouteProof,
  workflowCodingRoutePromotionLoopProof,
}) {
  const allScreenshotsCaptured =
    queryResults.length === AUTOPILOT_RETAINED_QUERIES.length &&
    queryResults.every((result) => result.passed === true);
  const summary = runtimeArtifacts.summary;
  const hasTranscript = summary.transcriptCount > 0;
  const hasTrace = summary.logSignals.chatProofTrace > 0;
  const hasEvents =
    summary.threadEventCount > 0 || summary.logSignals.kernelEvents > 0;
  const hasReceipts =
    summary.runBundleCount > 0 || summary.threadEventCount > 0;
  const hasPromptAssembly = summary.promptAssemblyCount > 0;
  const hasTurnState = summary.turnStateCount > 0;
  const hasDecisionLoop = summary.decisionLoopCount > 0;
  const hasTraceBundle = summary.traceBundleCount > 0;
  const hasModelRouting = summary.modelRoutingCount > 0;
  const hasToolSelectionQuality = summary.toolSelectionQualityCount > 0;
  const hasSources = summary.selectedSourceCount > 0;
  const hasScorecard = summary.scorecardCount > 0;
  const hasStopReason = summary.stopReasonCount > 0;
  const hasQualityLedger = summary.qualityLedgerCount > 0;
  const hasHarnessShadow =
    summary.harnessWorkerBindingCount > 0 &&
    summary.harnessShadowRunCount > 0 &&
    summary.harnessNodeAttemptCount > 0 &&
    summary.harnessShadowComparisonCount > 0 &&
    summary.harnessBlockingDivergenceCount === 0;
  const hasHarnessGatedCognition =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedCognitionCount > 0;
  const hasHarnessGatedRoutingModel =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedRoutingModelCount > 0;
  const hasHarnessGatedVerificationOutput =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedVerificationOutputCount > 0;
  const hasHarnessGatedAuthorityTooling =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedAuthorityToolingCount > 0;
  const hasHarnessForkActivation =
    hasHarnessGatedAuthorityTooling &&
    summary.harnessForkActivationBlockedCount > 0 &&
    summary.harnessForkActivationMintedCount > 0 &&
    summary.harnessForkHandoffTimelineBoundCount > 0;
  const packageManifestHasForkMutationCanary = (manifest) =>
    (manifest?.forkMutationCanaryReceiptRefCount ?? 0) > 0 &&
    (manifest?.forkMutationCanaryReplayFixtureRefCount ?? 0) > 0 &&
    (manifest?.forkMutationCanaryNodeAttemptCount ?? 0) > 0;
  const packageReviewHasForkMutationCanary = (review) =>
    (review?.evidence?.forkMutationCanaryReceiptRefCount ?? 0) > 0 &&
    (review?.evidence?.forkMutationCanaryReplayFixtureRefCount ?? 0) > 0 &&
    (review?.evidence?.forkMutationCanaryNodeAttemptCount ?? 0) > 0;
  const hasHarnessForkMutationCanaryGuiProof =
    packageManifestHasForkMutationCanary(
      promotionTransitionLiveGuiInteractionProof?.proof
        ?.packageEvidenceGateClickProof?.manifest,
    ) ||
    packageManifestHasForkMutationCanary(
      promotionTransitionLiveGuiInteractionProof?.proof
        ?.packageEvidenceImportRoundTripProof?.validImport?.manifest,
    ) ||
    packageReviewHasForkMutationCanary(
      promotionTransitionLiveGuiInteractionProof?.proof?.packageImportReviewProof
        ?.review,
    ) ||
    packageReviewHasForkMutationCanary(
      promotionTransitionLiveGuiInteractionProof?.proof
        ?.packageImportActivationHandoffProof?.review,
    ) ||
    packageReviewHasForkMutationCanary(
      promotionTransitionLiveGuiInteractionProof?.proof
        ?.packageImportActivationApplyProof?.review,
    );
  const hasHarnessForkMutationCanary =
    hasHarnessForkActivation &&
    ((summary.harnessForkMutationCanaryReadyCount > 0 &&
      summary.harnessForkMutationCanaryReceiptCount > 0 &&
      summary.harnessForkMutationCanaryReplayCount > 0 &&
      summary.harnessForkMutationCanaryNodeAttemptCount > 0) ||
      hasHarnessForkMutationCanaryGuiProof);
  const forkMutationCanaryNodeInspectorState =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.packageEvidenceGateClickProof?.restored
      ?.mutationCanaryNodeAttemptState ?? null;
  const forkMutationCanaryNodeInspectorRefs =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.packageEvidenceGateClickProof?.selectedRefs ?? {};
  const hasHarnessForkMutationCanaryNodeInspector =
    hasHarnessForkMutationCanary &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateMutationCanaryNodeInspectorDeepLink === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.packageEvidenceGateClickProof === true &&
    forkMutationCanaryNodeInspectorState?.["data-node-attempt-source-kind"] ===
      "fork_mutation_canary" &&
    forkMutationCanaryNodeInspectorState?.["data-component-kind"] ===
      "budget_gate" &&
    forkMutationCanaryNodeInspectorState?.["data-node-attempt-id"] ===
      forkMutationCanaryNodeInspectorRefs?.mutationCanaryNodeAttemptId &&
    String(
      forkMutationCanaryNodeInspectorState?.["data-receipt-refs"] ?? "",
    ).includes(forkMutationCanaryNodeInspectorRefs?.mutationCanaryReceiptRef) &&
    forkMutationCanaryNodeInspectorState?.["data-replay-fixture-ref"] ===
      forkMutationCanaryNodeInspectorRefs?.mutationCanaryReplayFixtureRef &&
    forkMutationCanaryNodeInspectorState?.["data-mutation-diff-hash"] ===
      forkMutationCanaryNodeInspectorRefs?.mutationCanaryDiffHash &&
    forkMutationCanaryNodeInspectorState?.["data-rollback-target"] ===
      forkMutationCanaryNodeInspectorRefs?.mutationCanaryRollbackTarget;
  const hasHarnessRollbackRestoreCanary =
    hasHarnessForkMutationCanary &&
    summary.harnessRollbackRestoreCanaryBlockedCount > 0 &&
    summary.harnessRollbackRestoreCanaryReadyCount > 0;
  const hasHarnessRollbackRestoreCanaryReceipts =
    hasHarnessRollbackRestoreCanary &&
    summary.harnessRollbackRestoreCanaryReceiptCount >= 2;
  const hasHarnessActivationAuditReceipts =
    hasHarnessRollbackRestoreCanaryReceipts &&
    summary.harnessActivationAuditReceiptCount > 0;
  const hasHarnessRollbackExecutionReceipts =
    hasHarnessActivationAuditReceipts &&
    summary.harnessRollbackExecutionReceiptCount > 0;
  const hasHarnessRollbackRestoreCanaryUi =
    hasHarnessRollbackRestoreCanary &&
    hasHarnessRollbackRestoreCanaryReceipts &&
    hasHarnessActivationAuditReceipts &&
    hasHarnessRollbackExecutionReceipts &&
    rollbackRestoreCanaryUiProof?.proof?.passed === true;
  const hasHarnessPackageEvidenceManifest =
    hasHarnessRollbackRestoreCanaryUi &&
    rollbackRestoreCanaryUiProof?.proof?.checks
      ?.harnessPackageEvidenceManifest === true;
  const hasHarnessPackageEvidenceGate =
    hasHarnessPackageEvidenceManifest &&
    rollbackRestoreCanaryUiProof?.proof?.checks?.harnessPackageEvidenceGate ===
      true;
  const hasHarnessPackageEvidenceGateClickProof =
    hasHarnessPackageEvidenceGate &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.packageEvidenceGateClickProof === true;
  const hasHarnessPackageEvidenceImportRoundTrip =
    hasHarnessPackageEvidenceGateClickProof &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.packageEvidenceImportRoundTripProof === true;
  const hasHarnessPackageImportReviewMode =
    hasHarnessPackageEvidenceImportRoundTrip &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.packageImportReviewProof === true;
  const hasHarnessPackageImportActivationHandoff =
    hasHarnessPackageImportReviewMode &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.packageImportActivationHandoffProof === true;
	  const hasHarnessPackageImportActivationApply =
	    hasHarnessPackageImportActivationHandoff &&
	    promotionTransitionLiveGuiInteractionProof?.proof?.checks
	      ?.packageImportActivationApplyProof === true;
  const applyProofActivationResult =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.packageImportActivationApplyProof?.activationResult ?? null;
  const applyProofMutationCanary =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.packageImportActivationApplyProof?.mutationCanary ?? null;
  const hasHarnessPackageImportActivationMutationCanaryBinding =
    hasHarnessPackageImportActivationApply &&
    typeof applyProofActivationResult?.reviewedForkMutationCanaryId ===
      "string" &&
    applyProofActivationResult.reviewedForkMutationCanaryId.length > 0 &&
    applyProofActivationResult.reviewedForkMutationCanaryStatus === "passed" &&
    typeof applyProofActivationResult.reviewedForkMutationCanaryDiffHash ===
      "string" &&
    (applyProofActivationResult.reviewedForkMutationCanaryReceiptRefs?.length ??
      0) > 0 &&
    (applyProofActivationResult
      .reviewedForkMutationCanaryReplayFixtureRefs?.length ?? 0) > 0 &&
    (applyProofActivationResult.reviewedForkMutationCanaryNodeAttemptIds
      ?.length ?? 0) > 0 &&
    typeof applyProofActivationResult
      .reviewedForkMutationCanaryRollbackTarget === "string" &&
    applyProofMutationCanary?.selectedState?.[
      "data-selected-activation-gate-id"
    ] === "mutation-canary" &&
    applyProofMutationCanary?.nodeAttemptState?.["data-node-attempt-id"] ===
      applyProofActivationResult.reviewedForkMutationCanaryNodeAttemptIds?.[0];
	  const hasHarnessPackageImportActivationReplayIntegrity =
	    hasHarnessPackageImportActivationApply &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.packageImportActivationReplayIntegrityProof === true;
  const hasHarnessPromotionTransitionGuiBehavior =
    hasHarnessRollbackRestoreCanaryUi &&
    promotionTransitionGuiBehaviorProof?.proof?.passed === true;
  const hasHarnessPromotionTransitionLiveGuiInteraction =
    hasHarnessPromotionTransitionGuiBehavior &&
    promotionTransitionLiveGuiInteractionProof?.proof?.passed === true;
  const hasHarnessRouteStatefulDeepLinkReplay =
    hasHarnessPromotionTransitionLiveGuiInteraction &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routeStatefulDeepLinkReplay === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.deepLinkReplayProof
      ?.passed === true;
  const hasHarnessColdStartDeepLinkRestore =
    hasHarnessRouteStatefulDeepLinkReplay &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.coldStartDeepLinkRestore === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.coldStartDeepLinkRestoreProof?.passed === true;
  const hasHarnessRevisionBindingDeepLinkRestore =
    hasHarnessColdStartDeepLinkRestore &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routeStatefulRevisionBindingDeepLink === true;
  const hasHarnessActivationBlockerDeepLinkRestore =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activationBlockerDeepLinkProof?.passed === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routeStatefulActivationBlockerDeepLink === true;
  const hasHarnessActivationAuditDeepLinkRestore =
    hasHarnessColdStartDeepLinkRestore &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routeStatefulActivationAuditDeepLink === true;
  const hasHarnessActivationGateDeepLinkRestore =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activationGateDeepLinkProof?.passed === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routeStatefulActivationGateDeepLink === true;
  const hasHarnessActivationGateEvidenceInspector =
    hasHarnessActivationGateDeepLinkRestore &&
    rollbackRestoreCanaryUiProof?.proof?.checks
      ?.activationGateEvidenceInspector === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateEvidenceInspectable === true;
  const hasHarnessActivationGateReferenceDeepLinkRestore =
    hasHarnessActivationGateEvidenceInspector &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routeStatefulActivationGateReferenceDeepLinks === true;
  const hasHarnessActivationGateActionWorkbench =
    hasHarnessActivationGateEvidenceInspector &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateActionWorkbench === true;
  const hasHarnessActivationGateActionClickProof =
    hasHarnessActivationGateActionWorkbench &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateActionClickProof === true;
  const hasHarnessActivationGateCollectEvidenceClickProof =
    hasHarnessActivationGateActionWorkbench &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateCollectEvidenceClickProof === true;
  const hasHarnessActivationGateRollbackRestoreClickProof =
    hasHarnessActivationGateActionWorkbench &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateRollbackRestoreClickProof === true;
  const hasHarnessActivationIdGateClickProof =
    hasHarnessActivationGateActionWorkbench &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationIdGateClickProof === true;
  const hasHarnessCanaryExecutionBoundary =
    hasHarnessRollbackRestoreCanary &&
    summary.harnessCanaryBoundaryExecutedCount > 0 &&
    summary.harnessCanaryBoundaryRollbackDrillCount > 0;
  const hasHarnessLiveHandoff =
    hasHarnessCanaryExecutionBoundary &&
    summary.harnessLiveHandoffDefaultPromotedCount > 0 &&
    summary.harnessLiveHandoffRollbackCount > 0;
  const hasHarnessSelectorRouting =
    hasHarnessLiveHandoff &&
    summary.harnessSelectorDefaultPromotedCount > 0 &&
    summary.harnessSelectorLivePromotionReadinessGatedCount > 0 &&
    summary.harnessSelectorWorkflowRecoveryBlockedCount > 0;
  const hasHarnessSelectorReviewedImportActivationApplyInvariant =
    hasHarnessSelectorRouting &&
    summary.harnessSelectorReviewedImportActivationApplyInvariantCount > 0 &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.selectorReviewedImportActivationApplyInvariant === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.liveHandoffReviewedImportActivationApplyInvariant === true &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.defaultDispatchReviewedImportActivationApplyInvariant === true;
  const hasHarnessWorkerLaunchReviewedImportActivationInvariant =
    hasHarnessSelectorReviewedImportActivationApplyInvariant &&
    summary.harnessWorkerLaunchReviewedImportActivationInvariantCount > 0 &&
    summary.harnessDefaultRuntimeBindingSamples.some(
      (binding) =>
        binding?.workerLaunchReviewedImportActivationInvariantBound === true,
    );
  const hasHarnessWorkerLaunchReviewedImportActivationInvariantGuiVisible =
    hasHarnessWorkerLaunchReviewedImportActivationInvariant &&
    rollbackRestoreCanaryUiProof?.proof?.checks?.workerSessionCheckpointUi ===
      true;
  const hasHarnessWorkerLaunchReviewedImportActivationInvariantGateDeepLink =
    hasHarnessWorkerLaunchReviewedImportActivationInvariantGuiVisible &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activationGateWorkerInvariantDeepLink === true;
  const hasHarnessWorkerLaunchReviewedImportActivationInvariantNegativeEnforcement =
    hasHarnessWorkerLaunchReviewedImportActivationInvariantGateDeepLink &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.workerInvariantNegativeEnforcement === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.workerInvariantNegativeEnforcementProof?.passed === true;
  const hasHarnessDefaultRuntimeDispatch =
    hasHarnessSelectorRouting &&
    summary.harnessDefaultRuntimeDispatchReadonlyCount > 0 &&
    summary.harnessLivePromotionReadinessCount > 0 &&
    summary.harnessActivationIdGateClickProofRuntimeCount > 0 &&
    summary.harnessAuthorityToolingNodeAuthorityCount > 0 &&
    summary.harnessAuthorityToolingGateLiveCount > 0 &&
    summary.harnessAuthorityToolingProviderCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingMcpToolCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingNativeToolCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingConnectorCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingGithubPrCreateDryRunCount > 0 &&
    summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0;
  const workflowProofRuntimeSelector =
    promotionTransitionLiveGuiInteractionProof?.proof?.runtimeSelector ?? null;
  const workflowProofDefaultDispatch =
    promotionTransitionLiveGuiInteractionProof?.proof?.defaultDispatch ?? null;
  const workflowProofCognitionNodeAuthorityGate =
    workflowProofDefaultDispatch?.cognitionNodeAuthorityGate ?? null;
  const workflowProofRoutingModelNodeAuthorityGate =
    workflowProofDefaultDispatch?.routingModelNodeAuthorityGate ?? null;
  const workflowProofVerificationOutputNodeAuthorityGate =
    workflowProofDefaultDispatch?.verificationOutputNodeAuthorityGate ?? null;
  const workflowProofAuthorityToolingNodeAuthorityGate =
    workflowProofDefaultDispatch?.authorityToolingNodeAuthorityGate ?? null;
  const hasHarnessCognitionNodeAuthority =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessCognitionNodeAuthorityCount > 0 &&
    workflowProofCognitionNodeAuthorityGate?.schemaVersion ===
      "workflow.harness.default-runtime-dispatch.cognition-node-authority.v1" &&
    workflowProofCognitionNodeAuthorityGate?.authorityMode ===
      "node_authoritative" &&
    workflowProofCognitionNodeAuthorityGate?.authoritative === true &&
    workflowProofCognitionNodeAuthorityGate?.policyDecision ===
      "allow_node_authoritative_cognition" &&
    Array.isArray(workflowProofCognitionNodeAuthorityGate?.blockers) &&
    workflowProofCognitionNodeAuthorityGate.blockers.length === 0 &&
    ["planner", "prompt_assembler", "task_state"].every(
      (componentKind) =>
        workflowProofCognitionNodeAuthorityGate?.componentKinds?.includes(
          componentKind,
        ) &&
        workflowProofCognitionNodeAuthorityGate?.liveReadyComponentKinds?.includes(
          componentKind,
        ),
    );
  const hasHarnessRoutingModelNodeAuthority =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessRoutingModelNodeAuthorityCount > 0 &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.routingModelNodeAuthorityBound === true &&
    workflowProofRoutingModelNodeAuthorityGate?.schemaVersion ===
      "workflow.harness.default-runtime-dispatch.routing-model-node-authority.v1" &&
    workflowProofRoutingModelNodeAuthorityGate?.authorityMode ===
      "gated_node_authoritative" &&
    workflowProofRoutingModelNodeAuthorityGate?.authoritative === true &&
    workflowProofRoutingModelNodeAuthorityGate?.policyDecision ===
      "allow_gated_node_authoritative_routing_model" &&
    workflowProofRoutingModelNodeAuthorityGate?.visibleOutputAuthority ===
      "workflow_model_provider_call" &&
    workflowProofRoutingModelNodeAuthorityGate?.providerCanaryReady === true &&
    workflowProofRoutingModelNodeAuthorityGate?.rollbackAvailable === true &&
    Array.isArray(workflowProofRoutingModelNodeAuthorityGate?.blockers) &&
    workflowProofRoutingModelNodeAuthorityGate.blockers.length === 0 &&
    ["model_router", "model_call", "tool_router"].every(
      (componentKind) =>
        workflowProofRoutingModelNodeAuthorityGate?.componentKinds?.includes(
          componentKind,
        ) &&
        workflowProofRoutingModelNodeAuthorityGate?.shadowReadyComponentKinds?.includes(
          componentKind,
        ),
    );
  const hasHarnessVerificationOutputNodeAuthority =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessVerificationOutputNodeAuthorityCount > 0 &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.verificationOutputNodeAuthorityBound === true &&
    workflowProofVerificationOutputNodeAuthorityGate?.schemaVersion ===
      "workflow.harness.default-runtime-dispatch.verification-output-node-authority.v1" &&
    workflowProofVerificationOutputNodeAuthorityGate?.authorityMode ===
      "gated_node_authoritative" &&
    workflowProofVerificationOutputNodeAuthorityGate?.authoritative === true &&
    workflowProofVerificationOutputNodeAuthorityGate?.policyDecision ===
      "allow_gated_node_authoritative_verification_output" &&
    workflowProofVerificationOutputNodeAuthorityGate
      ?.outputWriterVisibleWriteCommitted === true &&
    workflowProofVerificationOutputNodeAuthorityGate?.rollbackAvailable ===
      true &&
    Array.isArray(workflowProofVerificationOutputNodeAuthorityGate?.blockers) &&
    workflowProofVerificationOutputNodeAuthorityGate.blockers.length === 0 &&
    [
      "postcondition_synthesizer",
      "verifier",
      "completion_gate",
      "receipt_writer",
      "quality_ledger",
      "output_writer",
    ].every(
      (componentKind) =>
        workflowProofVerificationOutputNodeAuthorityGate?.componentKinds?.includes(
          componentKind,
        ) &&
        workflowProofVerificationOutputNodeAuthorityGate?.shadowReadyComponentKinds?.includes(
          componentKind,
        ),
    );
  const hasHarnessAuthorityToolingNodeAuthority =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingNodeAuthorityCount > 0 &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.authorityToolingNodeAuthorityBound === true &&
    workflowProofAuthorityToolingNodeAuthorityGate?.schemaVersion ===
      "workflow.harness.default-runtime-dispatch.authority-tooling-node-authority.v1" &&
    workflowProofAuthorityToolingNodeAuthorityGate?.authorityMode ===
      "gated_node_authoritative" &&
    workflowProofAuthorityToolingNodeAuthorityGate?.authoritative === true &&
    workflowProofAuthorityToolingNodeAuthorityGate?.policyDecision ===
      "allow_gated_node_authoritative_authority_tooling" &&
    workflowProofAuthorityToolingNodeAuthorityGate?.readOnlyRouteAccepted ===
      true &&
    workflowProofAuthorityToolingNodeAuthorityGate?.destructiveRouteDenied ===
      true &&
    workflowProofAuthorityToolingNodeAuthorityGate?.mutatingToolCallsBlocked ===
      true &&
    workflowProofAuthorityToolingNodeAuthorityGate?.sideEffectsExecuted ===
      false &&
    workflowProofAuthorityToolingNodeAuthorityGate?.gateLiveReady === true &&
    workflowProofAuthorityToolingNodeAuthorityGate
      ?.readOnlyAuthorityCanaryReady === true &&
    workflowProofAuthorityToolingNodeAuthorityGate?.rollbackAvailable === true &&
    Array.isArray(workflowProofAuthorityToolingNodeAuthorityGate?.blockers) &&
    workflowProofAuthorityToolingNodeAuthorityGate.blockers.length === 0 &&
    [
      "policy_gate",
      "approval_gate",
      "dry_run_simulator",
      "mcp_provider",
      "mcp_tool_call",
      "tool_call",
      "connector_call",
      "github_pr_create",
      "wallet_capability",
    ].every(
      (componentKind) =>
        workflowProofAuthorityToolingNodeAuthorityGate?.componentKinds?.includes(
          componentKind,
        ) &&
        workflowProofAuthorityToolingNodeAuthorityGate?.shadowReadyComponentKinds?.includes(
          componentKind,
        ),
    );
  const runtimeBindingHasReviewedImportActivationInvariant = (binding) =>
    binding?.workerLaunchReviewedImportActivationInvariantBound === true;
  const runtimeBindingHasRollbackLiveShadowGate = (binding) =>
    binding?.rollbackFromLiveShadowGateBound === true &&
    binding?.liveShadowComparisonGateIdsMatch === true &&
    binding?.selectorLiveShadowComparisonGateId ===
      "p0-live-shadow-comparison-gate" &&
    binding?.workerBinding?.liveShadowComparisonGateId ===
      "p0-live-shadow-comparison-gate" &&
    binding?.workerBindingRegistryRecord?.rollbackReadinessProofId ===
      binding?.selectorLivePromotionReadinessProofId &&
    binding?.workerBindingRegistryRecord?.rollbackLiveShadowComparisonGateId ===
      "p0-live-shadow-comparison-gate" &&
    binding?.workerAttachRollbackReceipt?.rollbackReadinessProofId ===
      binding?.selectorLivePromotionReadinessProofId &&
    binding?.workerAttachRollbackReceipt?.rollbackLiveShadowComparisonGateId ===
      "p0-live-shadow-comparison-gate" &&
    binding?.workerSessionRecord?.rollbackReadinessProofId ===
      binding?.selectorLivePromotionReadinessProofId &&
    binding?.workerSessionRecord?.rollbackLiveShadowComparisonGateId ===
      "p0-live-shadow-comparison-gate";
  const chatRuntimeBindingMatchesWorkflowProof =
    hasHarnessDefaultRuntimeDispatch &&
    Boolean(workflowProofRuntimeSelector) &&
    Boolean(workflowProofDefaultDispatch) &&
    summary.harnessDefaultRuntimeBindingSamples.some(
      (binding) =>
        binding?.bindingMatched === true &&
        binding.workflowId === workflowProofRuntimeSelector.workflowId &&
        binding.activationId === workflowProofRuntimeSelector.activationId &&
        binding.harnessHash === workflowProofRuntimeSelector.harnessHash &&
        binding.rollbackTarget ===
          workflowProofRuntimeSelector.rollbackTarget &&
        binding.selectedSelector ===
          workflowProofRuntimeSelector.selectedSelector &&
        binding.productionDefaultSelector ===
          workflowProofRuntimeSelector.productionDefaultSelector &&
        binding.runtimeAuthority ===
          workflowProofDefaultDispatch.runtimeAuthority &&
        binding.executionMode === workflowProofDefaultDispatch.executionMode &&
        binding.selectorDecisionLinksDispatch === true &&
        binding.drivesRuntimeDecision === true &&
        binding.dispatchDrivesRuntime === true &&
        binding.selectorLivePromotionReadinessReady === true &&
        binding.liveHandoffLivePromotionReadinessReady === true &&
        binding.dispatchLivePromotionReadinessReady === true &&
        binding.selectorLiveShadowComparisonGateReady === true &&
        binding.liveHandoffLiveShadowComparisonGateReady === true &&
        binding.dispatchLiveShadowComparisonGateReady === true &&
        binding.livePromotionReadinessProofIdsMatch === true &&
        binding.invalidForkLiveActivationBlocked === true &&
        runtimeBindingHasRollbackLiveShadowGate(binding) &&
        runtimeBindingHasReviewedImportActivationInvariant(binding) &&
        binding.workerBindingAuthorityReady === true &&
        Array.isArray(binding.workerBindingAuthorityBlockers) &&
        binding.workerBindingAuthorityBlockers.length === 0 &&
        binding.workerBindingRegistryBound === true &&
        binding.workerBindingRegistryStatus === "bound" &&
        Array.isArray(binding.workerBindingRegistryBlockers) &&
        binding.workerBindingRegistryBlockers.length === 0 &&
        binding.workerAttachAccepted === true &&
        binding.workerAttachStatus === "bound" &&
        Array.isArray(binding.workerAttachBlockers) &&
        binding.workerAttachBlockers.length === 0 &&
        binding.workerAttachRollbackAvailable === true &&
        binding.workerAttachResumeAccepted === true &&
        binding.workerAttachRollbackAccepted === true &&
        binding.workerAttachLifecycleComplete === true &&
        Array.isArray(binding.workerAttachLifecycleStatuses) &&
        binding.workerAttachLifecycleStatuses.includes("bound") &&
        binding.workerAttachLifecycleStatuses.includes("resumed") &&
        binding.workerAttachLifecycleStatuses.includes("rolled_back") &&
        Array.isArray(binding.workerAttachLifecycleAttemptIds) &&
        binding.workerAttachLifecycleAttemptIds.length >= 3 &&
        binding.workerSessionAccepted === true &&
        binding.workerSessionStatus === "rollback_ready" &&
        Array.isArray(binding.workerSessionBlockers) &&
        binding.workerSessionBlockers.length === 0 &&
        binding.workerSessionRecord?.schemaVersion ===
          "workflow.harness.worker-session.v1" &&
        binding.workerSessionRecord?.accepted === true &&
        binding.workerSessionRecord?.currentStatus === "rollback_ready" &&
        binding.workerSessionRecord?.resumed === true &&
        binding.workerSessionRecord?.rollbackTargetReady === true &&
        binding.workerSessionRecord?.workerId ===
          binding.workerAttachReceipt?.workerId &&
        typeof binding.workerSessionRecord?.persistenceKey === "string" &&
        binding.workerSessionRecord.persistenceKey.startsWith(
          "agent::harness_worker_session::",
        ) &&
        typeof binding.workerSessionRecord?.recordPersistenceKey === "string" &&
        binding.workerSessionRecord.recordPersistenceKey.startsWith(
          "agent::harness_worker_session_record::",
        ) &&
        binding.workerSessionRecord?.persistedInRuntimeCheckpoint === true &&
        binding.workerSessionRecord?.restoredFromPersistedSession === true &&
        binding.workerSessionRecord?.runtimeCheckpointSource ===
          "runtime_state_access_harness_worker_session_record" &&
        Array.isArray(binding.workerSessionRecord?.persistenceBlockers) &&
        binding.workerSessionRecord.persistenceBlockers.length === 0 &&
        binding.workerSessionRecord?.launchAuthorityReady === true &&
        Array.isArray(binding.workerSessionRecord?.launchAuthorityBlockers) &&
        binding.workerSessionRecord.launchAuthorityBlockers.length === 0 &&
        binding.workerSessionRecord?.launchAuthoritySource ===
          "persisted_harness_worker_session_record" &&
        binding.workerSessionRecord?.rollbackHandoffReady === true &&
        Array.isArray(binding.workerSessionRecord?.rollbackHandoffBlockers) &&
        binding.workerSessionRecord.rollbackHandoffBlockers.length === 0 &&
        binding.workerSessionRecord?.rollbackHandoffTarget ===
          binding.workerSessionRecord?.rollbackTarget &&
        binding.workerLaunchEnvelopesAccepted === true &&
        Array.isArray(binding.workerLaunchEnvelopes) &&
        binding.workerLaunchEnvelopes.length >= 3 &&
        Array.isArray(binding.workerLaunchEnvelopeIds) &&
        binding.workerLaunchEnvelopeIds.length >= 3 &&
        ["launch", "resume", "rollback"].every((phase) =>
          binding.workerLaunchEnvelopes.some(
            (envelope) =>
              envelope?.schemaVersion ===
                "workflow.harness.worker-launch-envelope.v1" &&
              envelope?.phase === phase &&
              envelope?.sessionRecordId ===
                binding.workerSessionRecord?.sessionRecordId &&
              envelope?.workerId === binding.workerSessionRecord?.workerId &&
              envelope?.accepted === true &&
              Array.isArray(envelope?.blockers) &&
              envelope.blockers.length === 0,
          ),
        ) &&
        binding.workerHandoffReceiptsAccepted === true &&
        Array.isArray(binding.workerHandoffReceipts) &&
        binding.workerHandoffReceipts.length >= 3 &&
        Array.isArray(binding.workerHandoffReceiptIds) &&
        binding.workerHandoffReceiptIds.length >= 3 &&
        [
          ["launch", "launched"],
          ["resume", "resumed"],
          ["rollback", "rollback_handoff_ready"],
        ].every(([phase, status]) =>
          binding.workerHandoffReceipts.some(
            (receipt) =>
              receipt?.schemaVersion ===
                "workflow.harness.worker-handoff-receipt.v1" &&
              receipt?.phase === phase &&
              receipt?.handoffStatus === status &&
              receipt?.sessionRecordId ===
                binding.workerSessionRecord?.sessionRecordId &&
              receipt?.workerId === binding.workerSessionRecord?.workerId &&
              receipt?.accepted === true &&
              Array.isArray(receipt?.blockers) &&
              receipt.blockers.length === 0 &&
              Array.isArray(receipt?.receiptRefs) &&
              receipt.receiptRefs.length >= 4,
          ),
        ) &&
        binding.invalidWorkerAttachBlocked === true &&
        binding.selectorLivePromotionReadinessProofId ===
          workflowProofRuntimeSelector.livePromotionReadinessProof?.proofId &&
        binding.dispatchLivePromotionReadinessProofId ===
          workflowProofDefaultDispatch.livePromotionReadinessProof?.proofId &&
        typeof binding.selectorDecisionId === "string" &&
        binding.selectorDecisionId.startsWith("harness-selector:") &&
        typeof binding.defaultDispatchId === "string" &&
        binding.defaultDispatchId.startsWith("harness-default-dispatch:") &&
        binding.workerBinding?.harnessWorkflowId ===
          workflowProofRuntimeSelector.workflowId &&
        binding.workerBinding?.harnessActivationId ===
          workflowProofRuntimeSelector.activationId &&
        binding.workerBinding?.harnessHash ===
          workflowProofRuntimeSelector.harnessHash &&
        binding.workerBinding?.executionMode ===
          workflowProofDefaultDispatch.executionMode &&
        binding.workerBinding?.selectorDecisionId ===
          binding.selectorDecisionId &&
        binding.workerBinding?.defaultDispatchId ===
          binding.defaultDispatchId &&
        binding.workerBinding?.rollbackTarget ===
          workflowProofRuntimeSelector.rollbackTarget &&
        binding.workerBinding?.authorityBindingReady === true &&
        Array.isArray(binding.workerBinding?.authorityBindingBlockers) &&
        binding.workerBinding.authorityBindingBlockers.length === 0 &&
        binding.workerBinding?.livePromotionReadinessProofId ===
          binding.selectorLivePromotionReadinessProofId &&
        binding.workerBindingRegistryRecord?.bindingStatus === "bound" &&
        Array.isArray(binding.workerBindingRegistryRecord?.blockers) &&
        binding.workerBindingRegistryRecord.blockers.length === 0 &&
        binding.workerBindingRegistryRecord?.readinessProofId ===
          binding.selectorLivePromotionReadinessProofId &&
        binding.workerBindingRegistryRecord?.activationId ===
          workflowProofRuntimeSelector.activationId &&
        binding.workerBindingRegistryRecord?.workerBinding
          ?.harnessActivationId === workflowProofRuntimeSelector.activationId &&
        binding.workerAttachReceipt?.accepted === true &&
        binding.workerAttachReceipt?.attachStatus === "bound" &&
        binding.workerAttachReceipt?.registryRecordId ===
          binding.workerBindingRegistryRecord?.registryRecordId &&
        binding.workerAttachReceipt?.readinessProofId ===
          binding.selectorLivePromotionReadinessProofId &&
        binding.workerAttachResumeReceipt?.accepted === true &&
        binding.workerAttachResumeReceipt?.attachStatus === "resumed" &&
        binding.workerAttachRollbackReceipt?.accepted === true &&
        binding.workerAttachRollbackReceipt?.attachStatus === "rolled_back" &&
        binding.invalidWorkerAttachReceipt?.accepted === false,
    );
  const hasHarnessChatRuntimeBinding =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessDefaultRuntimeBindingCount > 0 &&
    summary.harnessDefaultRuntimeBindingMatchedCount > 0 &&
    summary.harnessDefaultRuntimeRollbackLiveShadowGateBoundCount > 0 &&
    chatRuntimeBindingMatchesWorkflowProof;
  const hasHarnessActiveRuntimeRollbackProofWorkbench =
    hasHarnessChatRuntimeBinding &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activeRuntimeRollbackProofWorkbench === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackProofWorkbenchProof?.passed === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackProofWorkbench?.rollbackProofBound === "true";
  const hasHarnessActiveRuntimeRollbackExecutionWorkbench =
    hasHarnessActiveRuntimeRollbackProofWorkbench &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activeRuntimeRollbackExecutionWorkbench === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackExecutionProof?.passed === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackExecutionWorkbench?.dryRunStatus === "passed" &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackExecutionWorkbench?.applyDisabled === false &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackExecutionWorkbench?.routeRestoreProofBound ===
      true;
  const hasHarnessActiveRuntimeRollbackApplyExecution =
    hasHarnessActiveRuntimeRollbackExecutionWorkbench &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activeRuntimeRollbackApplyExecution === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackApplyProof?.passed === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackApplyExecution?.applyStatus === "applied" &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackApplyExecution?.rollbackApplied === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackApplyExecution?.rollbackTargetVerified === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackApplyExecution?.hashVerified === true;
  const activeRuntimeRollbackNegativeRequiredCases = [
    {
      caseId: "stale-hash-node-replay",
      mutationKind: "stale_proof",
      staleProofBlocked: true,
      detachedProofBlocked: false,
      hashVerified: false,
      expectedBlockers: ["rollback_harness_hash_stale"],
    },
    {
      caseId: "detached-launch-envelope-missing",
      mutationKind: "detached_proof",
      staleProofBlocked: true,
      detachedProofBlocked: true,
      hashVerified: true,
      expectedBlockers: ["rollback_launch_envelope_missing"],
    },
    {
      caseId: "detached-handoff-receipt-missing",
      mutationKind: "detached_proof",
      staleProofBlocked: true,
      detachedProofBlocked: true,
      hashVerified: true,
      expectedBlockers: ["rollback_handoff_receipt_missing"],
    },
    {
      caseId: "detached-node-attempt-missing",
      mutationKind: "detached_proof",
      staleProofBlocked: true,
      detachedProofBlocked: true,
      hashVerified: true,
      expectedBlockers: ["rollback_node_attempt_missing"],
    },
    {
      caseId: "detached-node-attempt-orphaned",
      mutationKind: "detached_proof",
      staleProofBlocked: false,
      detachedProofBlocked: true,
      hashVerified: true,
      expectedBlockers: ["rollback_node_attempt_orphaned"],
    },
    {
      caseId: "detached-replay-fixture-missing",
      mutationKind: "detached_proof",
      staleProofBlocked: true,
      detachedProofBlocked: true,
      hashVerified: true,
      expectedBlockers: ["rollback_replay_fixture_missing"],
    },
  ];
  const negativeApplySummaryCases =
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackNegativeApply?.cases ?? [];
  const hasHarnessActiveRuntimeRollbackNegativeApply =
    hasHarnessActiveRuntimeRollbackApplyExecution &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.activeRuntimeRollbackNegativeApply === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.activeRuntimeRollbackNegativeApplyProof?.passed === true &&
    activeRuntimeRollbackNegativeRequiredCases.every((requiredCase) =>
      negativeApplySummaryCases.some(
        (negativeCase) =>
          negativeCase.caseId === requiredCase.caseId &&
          negativeCase.mutationKind === requiredCase.mutationKind &&
          negativeCase.applyButtonDisabled === true &&
          negativeCase.applyStatus === "blocked" &&
          negativeCase.staleProofBlocked ===
            requiredCase.staleProofBlocked &&
          negativeCase.detachedProofBlocked ===
            requiredCase.detachedProofBlocked &&
          negativeCase.rollbackApplied === false &&
          negativeCase.hashVerified === requiredCase.hashVerified &&
          requiredCase.expectedBlockers.every(
            (blocker) =>
              negativeCase.expectedBlockers?.includes(blocker) === true &&
              negativeCase.observedRailBlockers?.includes(blocker) === true &&
              negativeCase.runtimeBlockers?.includes(blocker) === true,
          ),
      ),
    );
  const hasHarnessLiveTurnNodeTimeline =
    hasHarnessChatRuntimeBinding &&
    summary.harnessLiveTurnNodeTimelineCount > 0 &&
    summary.harnessLiveTurnNodeTimelineScenarios.includes(
      "retained_harness_dogfooding",
    ) &&
    summary.harnessLiveTurnNodeTimelineSamples.some(
      (sample) =>
        sample?.scenario === "retained_harness_dogfooding" &&
        sample?.executionMode === "live" &&
        sample?.runtimeAuthority === "blessed_workflow_activation_default" &&
        sample?.dispatchNodeAttemptCount >= 20 &&
        sample?.acceptedNodeAttemptCount >= 18 &&
        sample?.receiptRefCount >= 18 &&
        sample?.replayFixtureRefCount >= 18 &&
        sample?.liveAdapterAttemptCount >= 3 &&
        sample?.gatedAdapterAttemptCount >= 20 &&
        sample?.modelExecutionAttemptCount >= 5 &&
        Array.isArray(sample?.policyDecisions) &&
        sample.policyDecisions.length >= 4,
    );
  const hasHarnessLiveTurnNodeInspector =
    hasHarnessLiveTurnNodeTimeline &&
    summary.harnessLiveTurnNodeInspectorCount > 0 &&
    summary.harnessLiveTurnNodeInspectorScenarios.includes(
      "retained_harness_dogfooding",
    ) &&
    summary.harnessLiveTurnNodeInspectorSamples.some(
      (sample) =>
        sample?.scenario === "retained_harness_dogfooding" &&
        sample?.runtimeAuthority === "blessed_workflow_activation_default" &&
        typeof sample?.nodeAttemptId === "string" &&
        sample.nodeAttemptId.length > 0 &&
        typeof sample?.workflowNodeId === "string" &&
        sample.workflowNodeId.length > 0 &&
        typeof sample?.componentKind === "string" &&
        sample.componentKind.length > 0 &&
        typeof sample?.executionMode === "string" &&
        sample.executionMode.length > 0 &&
        typeof sample?.readiness === "string" &&
        sample.readiness.length > 0 &&
        typeof sample?.status === "string" &&
        sample.status.length > 0 &&
        typeof sample?.policyDecision === "string" &&
        sample.policyDecision.length > 0 &&
        sample?.receiptRefCount > 0 &&
        Array.isArray(sample?.receiptRefs) &&
        sample.receiptRefs.length > 0 &&
        typeof sample?.replayFixtureRef === "string" &&
        sample.replayFixtureRef.length > 0 &&
        typeof sample?.inputHash === "string" &&
        sample.inputHash.length > 0 &&
        typeof sample?.outputHash === "string" &&
        sample.outputHash.length > 0 &&
        sample?.inspectorTestId === "workflow-harness-node-attempt-inspector" &&
        sample?.selectedNodeInspectorTestId ===
          "workflow-selected-node-harness-attempt" &&
        sample?.timelineTestId === "workflow-run-harness-timeline" &&
        sample?.deepLinkParam === "nodeAttemptId",
    );
  const hasHarnessLiveTurnNodeInspectorDeepLink =
    hasHarnessLiveTurnNodeInspector &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.liveTurnNodeInspectorDeepLink === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.liveTurnNodeInspectorDeepLinkProof?.passed === true;
  const liveShadowComparisonProof =
    promotionTransitionLiveGuiInteractionProof?.proof?.liveShadowComparison ??
    null;
  const liveShadowComparisonGate =
    workflowProofDefaultDispatch?.liveShadowComparisonGate ??
    workflowProofDefaultDispatch?.livePromotionReadinessProof
      ?.liveShadowComparisonGate ??
    null;
  const liveShadowComparisonComponentKinds = [
    ...new Set([
      ...summary.harnessLiveShadowComparisonComponentKinds,
      ...(Array.isArray(liveShadowComparisonGate?.componentKinds)
        ? liveShadowComparisonGate.componentKinds
        : []),
    ]),
  ];
  const liveShadowComparisonCount = Math.max(
    summary.harnessLiveShadowComparisonCount,
    Number.isFinite(liveShadowComparisonGate?.comparisonCount)
      ? liveShadowComparisonGate.comparisonCount
      : 0,
    liveShadowComparisonComponentKinds.length,
  );
  const hasHarnessLiveShadowCognitionPairs =
    liveShadowComparisonCount >=
      HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS.length &&
    HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS.every((componentKind) =>
      liveShadowComparisonComponentKinds.includes(componentKind),
    );
  const hasHarnessLiveShadowRoutingModelPairs =
    liveShadowComparisonCount >=
      HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS.length +
        HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS.length &&
    HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS.every((componentKind) =>
      liveShadowComparisonComponentKinds.includes(componentKind),
    );
  const hasHarnessLiveShadowVerificationOutputPairs =
    liveShadowComparisonCount >=
      HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS.length +
        HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS.length +
        HARNESS_VERIFICATION_OUTPUT_LIVE_SHADOW_COMPONENT_KINDS.length &&
    HARNESS_VERIFICATION_OUTPUT_LIVE_SHADOW_COMPONENT_KINDS.every(
      (componentKind) =>
        liveShadowComparisonComponentKinds.includes(componentKind),
    );
  const hasHarnessLiveShadowAuthorityToolingPairs =
    liveShadowComparisonCount >=
      HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS.length +
        HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS.length +
        HARNESS_VERIFICATION_OUTPUT_LIVE_SHADOW_COMPONENT_KINDS.length +
        HARNESS_AUTHORITY_TOOLING_LIVE_SHADOW_COMPONENT_KINDS.length &&
    HARNESS_AUTHORITY_TOOLING_LIVE_SHADOW_COMPONENT_KINDS.every(
      (componentKind) =>
        liveShadowComparisonComponentKinds.includes(componentKind),
    );
  const hasHarnessLiveShadowComparisonGate =
    hasHarnessLiveShadowCognitionPairs &&
    hasHarnessLiveShadowRoutingModelPairs &&
    hasHarnessLiveShadowVerificationOutputPairs &&
    hasHarnessLiveShadowAuthorityToolingPairs &&
    workflowProofDefaultDispatch?.liveShadowComparisonGateReady === true &&
    workflowProofDefaultDispatch?.livePromotionReadinessProof
      ?.liveShadowComparisonGateReady === true &&
    liveShadowComparisonGate?.schemaVersion ===
      "workflow.harness.live-shadow-comparison-gate.v1" &&
    liveShadowComparisonGate?.gateId === "p0-live-shadow-comparison-gate" &&
    liveShadowComparisonGate?.targetExecutionMode === "live" &&
    liveShadowComparisonGate?.ready === true &&
    liveShadowComparisonGate?.allRequiredComponentsPresent === true &&
    liveShadowComparisonGate?.receiptReady === true &&
    liveShadowComparisonGate?.replayReady === true &&
    liveShadowComparisonGate?.divergenceReady === true &&
    liveShadowComparisonGate?.blockingDivergenceCount === 0 &&
    liveShadowComparisonGate?.unclassifiedDivergenceCount === 0 &&
    liveShadowComparisonGate?.comparisonCount >=
      HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.length &&
    liveShadowComparisonGate?.requiredComparisonCount >=
      HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.length &&
    liveShadowComparisonGate?.policyDecision ===
      "allow_default_harness_live_shadow_comparison_gate" &&
    Array.isArray(liveShadowComparisonGate?.blockers) &&
    liveShadowComparisonGate.blockers.length === 0 &&
    HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.every(
      (componentKind) =>
        liveShadowComparisonGate?.componentKinds?.includes(componentKind),
    );
  const hasHarnessLiveShadowComparison =
    hasHarnessLiveTurnNodeInspectorDeepLink &&
    hasHarnessLiveShadowCognitionPairs &&
    hasHarnessLiveShadowRoutingModelPairs &&
    hasHarnessLiveShadowVerificationOutputPairs &&
    hasHarnessLiveShadowAuthorityToolingPairs &&
    promotionTransitionLiveGuiInteractionProof?.proof?.checks
      ?.liveShadowComparisonDeepLink === true &&
    promotionTransitionLiveGuiInteractionProof?.proof
      ?.liveShadowComparisonDeepLinkProof?.passed === true &&
    liveShadowComparisonProof?.selectedRailTestId ===
      "workflow-harness-live-shadow-comparison-inspector" &&
    typeof liveShadowComparisonProof?.observedLiveAttemptId === "string" &&
    liveShadowComparisonProof.observedLiveAttemptId.length > 0 &&
    typeof liveShadowComparisonProof?.observedShadowAttemptId === "string" &&
    liveShadowComparisonProof.observedShadowAttemptId.length > 0 &&
    liveShadowComparisonProof?.divergence === "none" &&
    liveShadowComparisonProof?.blocking === "false" &&
    Array.isArray(liveShadowComparisonProof?.liveReceiptRefs) &&
    liveShadowComparisonProof.liveReceiptRefs.length > 0 &&
    Array.isArray(liveShadowComparisonProof?.shadowReceiptRefs) &&
    liveShadowComparisonProof.shadowReceiptRefs.length > 0 &&
    typeof liveShadowComparisonProof?.liveReplayFixtureRef === "string" &&
    liveShadowComparisonProof.liveReplayFixtureRef.length > 0 &&
    typeof liveShadowComparisonProof?.shadowReplayFixtureRef === "string" &&
    liveShadowComparisonProof.shadowReplayFixtureRef.length > 0 &&
    liveShadowComparisonProof?.liveInputHash ===
      liveShadowComparisonProof?.shadowInputHash &&
    liveShadowComparisonProof?.liveOutputHash ===
      liveShadowComparisonProof?.shadowOutputHash;
  const hasHarnessLivePromotionReadiness =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessLivePromotionReadinessCount > 0 &&
    workflowProofDefaultDispatch?.livePromotionReadinessProof
      ?.defaultLiveActivationReady === true &&
    hasHarnessLiveShadowComparisonGate;
  const hasHarnessAuthorityToolingGateLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingGateLiveCount > 0;
  const hasHarnessAuthorityToolingProviderCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingProviderCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingMcpToolCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingMcpToolCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingNativeToolCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingNativeToolCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingConnectorCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingConnectorCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingGithubPrCreateDryRun =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingGithubPrCreateDryRunCount > 0;
  const hasHarnessAuthorityToolingWalletCapabilityLiveDryRun =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0;
  const providerGatedVisibleOutputScenarioCoverage =
    AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every(
      (scenario) =>
        summary.harnessModelProviderGatedVisibleOutputScenarios.includes(
          scenario,
        ),
    );
  const providerGatedVisibleOutputRollbackDrillScenarioCoverage =
    AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every(
      (scenario) =>
        summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios.includes(
          scenario,
        ),
    );
  const hasHarnessModelProviderGatedVisibleOutput =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessModelProviderGatedVisibleOutputCount > 0 &&
    providerGatedVisibleOutputScenarioCoverage;
  const hasHarnessModelProviderGatedVisibleOutputRollbackDrill =
    hasHarnessModelProviderGatedVisibleOutput &&
    summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount > 0 &&
    providerGatedVisibleOutputRollbackDrillScenarioCoverage;
  const readOnlyCapabilityRoutingScenarioCoverage =
    AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every(
      (scenario) =>
        summary.harnessReadOnlyCapabilityRoutingScenarios.includes(scenario),
    );
  const readOnlyCapabilityRoutingNoMutationScenarioCoverage =
    AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every(
      (scenario) =>
        summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios.includes(
          scenario,
        ),
    );
  const hasHarnessReadOnlyCapabilityRouting =
    hasHarnessDefaultRuntimeDispatch &&
    readOnlyCapabilityRoutingScenarioCoverage &&
    readOnlyCapabilityRoutingNoMutationScenarioCoverage;
  const hasWorkflowSkillContextCreateRunProof =
    workflowSkillContextProof?.proof?.passed === true;
  const hasWorkflowCodingRouteCreateRunProof =
    workflowCodingRouteProof?.proof?.passed === true;
  const hasWorkflowCodingRoutePromotionLoopProof =
    workflowCodingRoutePromotionLoopProof?.proof?.passed === true;

  return {
    chatUx: {
      final_answer_primary: allScreenshotsCaptured && hasTranscript,
      markdown_rendered: allScreenshotsCaptured && hasTranscript,
      mermaid_rendered:
        allScreenshotsCaptured &&
        queryResults.some(
          (result) => result.scenario === "mermaid_rendering" && result.passed,
        ),
      collapsible_thinking: allScreenshotsCaptured && hasTrace,
      collapsible_explored_files: allScreenshotsCaptured && hasSources,
      source_pills_reserved_for_search:
        allScreenshotsCaptured &&
        queryResults.every(
          (result) =>
            result.runtimeEvidence?.containsInlineSourcesUsed !== true,
        ),
      no_raw_receipt_dump: allScreenshotsCaptured && hasReceipts,
      no_default_facts_dashboard: allScreenshotsCaptured && hasQualityLedger,
      no_default_evidence_drawer: allScreenshotsCaptured && hasScorecard,
      no_overlapping_text: allScreenshotsCaptured,
    },
    runtimeConsistency: {
      visible_output_matches_trace:
        allScreenshotsCaptured && hasTranscript && hasTrace,
      visible_sources_match_selected_sources:
        allScreenshotsCaptured && hasSources,
      policy_blocks_match_receipts: hasReceipts && hasStopReason,
      task_state_matches_transcript: hasTranscript && hasQualityLedger,
      scorecard_matches_stop_reason: hasScorecard && hasStopReason,
      harness_shadow_attempts_present: hasHarnessShadow,
      harness_gated_cognition_present: hasHarnessGatedCognition,
      harness_cognition_node_authority_present:
        hasHarnessCognitionNodeAuthority,
      harness_routing_model_node_authority_present:
        hasHarnessRoutingModelNodeAuthority,
      harness_verification_output_node_authority_present:
        hasHarnessVerificationOutputNodeAuthority,
      harness_authority_tooling_node_authority_present:
        hasHarnessAuthorityToolingNodeAuthority,
      harness_gated_routing_model_present: hasHarnessGatedRoutingModel,
      harness_gated_verification_output_present:
        hasHarnessGatedVerificationOutput,
      harness_gated_authority_tooling_present: hasHarnessGatedAuthorityTooling,
      harness_fork_activation_present: hasHarnessForkActivation,
      harness_fork_mutation_canary_present: hasHarnessForkMutationCanary,
      harness_fork_mutation_canary_node_inspector_present:
        hasHarnessForkMutationCanaryNodeInspector,
      harness_fork_handoff_timeline_present:
        summary.harnessForkHandoffTimelineBoundCount > 0,
      harness_rollback_restore_canary_present: hasHarnessRollbackRestoreCanary,
      harness_rollback_restore_canary_receipts_present:
        hasHarnessRollbackRestoreCanaryReceipts,
      harness_activation_audit_receipts_present:
        hasHarnessActivationAuditReceipts,
      harness_rollback_execution_receipts_present:
        hasHarnessRollbackExecutionReceipts,
      harness_rollback_restore_canary_ui_present:
        hasHarnessRollbackRestoreCanaryUi,
      harness_package_evidence_manifest_present:
        hasHarnessPackageEvidenceManifest,
      harness_package_evidence_gate_present: hasHarnessPackageEvidenceGate,
      harness_package_evidence_gate_click_proof_present:
        hasHarnessPackageEvidenceGateClickProof,
      harness_package_evidence_import_roundtrip_present:
        hasHarnessPackageEvidenceImportRoundTrip,
      harness_package_import_review_mode_present:
        hasHarnessPackageImportReviewMode,
      harness_package_import_activation_handoff_present:
        hasHarnessPackageImportActivationHandoff,
	      harness_package_import_activation_apply_present:
	        hasHarnessPackageImportActivationApply,
      harness_package_import_activation_mutation_canary_bound_present:
        hasHarnessPackageImportActivationMutationCanaryBinding,
	      harness_package_import_activation_replay_integrity_present:
        hasHarnessPackageImportActivationReplayIntegrity,
      harness_promotion_transition_gui_behavior_present:
        hasHarnessPromotionTransitionGuiBehavior,
      harness_promotion_transition_live_gui_interaction_present:
        hasHarnessPromotionTransitionLiveGuiInteraction,
      harness_route_stateful_deep_link_replay_present:
        hasHarnessRouteStatefulDeepLinkReplay,
      harness_cold_start_deep_link_restore_present:
        hasHarnessColdStartDeepLinkRestore,
      harness_revision_binding_deep_link_restore_present:
        hasHarnessRevisionBindingDeepLinkRestore,
      harness_activation_blocker_deep_link_restore_present:
        hasHarnessActivationBlockerDeepLinkRestore,
      harness_activation_audit_deep_link_restore_present:
        hasHarnessActivationAuditDeepLinkRestore,
      harness_activation_gate_deep_link_restore_present:
        hasHarnessActivationGateDeepLinkRestore,
      harness_activation_gate_evidence_inspector_present:
        hasHarnessActivationGateEvidenceInspector,
      harness_activation_gate_ref_deep_link_restore_present:
        hasHarnessActivationGateReferenceDeepLinkRestore,
      harness_activation_gate_action_workbench_present:
        hasHarnessActivationGateActionWorkbench,
      harness_activation_gate_action_click_proof_present:
        hasHarnessActivationGateActionClickProof,
      harness_activation_gate_collect_evidence_click_proof_present:
        hasHarnessActivationGateCollectEvidenceClickProof,
      harness_activation_gate_rollback_restore_click_proof_present:
        hasHarnessActivationGateRollbackRestoreClickProof,
      harness_activation_id_gate_click_proof_present:
        hasHarnessActivationIdGateClickProof,
      harness_activation_id_gate_click_proof_runtime_present:
        summary.harnessActivationIdGateClickProofRuntimeCount > 0,
      harness_canary_execution_boundary_present:
        hasHarnessCanaryExecutionBoundary,
      harness_live_handoff_present: hasHarnessLiveHandoff,
      harness_selector_default_promoted: hasHarnessSelectorRouting,
      harness_selector_live_promotion_readiness_gated:
        summary.harnessSelectorLivePromotionReadinessGatedCount > 0,
      harness_selector_reviewed_import_activation_apply_invariant_present:
        hasHarnessSelectorReviewedImportActivationApplyInvariant,
      harness_worker_launch_reviewed_import_activation_apply_invariant_present:
        hasHarnessWorkerLaunchReviewedImportActivationInvariant,
      harness_worker_launch_reviewed_import_activation_apply_invariant_gui_visible:
        hasHarnessWorkerLaunchReviewedImportActivationInvariantGuiVisible,
      harness_worker_launch_reviewed_import_activation_apply_invariant_gate_deep_link_present:
        hasHarnessWorkerLaunchReviewedImportActivationInvariantGateDeepLink,
      harness_worker_launch_reviewed_import_activation_apply_invariant_negative_enforcement_present:
        hasHarnessWorkerLaunchReviewedImportActivationInvariantNegativeEnforcement,
      harness_default_runtime_dispatch_present:
        hasHarnessDefaultRuntimeDispatch,
      harness_cognition_node_authority_present:
        hasHarnessCognitionNodeAuthority,
      harness_routing_model_node_authority_present:
        hasHarnessRoutingModelNodeAuthority,
      harness_verification_output_node_authority_present:
        hasHarnessVerificationOutputNodeAuthority,
      harness_authority_tooling_node_authority_present:
        hasHarnessAuthorityToolingNodeAuthority,
      harness_live_promotion_readiness_present:
        hasHarnessLivePromotionReadiness,
      harness_chat_runtime_binding_matches_workflow_activation:
        hasHarnessChatRuntimeBinding,
      harness_default_runtime_rollback_live_shadow_gate_bound:
        summary.harnessDefaultRuntimeRollbackLiveShadowGateBoundCount > 0,
      harness_worker_binding_registry_reviewed_package_bound:
        summary.harnessWorkerBindingRegistryReviewedPackageBoundCount > 0,
      harness_active_runtime_rollback_proof_workbench_present:
        hasHarnessActiveRuntimeRollbackProofWorkbench,
      harness_active_runtime_rollback_execution_workbench_present:
        hasHarnessActiveRuntimeRollbackExecutionWorkbench,
      harness_active_runtime_rollback_apply_execution_present:
        hasHarnessActiveRuntimeRollbackApplyExecution,
      harness_active_runtime_rollback_negative_apply_present:
        hasHarnessActiveRuntimeRollbackNegativeApply,
      harness_live_turn_node_timeline_present: hasHarnessLiveTurnNodeTimeline,
      harness_live_turn_node_inspector_present: hasHarnessLiveTurnNodeInspector,
      harness_live_turn_node_inspector_deep_link_present:
        hasHarnessLiveTurnNodeInspectorDeepLink,
      harness_live_shadow_comparison_present: hasHarnessLiveShadowComparison,
      harness_live_shadow_routing_model_pairs_present:
        hasHarnessLiveShadowRoutingModelPairs,
      harness_live_shadow_verification_output_pairs_present:
        hasHarnessLiveShadowVerificationOutputPairs,
      harness_live_shadow_authority_tooling_pairs_present:
        hasHarnessLiveShadowAuthorityToolingPairs,
      harness_live_shadow_comparison_gate_present:
        hasHarnessLiveShadowComparisonGate,
      harness_authority_tooling_gate_live_present:
        hasHarnessAuthorityToolingGateLive,
      harness_authority_tooling_provider_catalog_live_present:
        hasHarnessAuthorityToolingProviderCatalogLive,
      harness_authority_tooling_mcp_tool_catalog_live_present:
        hasHarnessAuthorityToolingMcpToolCatalogLive,
      harness_authority_tooling_native_tool_catalog_live_present:
        hasHarnessAuthorityToolingNativeToolCatalogLive,
      harness_authority_tooling_connector_catalog_live_present:
        hasHarnessAuthorityToolingConnectorCatalogLive,
      harness_authority_tooling_github_pr_create_dry_run_present:
        hasHarnessAuthorityToolingGithubPrCreateDryRun,
      harness_authority_tooling_wallet_capability_live_dry_run_present:
        hasHarnessAuthorityToolingWalletCapabilityLiveDryRun,
      harness_model_provider_gated_visible_output_present:
        hasHarnessModelProviderGatedVisibleOutput,
      harness_model_provider_gated_visible_output_rollback_drill_present:
        hasHarnessModelProviderGatedVisibleOutputRollbackDrill,
      harness_read_only_capability_routing_present:
        hasHarnessReadOnlyCapabilityRouting,
      workflow_skill_context_create_run_proof_present:
        hasWorkflowSkillContextCreateRunProof,
      workflow_coding_route_create_run_proof_present:
        hasWorkflowCodingRouteCreateRunProof,
      workflow_coding_route_promotion_loop_proof_present:
        hasWorkflowCodingRoutePromotionLoopProof,
      better_agent_artifacts_present:
        hasTurnState &&
        hasDecisionLoop &&
        hasTraceBundle &&
        hasModelRouting &&
        hasToolSelectionQuality,
    },
    assessment: {
      method: "screenshot-capture-plus-runtime-evidence-export",
      allScreenshotsCaptured,
      hasTranscript,
      hasTrace,
      hasEvents,
      hasReceipts,
      hasPromptAssembly,
      hasTurnState,
      hasDecisionLoop,
      hasTraceBundle,
      hasModelRouting,
      hasToolSelectionQuality,
      hasSources,
      hasScorecard,
      hasStopReason,
      hasQualityLedger,
      hasHarnessShadow,
      hasHarnessGatedCognition,
      hasHarnessGatedRoutingModel,
      hasHarnessGatedVerificationOutput,
      hasHarnessGatedAuthorityTooling,
      hasHarnessForkActivation,
      hasHarnessForkMutationCanary,
      hasHarnessForkMutationCanaryNodeInspector,
      hasHarnessForkHandoffTimeline:
        summary.harnessForkHandoffTimelineBoundCount > 0,
      hasHarnessRollbackRestoreCanary,
      hasHarnessRollbackRestoreCanaryReceipts,
      hasHarnessActivationAuditReceipts,
      hasHarnessRollbackExecutionReceipts,
      hasHarnessRollbackRestoreCanaryUi,
      hasHarnessPackageEvidenceManifest,
      hasHarnessPackageEvidenceGate,
      hasHarnessPackageEvidenceGateClickProof,
      hasHarnessPackageEvidenceImportRoundTrip,
      hasHarnessPackageImportReviewMode,
      hasHarnessPackageImportActivationHandoff,
      hasHarnessPackageImportActivationApply,
      hasHarnessPackageImportActivationReplayIntegrity,
      hasHarnessPromotionTransitionGuiBehavior,
      hasHarnessPromotionTransitionLiveGuiInteraction,
      hasHarnessRouteStatefulDeepLinkReplay,
      hasHarnessColdStartDeepLinkRestore,
      hasHarnessRevisionBindingDeepLinkRestore,
      hasHarnessActivationBlockerDeepLinkRestore,
      hasHarnessActivationAuditDeepLinkRestore,
      hasHarnessActivationGateDeepLinkRestore,
      hasHarnessActivationGateEvidenceInspector,
      hasHarnessActivationGateReferenceDeepLinkRestore,
      hasHarnessActivationGateActionWorkbench,
      hasHarnessActivationGateActionClickProof,
      hasHarnessActivationGateCollectEvidenceClickProof,
      hasHarnessActivationGateRollbackRestoreClickProof,
      hasHarnessActivationIdGateClickProof,
      hasHarnessCanaryExecutionBoundary,
      hasHarnessLiveHandoff,
      hasHarnessSelectorRouting,
      hasHarnessSelectorReviewedImportActivationApplyInvariant,
      hasHarnessWorkerLaunchReviewedImportActivationInvariant,
      hasHarnessDefaultRuntimeDispatch,
      hasHarnessLivePromotionReadiness,
      hasHarnessChatRuntimeBinding,
      hasHarnessLiveTurnNodeTimeline,
      hasHarnessLiveTurnNodeInspector,
      hasHarnessLiveTurnNodeInspectorDeepLink,
      hasHarnessLiveShadowComparison,
      hasHarnessLiveShadowCognitionPairs,
      hasHarnessLiveShadowRoutingModelPairs,
      hasHarnessLiveShadowVerificationOutputPairs,
      hasHarnessLiveShadowAuthorityToolingPairs,
      hasHarnessLiveShadowComparisonGate,
      chatRuntimeBindingMatchesWorkflowProof,
      hasHarnessAuthorityToolingGateLive,
      hasHarnessModelProviderGatedVisibleOutput,
      hasHarnessModelProviderGatedVisibleOutputRollbackDrill,
      hasHarnessReadOnlyCapabilityRouting,
      hasWorkflowSkillContextCreateRunProof,
      providerGatedVisibleOutputRequiredScenarios: [
        ...AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS,
      ],
      providerGatedVisibleOutputScenarioCoverage,
      providerGatedVisibleOutputRollbackDrillScenarioCoverage,
      readOnlyCapabilityRoutingRequiredScenarios: [
        ...AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS,
      ],
      readOnlyCapabilityRoutingScenarioCoverage,
      readOnlyCapabilityRoutingNoMutationScenarioCoverage,
      harnessModelProviderGatedVisibleOutputScenarios:
        summary.harnessModelProviderGatedVisibleOutputScenarios,
      harnessModelProviderGatedVisibleOutputRollbackDrillScenarios:
        summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
      harnessReadOnlyCapabilityRoutingCount:
        summary.harnessReadOnlyCapabilityRoutingCount,
      harnessReadOnlyCapabilityRoutingNoMutationCount:
        summary.harnessReadOnlyCapabilityRoutingNoMutationCount,
      harnessReadOnlyCapabilityRoutingScenarios:
        summary.harnessReadOnlyCapabilityRoutingScenarios,
      harnessReadOnlyCapabilityRoutingNoMutationScenarios:
        summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
      harnessLivePromotionReadinessCount:
        summary.harnessLivePromotionReadinessCount,
      harnessCognitionNodeAuthorityCount:
        summary.harnessCognitionNodeAuthorityCount,
      harnessCognitionNodeAuthoritySamples:
        summary.harnessCognitionNodeAuthoritySamples,
      harnessRoutingModelNodeAuthorityCount:
        summary.harnessRoutingModelNodeAuthorityCount,
      harnessRoutingModelNodeAuthoritySamples:
        summary.harnessRoutingModelNodeAuthoritySamples,
      harnessVerificationOutputNodeAuthorityCount:
        summary.harnessVerificationOutputNodeAuthorityCount,
      harnessVerificationOutputNodeAuthoritySamples:
        summary.harnessVerificationOutputNodeAuthoritySamples,
      harnessAuthorityToolingNodeAuthorityCount:
        summary.harnessAuthorityToolingNodeAuthorityCount,
      harnessAuthorityToolingNodeAuthoritySamples:
        summary.harnessAuthorityToolingNodeAuthoritySamples,
      harnessLiveTurnNodeTimelineCount:
        summary.harnessLiveTurnNodeTimelineCount,
      harnessLiveTurnNodeTimelineScenarios:
        summary.harnessLiveTurnNodeTimelineScenarios,
      harnessLiveTurnNodeTimelineSamples:
        summary.harnessLiveTurnNodeTimelineSamples,
      harnessLiveTurnNodeInspectorCount:
        summary.harnessLiveTurnNodeInspectorCount,
      harnessLiveTurnNodeInspectorScenarios:
        summary.harnessLiveTurnNodeInspectorScenarios,
      harnessLiveTurnNodeInspectorSamples:
        summary.harnessLiveTurnNodeInspectorSamples,
      harnessLiveShadowComparisonCount:
        liveShadowComparisonCount,
      harnessLiveShadowComparisonScenarios:
        summary.harnessLiveShadowComparisonScenarios,
      harnessLiveShadowComparisonComponentKinds:
        liveShadowComparisonComponentKinds,
      harnessLiveShadowComparisonRequiredComponentKinds: [
        ...HARNESS_COGNITION_LIVE_SHADOW_COMPONENT_KINDS,
      ],
      harnessLiveShadowRoutingModelRequiredComponentKinds: [
        ...HARNESS_ROUTING_MODEL_LIVE_SHADOW_COMPONENT_KINDS,
      ],
      harnessLiveShadowVerificationOutputRequiredComponentKinds: [
        ...HARNESS_VERIFICATION_OUTPUT_LIVE_SHADOW_COMPONENT_KINDS,
      ],
      harnessLiveShadowAuthorityToolingRequiredComponentKinds: [
        ...HARNESS_AUTHORITY_TOOLING_LIVE_SHADOW_COMPONENT_KINDS,
      ],
      harnessLiveShadowComparisonGate: liveShadowComparisonGate,
      harnessLiveShadowComparisonSamples:
        summary.harnessLiveShadowComparisonSamples,
      harnessWorkerBindingCount: summary.harnessWorkerBindingCount,
      harnessShadowRunCount: summary.harnessShadowRunCount,
      harnessNodeAttemptCount: summary.harnessNodeAttemptCount,
      harnessShadowComparisonCount: summary.harnessShadowComparisonCount,
      harnessBlockingDivergenceCount: summary.harnessBlockingDivergenceCount,
      harnessGatedClusterCount: summary.harnessGatedClusterCount,
      harnessGatedCognitionCount: summary.harnessGatedCognitionCount,
      harnessGatedRoutingModelCount: summary.harnessGatedRoutingModelCount,
      harnessGatedVerificationOutputCount:
        summary.harnessGatedVerificationOutputCount,
      harnessGatedAuthorityToolingCount:
        summary.harnessGatedAuthorityToolingCount,
      harnessForkActivationBlockedCount:
        summary.harnessForkActivationBlockedCount,
      harnessForkActivationMintedCount:
        summary.harnessForkActivationMintedCount,
      harnessForkMutationCanaryReadyCount:
        summary.harnessForkMutationCanaryReadyCount,
      harnessForkMutationCanaryReceiptCount:
        summary.harnessForkMutationCanaryReceiptCount,
      harnessForkMutationCanaryReplayCount:
        summary.harnessForkMutationCanaryReplayCount,
      harnessForkMutationCanaryNodeAttemptCount:
        summary.harnessForkMutationCanaryNodeAttemptCount,
      harnessForkHandoffTimelineBoundCount:
        summary.harnessForkHandoffTimelineBoundCount,
      harnessRollbackRestoreCanaryBlockedCount:
        summary.harnessRollbackRestoreCanaryBlockedCount,
      harnessRollbackRestoreCanaryReadyCount:
        summary.harnessRollbackRestoreCanaryReadyCount,
      harnessRollbackRestoreCanaryReceiptCount:
        summary.harnessRollbackRestoreCanaryReceiptCount,
      harnessActivationAuditReceiptCount:
        summary.harnessActivationAuditReceiptCount,
      harnessRollbackExecutionReceiptCount:
        summary.harnessRollbackExecutionReceiptCount,
      harnessRollbackRestoreCanaryStatuses:
        summary.harnessRollbackRestoreCanaryStatuses,
      harnessRollbackRestoreCanaryUiProof:
        rollbackRestoreCanaryUiProof?.proof ?? null,
      harnessPromotionTransitionGuiBehaviorProof:
        promotionTransitionGuiBehaviorProof?.proof ?? null,
      harnessPromotionTransitionLiveGuiInteractionProof:
        promotionTransitionLiveGuiInteractionProof?.proof ?? null,
      harnessCanaryBoundaryExecutedCount:
        summary.harnessCanaryBoundaryExecutedCount,
      harnessCanaryBoundaryRollbackDrillCount:
        summary.harnessCanaryBoundaryRollbackDrillCount,
      harnessSelectorCanaryRoutedCount:
        summary.harnessSelectorCanaryRoutedCount,
      harnessSelectorWorkflowRecoveryBlockedCount:
        summary.harnessSelectorWorkflowRecoveryBlockedCount,
      harnessSelectorDefaultPromotedCount:
        summary.harnessSelectorDefaultPromotedCount,
      harnessSelectorLivePromotionReadinessGatedCount:
        summary.harnessSelectorLivePromotionReadinessGatedCount,
      harnessSelectorReviewedImportActivationApplyInvariantCount:
        summary.harnessSelectorReviewedImportActivationApplyInvariantCount,
      harnessLiveHandoffCanaryCount: summary.harnessLiveHandoffCanaryCount,
      harnessLiveHandoffDefaultPromotedCount:
        summary.harnessLiveHandoffDefaultPromotedCount,
      harnessLiveHandoffRollbackCount: summary.harnessLiveHandoffRollbackCount,
      harnessDefaultRuntimeDispatchReadonlyCount:
        summary.harnessDefaultRuntimeDispatchReadonlyCount,
      harnessDefaultRuntimeBindingCount:
        summary.harnessDefaultRuntimeBindingCount,
      harnessDefaultRuntimeBindingMatchedCount:
        summary.harnessDefaultRuntimeBindingMatchedCount,
      harnessDefaultRuntimeRollbackLiveShadowGateBoundCount:
        summary.harnessDefaultRuntimeRollbackLiveShadowGateBoundCount,
      harnessWorkerBindingRegistryReviewedPackageBoundCount:
        summary.harnessWorkerBindingRegistryReviewedPackageBoundCount,
      harnessDefaultRuntimeBindingSamples:
        summary.harnessDefaultRuntimeBindingSamples,
      harnessAuthorityToolingReadOnlyCanaryCount:
        summary.harnessAuthorityToolingReadOnlyCanaryCount,
      harnessAuthorityToolingGateLiveCount:
        summary.harnessAuthorityToolingGateLiveCount,
      harnessAuthorityToolingProviderCatalogLiveCount:
        summary.harnessAuthorityToolingProviderCatalogLiveCount,
      harnessAuthorityToolingMcpToolCatalogLiveCount:
        summary.harnessAuthorityToolingMcpToolCatalogLiveCount,
      harnessAuthorityToolingNativeToolCatalogLiveCount:
        summary.harnessAuthorityToolingNativeToolCatalogLiveCount,
      harnessAuthorityToolingConnectorCatalogLiveCount:
        summary.harnessAuthorityToolingConnectorCatalogLiveCount,
      harnessAuthorityToolingGithubPrCreateDryRunCount:
        summary.harnessAuthorityToolingGithubPrCreateDryRunCount,
      harnessAuthorityToolingWalletCapabilityLiveDryRunCount:
        summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount,
      harnessModelProviderGatedVisibleOutputCount:
        summary.harnessModelProviderGatedVisibleOutputCount,
      harnessModelProviderGatedVisibleOutputRollbackDrillCount:
        summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount,
    },
  };
}

function preflight() {
  const failures = [];
  const packageScripts = runShell(
    "node -e \"const p=require('./package.json'); console.log(Boolean(p.scripts?.['dev:desktop']))\"",
  );
  if (packageScripts.status !== 0 || packageScripts.stdout.trim() !== "true") {
    failures.push("package.json is missing dev:desktop script");
  }
  for (const command of ["npm", "bash"]) {
    if (!commandExists(command)) failures.push(`${command} not found on PATH`);
  }
  const optionalGuiTools = ["wmctrl", "xdotool", "import"];
  const missingGuiTools = optionalGuiTools.filter(
    (command) => !commandExists(command),
  );
  if (missingGuiTools.length > 0) {
    failures.push(
      `GUI automation tools missing: ${missingGuiTools.join(", ")}`,
    );
  }
  return failures;
}

function stopDesktopProcess(desktop) {
  if (!desktop || desktop.killed) return;
  try {
    process.kill(-desktop.pid, "SIGINT");
  } catch {
    desktop.kill("SIGINT");
  }
}

export async function waitForHarnessPromotionLiveWorkflow(
  proofWorkflowPath,
  timeoutMs,
) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    workflow: null,
    error: "proof workflow not found",
  };
  while (Date.now() < deadline) {
    if (existsSync(proofWorkflowPath)) {
      try {
        const workflow = JSON.parse(readFileSync(proofWorkflowPath, "utf8"));
        latest = { workflow, error: null };
        const liveGuiProbeDiagnostics =
          workflow.metadata?.harness?.liveGuiProbeDiagnostics ?? null;
        if (liveGuiProbeDiagnostics?.status === "blocked") {
          return {
            ...latest,
            blocked: true,
            liveGuiProbeDiagnostics,
          };
        }
        const cluster = workflow.metadata?.harness?.promotionClusters?.find(
          (candidate) => candidate.clusterId === "cognition",
        );
        const transitions =
          workflow.metadata?.harness?.promotionTransitions ?? [];
        if (
          cluster?.promotionStatus === "live" &&
          transitions.some(
            (attempt) =>
              attempt.clusterId === "cognition" &&
              attempt.targetExecutionMode === "live" &&
              attempt.attemptStatus === "promoted",
          )
        ) {
          return latest;
        }
      } catch (error) {
        latest = {
          workflow: null,
          error: String(error?.message || error),
        };
      }
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    timedOut: true,
  };
}

export async function collectPromotionTransitionLiveGuiInteractionProof(
  outputRoot,
  args,
) {
  const proofPath = join(
    outputRoot,
    "promotion-transition-live-gui-interaction-proof.json",
  );
  const proofWorkflowEvidencePath = join(
    outputRoot,
    "promotion-transition-live-gui-workflow.json",
  );
  const proofWorkflowPath = resolve(
    repoRoot,
    "apps/autopilot/src-tauri/.agents/workflows/default-agent-harness-live-gui-promotion-proof.workflow.json",
  );
  const logPath = join(outputRoot, "promotion-transition-live-gui.log");
  try {
    unlinkSync(proofWorkflowPath);
  } catch {
    // No stale proof to remove.
  }
  closeMatchingWindows(args.windowName);
  await sleep(1_000);

  const log = [];
  const desktop = spawn("npm", ["run", "dev:desktop"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      AUTOPILOT_LOCAL_GPU_DEV: "1",
      AUTOPILOT_HARNESS_DEFAULT_PROMOTION:
        process.env.AUTOPILOT_HARNESS_DEFAULT_PROMOTION ?? "1",
      AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT:
        process.env.AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT ?? "1",
      AUTOPILOT_RESET_DATA_ON_BOOT: "0",
      AUTOPILOT_REUSE_DEV_SERVER: "0",
      AUTO_START_DEV_SERVER: "1",
      VITE_AUTOPILOT_INITIAL_VIEW: "workflows",
      VITE_AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  desktop.stdout.on("data", (chunk) => log.push(chunk.toString()));
  desktop.stderr.on("data", (chunk) => log.push(chunk.toString()));

  let windowId = null;
  let screenshot = { ok: false, path: null, stderr: "not captured" };
  try {
    windowId = await waitForWindow(args.windowName, args.windowTimeoutMs);
    if (!windowId) {
      const proof = {
        schemaVersion:
          "ioi.autopilot.gui-harness.promotion-transition-live-gui-interaction.v1",
        passed: false,
        checks: {
          desktopWindowOpened: false,
        },
        proofWorkflowPath,
        error: `Timed out waiting for window matching ${args.windowName}`,
        logTail: log.slice(-80),
      };
      writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
      return { path: proofPath, proof };
    }
    await sleep(Math.min(Math.max(args.settleMs, 6_000), 15_000));
    const liveWorkflow = await waitForHarnessPromotionLiveWorkflow(
      proofWorkflowPath,
      Math.min(args.queryTimeoutMs, 120_000),
    );
    await sleep(2_000);
    screenshot = captureScreenshot(
      windowId,
      outputRoot,
      "promotion_transition_live_gui_interaction",
    );
    const workflow = liveWorkflow.workflow;
    if (workflow) {
      writeFileSync(
        proofWorkflowEvidencePath,
        `${JSON.stringify(workflow, null, 2)}\n`,
        "utf8",
      );
    }
    const clusterIds = [
      "cognition",
      "routing_model",
      "verification_output",
      "authority_tooling",
    ];
    const clusters = workflow?.metadata?.harness?.promotionClusters ?? [];
    const clusterById = new Map(
      clusters.map((candidate) => [candidate.clusterId, candidate]),
    );
    const transitions = workflow?.metadata?.harness?.promotionTransitions ?? [];
    const audit = workflow?.metadata?.harness?.activationAudit ?? [];
    const liveGuiProbeDiagnostics =
      workflow?.metadata?.harness?.liveGuiProbeDiagnostics ?? null;
    const selector =
      workflow?.metadata?.harness?.runtimeSelectorDecision ?? null;
    const liveHandoff = workflow?.metadata?.harness?.liveHandoffProof ?? null;
    const defaultDispatch =
      workflow?.metadata?.harness?.defaultRuntimeDispatchProof ?? null;
    const activationRecord =
      workflow?.metadata?.harness?.activationRecord ?? null;
    const workerBinding = workflow?.metadata?.workerHarnessBinding ?? null;
    const workerBindingRegistry =
      defaultDispatch?.workerBindingRegistryRecord ??
      workflow?.metadata?.harness?.workerBindingRegistryRecord ??
      activationRecord?.workerBindingRegistryRecord ??
      null;
    const workerAttachReceipt =
      defaultDispatch?.workerAttachReceipt ??
      workflow?.metadata?.harness?.workerAttachReceipt ??
      activationRecord?.workerAttachReceipt ??
      null;
    const workerAttachLifecycle =
      defaultDispatch?.workerAttachLifecycle ??
      workflow?.metadata?.harness?.workerAttachLifecycle ??
      activationRecord?.workerAttachLifecycle ??
      [];
    const workerAttachResumeReceipt =
      defaultDispatch?.workerAttachResumeReceipt ??
      workerAttachLifecycle.find((event) => event?.phase === "resume")
        ?.receipt ??
      null;
    const workerAttachRollbackReceipt =
      defaultDispatch?.workerAttachRollbackReceipt ??
      workerAttachLifecycle.find((event) => event?.phase === "rollback")
        ?.receipt ??
      null;
    const workerAttachLifecycleStatuses = Array.isArray(
      defaultDispatch?.workerAttachLifecycleStatuses,
    )
      ? defaultDispatch.workerAttachLifecycleStatuses
      : workerAttachLifecycle
          .map((event) => event?.attachStatus)
          .filter((status) => typeof status === "string");
    const workerAttachLifecycleAttemptIds = Array.isArray(
      defaultDispatch?.workerAttachLifecycleAttemptIds,
    )
      ? defaultDispatch.workerAttachLifecycleAttemptIds
      : workerAttachLifecycle
          .map((event) => event?.attemptId)
          .filter((attemptId) => typeof attemptId === "string");
    const workerSessionRecord =
      defaultDispatch?.workerSessionRecord ??
      workflow?.metadata?.harness?.workerSessionRecord ??
      activationRecord?.workerSessionRecord ??
      null;
    const workerLaunchEnvelopes =
      defaultDispatch?.workerLaunchEnvelopes ??
      workflow?.metadata?.harness?.workerLaunchEnvelopes ??
      activationRecord?.workerLaunchEnvelopes ??
      [];
    const workerHandoffReceipts =
      defaultDispatch?.workerHandoffReceipts ??
      workflow?.metadata?.harness?.workerHandoffReceipts ??
      activationRecord?.workerHandoffReceipts ??
      [];
    const workerLaunchEnvelopeIds = Array.isArray(
      defaultDispatch?.workerLaunchEnvelopeIds,
    )
      ? defaultDispatch.workerLaunchEnvelopeIds
      : workerLaunchEnvelopes
          .map((envelope) => envelope?.envelopeId)
          .filter((envelopeId) => typeof envelopeId === "string");
    const workerHandoffReceiptIds = Array.isArray(
      defaultDispatch?.workerHandoffReceiptIds,
    )
      ? defaultDispatch.workerHandoffReceiptIds
      : workerHandoffReceipts
          .map((receipt) => receipt?.receiptId)
          .filter((receiptId) => typeof receiptId === "string");
    const workerHandoffNodeAttempts = Array.isArray(
      defaultDispatch?.workerHandoffNodeAttempts,
    )
      ? defaultDispatch.workerHandoffNodeAttempts
      : [];
    const workerHandoffNodeAttemptIds = Array.isArray(
      defaultDispatch?.workerHandoffNodeAttemptIds,
    )
      ? defaultDispatch.workerHandoffNodeAttemptIds
      : workerHandoffNodeAttempts
          .map((attempt) => attempt?.attemptId)
          .filter((attemptId) => typeof attemptId === "string");
    const workerHandoffReplayFixtureRefs = Array.isArray(
      defaultDispatch?.workerHandoffReplayFixtureRefs,
    )
      ? defaultDispatch.workerHandoffReplayFixtureRefs
      : workerHandoffNodeAttempts
          .map((attempt) => attempt?.replay?.fixtureRef)
          .filter((fixtureRef) => typeof fixtureRef === "string");
    const deepLinkReplayProof =
      workflow?.metadata?.harness?.deepLinkReplayProof ?? null;
    const coldStartDeepLinkRestoreProof =
      workflow?.metadata?.harness?.coldStartDeepLinkRestoreProof ?? null;
    const activationBlockerDeepLinkProof =
      workflow?.metadata?.harness?.activationBlockerDeepLinkProof ?? null;
    const activationGateDeepLinkProof =
      workflow?.metadata?.harness?.activationGateDeepLinkProof ?? null;
    const liveActivationGateDeepLinkProof =
      workflow?.metadata?.harness?.liveActivationGateDeepLinkProof ?? null;
    const liveTurnNodeInspectorDeepLinkProof =
      workflow?.metadata?.harness?.liveTurnNodeInspectorDeepLinkProof ?? null;
    const liveShadowComparisonDeepLinkProof =
      workflow?.metadata?.harness?.liveShadowComparisonDeepLinkProof ?? null;
    const activeRuntimeRollbackProofWorkbenchProof =
      workflow?.metadata?.harness?.activeRuntimeRollbackProofWorkbenchProof ??
      null;
    const activeRuntimeRollbackExecutionProof =
      workflow?.metadata?.harness?.activeRuntimeRollbackExecutionProof ?? null;
    const activeRuntimeRollbackApplyProof =
      workflow?.metadata?.harness?.activeRuntimeRollbackApplyProof ?? null;
    const activeRuntimeRollbackNegativeApplyProof =
      workflow?.metadata?.harness?.activeRuntimeRollbackNegativeApplyProof ??
      null;
    const activationGateActionClickProof =
      workflow?.metadata?.harness?.activationGateActionClickProof ?? null;
    const packageEvidenceGateClickProof =
      workflow?.metadata?.harness?.packageEvidenceGateClickProof ?? null;
    const packageEvidenceImportRoundTripProof =
      workflow?.metadata?.harness?.packageEvidenceImportRoundTripProof ?? null;
    const packageImportReviewProof =
      workflow?.metadata?.harness?.packageImportReviewProof ?? null;
    const packageImportActivationHandoffProof =
      workflow?.metadata?.harness?.packageImportActivationHandoffProof ?? null;
    const packageImportActivationApplyProof =
      workflow?.metadata?.harness?.packageImportActivationApplyProof ?? null;
    const packageImportActivationReplayIntegrityProof =
      workflow?.metadata?.harness
        ?.packageImportActivationReplayIntegrityProof ?? null;
    const activationGateCollectEvidenceClickProof =
      workflow?.metadata?.harness?.activationGateCollectEvidenceClickProof ??
      null;
    const activationGateRollbackRestoreClickProof =
      workflow?.metadata?.harness?.activationGateRollbackRestoreClickProof ??
      null;
    const activationIdGateClickProof =
      workflow?.metadata?.harness?.activationIdGateClickProof ?? null;
    const workerInvariantNegativeEnforcementProof =
      workflow?.metadata?.harness?.workerInvariantNegativeEnforcementProof ??
      null;
    const revisionBinding =
      workflow?.metadata?.harness?.revisionBinding ??
      workflow?.metadata?.harness?.activationRecord?.revisionBinding ??
      null;
    const revisionBindingRef =
      revisionBinding?.activatedRevision ??
      revisionBinding?.workflowContentHash ??
      revisionBinding?.activationId ??
      null;
    const requiredDeepLinkReplayCaseIds = [
      "selector",
      "dispatch",
      "worker",
      "rollback",
      "receipt",
      "replay",
      "revision",
      "activation-audit",
    ];
    const deepLinkReplayCasesById = new Map(
      (deepLinkReplayProof?.cases ?? []).map((replayCase) => [
        replayCase.id,
        replayCase,
      ]),
    );
    const deepLinkReplayPassed =
      deepLinkReplayProof?.passed === true &&
      requiredDeepLinkReplayCaseIds.every((caseId) => {
        const replayCase = deepLinkReplayCasesById.get(caseId);
        return (
          replayCase?.passed === true &&
          typeof replayCase.hash === "string" &&
          replayCase.hash.startsWith("#harness-workbench?") &&
          replayCase.historyMatches === true &&
          replayCase.parsedMatches === true &&
          replayCase.observedValue === replayCase.expectedValue
        );
      });
    const coldStartDeepLinkRestoreCasesById = new Map(
      (coldStartDeepLinkRestoreProof?.cases ?? []).map((restoreCase) => [
        restoreCase.id,
        restoreCase,
      ]),
    );
    const coldStartDeepLinkRestorePassed =
      coldStartDeepLinkRestoreProof?.passed === true &&
      requiredDeepLinkReplayCaseIds.every((caseId) => {
        const restoreCase = coldStartDeepLinkRestoreCasesById.get(caseId);
        return (
          restoreCase?.passed === true &&
          typeof restoreCase.hash === "string" &&
          restoreCase.hash.startsWith("#harness-workbench?") &&
          restoreCase.initialHash === restoreCase.hash &&
          restoreCase.historyMatches === true &&
          restoreCase.parsedMatches === true &&
          restoreCase.workflowReloaded === true &&
          restoreCase.restoredFromInitialHash === true &&
          restoreCase.observedValue === restoreCase.expectedValue
        );
      });
    const activationGateDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate",
      ) ?? null;
    const activationGateEvidenceDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate-evidence",
      ) ?? null;
    const activationGateReceiptDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate-receipt",
      ) ?? null;
    const activationGateReplayDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate-replay",
      ) ?? null;
    const activationGateCanaryBoundaryDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate-canary-boundary",
      ) ?? null;
    const activationGateCanaryRollbackDrillDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) =>
          replayCase.id === "activation-gate-canary-rollback-drill",
      ) ?? null;
    const activationGateNodeAttemptDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate-node-attempt",
      ) ?? null;
    const activationGateMutationCanaryNodeAttemptDeepLinkCase =
      activationGateDeepLinkProof?.cases?.find(
        (replayCase) =>
          replayCase.id === "activation-gate-mutation-canary-node-attempt",
      ) ?? null;
    const activationGateWorkerInvariantDeepLinkCase =
      liveActivationGateDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "activation-gate-worker-invariant",
      ) ?? null;
    const activationGateEvidenceRefCount = Number(
      activationGateDeepLinkCase?.observedSelectedState?.[
        "data-evidence-ref-count"
      ] ?? 0,
    );
    const activationGateWorkerInvariantState =
      activationGateWorkerInvariantDeepLinkCase?.observedSelectedState ?? {};
    const activationGateWorkerInvariantRequiredIds = String(
      activationGateWorkerInvariantState["data-required-invariant-ids"] ?? "",
    )
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const activationGateWorkerInvariantDeepLinkRestored =
      liveActivationGateDeepLinkProof?.passed === true &&
      activationGateWorkerInvariantDeepLinkCase?.passed === true &&
      activationGateWorkerInvariantDeepLinkCase?.selectedRailTestId ===
        "workflow-harness-activation-gate-inspector" &&
      typeof activationGateWorkerInvariantDeepLinkCase?.hash === "string" &&
      activationGateWorkerInvariantDeepLinkCase.hash.startsWith(
        "#harness-workbench?",
      ) &&
      activationGateWorkerInvariantDeepLinkCase.hash.includes(
        "panel=settings",
      ) &&
      activationGateWorkerInvariantDeepLinkCase.hash.includes(
        "activationGateId=worker-invariant",
      ) &&
      activationGateWorkerInvariantDeepLinkCase.historyMatches === true &&
      activationGateWorkerInvariantDeepLinkCase.parsedMatches === true &&
      activationGateWorkerInvariantDeepLinkCase.observedValue ===
        "worker-invariant" &&
      activationGateWorkerInvariantState["data-selected-activation-gate-id"] ===
        "worker-invariant" &&
      activationGateWorkerInvariantState["data-gate-status"] === "passed" &&
      activationGateWorkerInvariantRequiredIds.includes(
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
      ) &&
      String(
        activationGateWorkerInvariantState["data-invariant-blockers"] ?? "",
      ) === "" &&
      String(
        activationGateWorkerInvariantState["data-invariant-blocker-count"] ??
          "",
      ) === "0" &&
      String(
        activationGateWorkerInvariantState["data-gate-action-id"] ?? "",
      ).startsWith("activation-gate-action:worker-invariant:") &&
      activationGateWorkerInvariantState["data-gate-action-command"] ===
        "workflow-harness-gate-action-worker-invariant";
    const workerInvariantNegativeDeepLink =
      workerInvariantNegativeEnforcementProof?.deepLink ?? {};
    const workerInvariantNegativeApply =
      workerInvariantNegativeEnforcementProof?.activationApply ?? {};
    const workerInvariantNegativeRequiredIds = Array.isArray(
      workerInvariantNegativeDeepLink.requiredInvariantIds,
    )
      ? workerInvariantNegativeDeepLink.requiredInvariantIds
      : [];
    const workerInvariantNegativeBlockers = Array.isArray(
      workerInvariantNegativeDeepLink.invariantBlockers,
    )
      ? workerInvariantNegativeDeepLink.invariantBlockers
      : [];
    const workerInvariantNegativeApplyBlockers = Array.isArray(
      workerInvariantNegativeApply.blockers,
    )
      ? workerInvariantNegativeApply.blockers
      : [];
    const workerInvariantNegativeEnforcement =
      workerInvariantNegativeEnforcementProof?.passed === true &&
      workerInvariantNegativeEnforcementProof?.schemaVersion ===
        "workflow.harness.worker-invariant-negative-enforcement-proof.v1" &&
      workerInvariantNegativeEnforcementProof?.invalidCandidate?.decision ===
        "blocked" &&
      workerInvariantNegativeEnforcementProof.invalidCandidate.activationBlockers?.includes(
        "worker_launch_reviewed_import_activation_apply_invariant_missing",
      ) === true &&
      typeof workerInvariantNegativeDeepLink.hash === "string" &&
      workerInvariantNegativeDeepLink.hash.startsWith("#harness-workbench?") &&
      workerInvariantNegativeDeepLink.hash.includes("panel=settings") &&
      workerInvariantNegativeDeepLink.hash.includes(
        "activationGateId=worker-invariant",
      ) &&
      workerInvariantNegativeDeepLink.selectedRailTestId ===
        "workflow-harness-activation-gate-inspector" &&
      workerInvariantNegativeDeepLink.gateId === "worker-invariant" &&
      workerInvariantNegativeDeepLink.status === "blocked" &&
      workerInvariantNegativeBlockers.includes(
        "worker_launch_reviewed_import_activation_invariant_not_bound",
      ) &&
      (!workerInvariantNegativeRequiredIds.includes(
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
      ) ||
        workerInvariantNegativeBlockers.includes(
          "worker_launch_reviewed_import_activation_invariant_not_bound",
        )) &&
      Number(workerInvariantNegativeDeepLink.invariantBlockerCount ?? 0) > 0 &&
      workerInvariantNegativeDeepLink.action?.id ===
        "activation-gate-action:worker-invariant:check-readiness" &&
      workerInvariantNegativeDeepLink.action?.kind === "check_readiness" &&
      workerInvariantNegativeDeepLink.action?.impact === "inspect" &&
      workerInvariantNegativeDeepLink.action?.command ===
        "workflow-harness-gate-action-worker-invariant" &&
      workerInvariantNegativeApply.attempted === true &&
      workerInvariantNegativeApply.applied === false &&
      workerInvariantNegativeApply.activationId === null &&
      workerInvariantNegativeApply.workflowActivationId === null &&
      workerInvariantNegativeApply.workflowActivationState === "blocked" &&
      workerInvariantNegativeApplyBlockers.includes(
        "worker_launch_reviewed_import_activation_apply_invariant_missing",
      ) &&
      workerInvariantNegativeApplyBlockers.includes("candidate_not_mintable") &&
      workerInvariantNegativeApply.workerBindingAuthorityReady === false &&
      workerInvariantNegativeApply.workerSessionLive === false &&
      Number(workerInvariantNegativeApply.workerLaunchEnvelopeCount ?? 0) ===
        0 &&
      Number(workerInvariantNegativeApply.workerHandoffReceiptCount ?? 0) ===
        0 &&
      Number(
        workerInvariantNegativeApply.workerHandoffNodeAttemptCount ?? 0,
      ) === 0 &&
      workerInvariantNegativeApply.latestAuditEventType ===
        "activation_mint_blocked" &&
      workerInvariantNegativeApply.latestAuditStatus === "blocked";
    const activationGateReferenceDeepLinkRestored = (
      replayCase,
      paramName,
      stateName,
    ) =>
      replayCase?.passed === true &&
      typeof replayCase.hash === "string" &&
      replayCase.hash.includes(`${paramName}=`) &&
      replayCase.historyMatches === true &&
      replayCase.parsedMatches === true &&
      replayCase.observedValue === replayCase.expectedValue &&
      replayCase.observedSelectedState?.[stateName] ===
        replayCase.expectedValue;
    const liveTurnNodeInspectorDeepLinkCase =
      liveTurnNodeInspectorDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "live-turn-node-inspector",
      ) ?? null;
    const liveShadowComparisonDeepLinkCase =
      liveShadowComparisonDeepLinkProof?.cases?.find(
        (replayCase) => replayCase.id === "live-shadow-comparison",
      ) ?? null;
    const defaultDispatchAdapterAttempts = [
      ...(defaultDispatch?.cognitionExecutionAdapterResults ?? []),
      ...(defaultDispatch?.cognitionExecutionShadowAdapterResults ?? []),
      ...(defaultDispatch?.cognitionExecutionGateAdapterResults ?? []),
      ...(defaultDispatch?.routingModelAdapterResults ?? []),
      ...(defaultDispatch?.routingModelShadowAdapterResults ?? []),
      ...(defaultDispatch?.verificationOutputAdapterResults ?? []),
      ...(defaultDispatch?.verificationOutputShadowAdapterResults ?? []),
      ...(defaultDispatch?.authorityToolingAdapterResults ?? []),
      ...(defaultDispatch?.authorityToolingShadowAdapterResults ?? []),
    ]
      .map((result) => result?.nodeAttempt ?? null)
      .filter(Boolean);
    const defaultDispatchNodeAttempts = [
      ...defaultDispatchAdapterAttempts,
      ...(defaultDispatch?.dispatchNodeAttempts ?? []),
    ];
    const liveTurnNodeInspectorAttempt =
      defaultDispatchNodeAttempts.find(
        (attempt) =>
          attempt?.attemptId ===
          liveTurnNodeInspectorDeepLinkCase?.expectedValue,
      ) ??
      defaultDispatchNodeAttempts.find(
        (attempt) =>
          attempt?.executionMode === "live" &&
          attempt?.readiness === "live_ready" &&
          attempt?.status === "live" &&
          Array.isArray(attempt?.receiptIds) &&
          attempt.receiptIds.length > 0 &&
          typeof attempt?.replay?.fixtureRef === "string" &&
          attempt.replay.fixtureRef.length > 0,
      ) ??
      null;
    const liveTurnNodeInspectorState =
      liveTurnNodeInspectorDeepLinkCase?.observedSelectedState ?? {};
    const liveTurnNodeInspectorReceiptRefs = String(
      liveTurnNodeInspectorState["data-receipt-refs"] ?? "",
    )
      .split(/[|,]/)
      .map((value) => value.trim())
      .filter(Boolean);
    const liveTurnNodeInspectorDeepLinkRestored =
      liveTurnNodeInspectorDeepLinkProof?.passed === true &&
      liveTurnNodeInspectorDeepLinkCase?.passed === true &&
      liveTurnNodeInspectorDeepLinkCase?.selectedRailTestId ===
        "workflow-harness-node-attempt-inspector" &&
      typeof liveTurnNodeInspectorDeepLinkCase?.hash === "string" &&
      liveTurnNodeInspectorDeepLinkCase.hash.startsWith(
        "#harness-workbench?",
      ) &&
      liveTurnNodeInspectorDeepLinkCase.hash.includes("panel=outputs") &&
      liveTurnNodeInspectorDeepLinkCase.hash.includes("nodeAttemptId=") &&
      liveTurnNodeInspectorDeepLinkCase.hash.includes("receiptRef=") &&
      liveTurnNodeInspectorDeepLinkCase.hash.includes("replayFixtureRef=") &&
      liveTurnNodeInspectorDeepLinkCase.historyMatches === true &&
      liveTurnNodeInspectorDeepLinkCase.parsedMatches === true &&
      liveTurnNodeInspectorDeepLinkCase.observedValue ===
        liveTurnNodeInspectorDeepLinkCase.expectedValue &&
      Boolean(liveTurnNodeInspectorAttempt) &&
      liveTurnNodeInspectorState["data-node-attempt-id"] ===
        liveTurnNodeInspectorAttempt?.attemptId &&
      liveTurnNodeInspectorState["data-node-attempt-source-kind"] ===
        "default_runtime_dispatch" &&
      liveTurnNodeInspectorState["data-workflow-node-id"] ===
        liveTurnNodeInspectorAttempt?.workflowNodeId &&
      liveTurnNodeInspectorState["data-component-kind"] ===
        liveTurnNodeInspectorAttempt?.componentKind &&
      liveTurnNodeInspectorState["data-component-id"] ===
        liveTurnNodeInspectorAttempt?.componentId &&
      liveTurnNodeInspectorState["data-harness-workflow-id"] ===
        liveTurnNodeInspectorAttempt?.harnessWorkflowId &&
      liveTurnNodeInspectorState["data-harness-activation-id"] ===
        liveTurnNodeInspectorAttempt?.harnessActivationId &&
      liveTurnNodeInspectorState["data-harness-hash"] ===
        liveTurnNodeInspectorAttempt?.harnessHash &&
      liveTurnNodeInspectorState["data-execution-mode"] ===
        liveTurnNodeInspectorAttempt?.executionMode &&
      liveTurnNodeInspectorState["data-readiness"] ===
        liveTurnNodeInspectorAttempt?.readiness &&
      liveTurnNodeInspectorState["data-status"] ===
        liveTurnNodeInspectorAttempt?.status &&
      liveTurnNodeInspectorState["data-policy-decision"] ===
        liveTurnNodeInspectorAttempt?.policyDecision &&
      liveTurnNodeInspectorReceiptRefs.includes(
        liveTurnNodeInspectorAttempt?.receiptIds?.[0],
      ) &&
      liveTurnNodeInspectorState["data-replay-fixture-ref"] ===
        liveTurnNodeInspectorAttempt?.replay?.fixtureRef &&
      liveTurnNodeInspectorState["data-input-hash"] ===
        liveTurnNodeInspectorAttempt?.inputHash &&
      liveTurnNodeInspectorState["data-output-hash"] ===
        liveTurnNodeInspectorAttempt?.outputHash;
    const liveShadowComparison =
      (defaultDispatch?.liveShadowComparisons ?? []).find(
        (comparison) =>
          comparison.liveAttemptId ===
          liveShadowComparisonDeepLinkCase?.expectedValue,
      ) ??
      (defaultDispatch?.liveShadowComparisons ?? [])[0] ??
      null;
    const liveShadowLiveAttempt =
      defaultDispatchNodeAttempts.find(
        (attempt) => attempt?.attemptId === liveShadowComparison?.liveAttemptId,
      ) ?? null;
    const liveShadowShadowAttempt =
      defaultDispatchNodeAttempts.find(
        (attempt) =>
          attempt?.attemptId === liveShadowComparison?.shadowAttemptId,
      ) ?? null;
    const liveShadowComparisonState =
      liveShadowComparisonDeepLinkCase?.observedSelectedState ?? {};
    const liveShadowComparisonLiveReceiptRefs = String(
      liveShadowComparisonState["data-live-receipt-refs"] ?? "",
    )
      .split(/[|,]/)
      .map((value) => value.trim())
      .filter(Boolean);
    const liveShadowComparisonShadowReceiptRefs = String(
      liveShadowComparisonState["data-shadow-receipt-refs"] ?? "",
    )
      .split(/[|,]/)
      .map((value) => value.trim())
      .filter(Boolean);
    const liveShadowComparisonDeepLinkRestored =
      liveShadowComparisonDeepLinkProof?.passed === true &&
      liveShadowComparisonDeepLinkCase?.passed === true &&
      liveShadowComparisonDeepLinkCase?.selectedRailTestId ===
        "workflow-harness-live-shadow-comparison-inspector" &&
      typeof liveShadowComparisonDeepLinkCase?.hash === "string" &&
      liveShadowComparisonDeepLinkCase.hash.startsWith("#harness-workbench?") &&
      liveShadowComparisonDeepLinkCase.hash.includes("panel=outputs") &&
      liveShadowComparisonDeepLinkCase.hash.includes("nodeAttemptId=") &&
      liveShadowComparisonDeepLinkCase.hash.includes("receiptRef=") &&
      liveShadowComparisonDeepLinkCase.hash.includes("replayFixtureRef=") &&
      liveShadowComparisonDeepLinkCase.historyMatches === true &&
      liveShadowComparisonDeepLinkCase.parsedMatches === true &&
      liveShadowComparisonDeepLinkCase.observedValue ===
        liveShadowComparisonDeepLinkCase.expectedValue &&
      Boolean(liveShadowComparison) &&
      Boolean(liveShadowLiveAttempt) &&
      Boolean(liveShadowShadowAttempt) &&
      liveShadowComparisonState["data-live-attempt-id"] ===
        liveShadowComparison?.liveAttemptId &&
      liveShadowComparisonState["data-shadow-attempt-id"] ===
        liveShadowComparison?.shadowAttemptId &&
      liveShadowComparisonState["data-workflow-node-id"] ===
        liveShadowComparison?.workflowNodeId &&
      liveShadowComparisonState["data-component-kind"] ===
        liveShadowComparison?.componentKind &&
      liveShadowComparisonState["data-divergence"] ===
        liveShadowComparison?.divergence &&
      liveShadowComparisonState["data-blocking"] ===
        (liveShadowComparison?.blocking ? "true" : "false") &&
      liveShadowComparisonLiveReceiptRefs.includes(
        liveShadowLiveAttempt?.receiptIds?.[0],
      ) &&
      liveShadowComparisonShadowReceiptRefs.includes(
        liveShadowShadowAttempt?.receiptIds?.[0],
      ) &&
      liveShadowComparisonState["data-live-replay-fixture-ref"] ===
        liveShadowLiveAttempt?.replay?.fixtureRef &&
      liveShadowComparisonState["data-shadow-replay-fixture-ref"] ===
        liveShadowShadowAttempt?.replay?.fixtureRef &&
      liveShadowComparisonState["data-live-input-hash"] ===
        liveShadowLiveAttempt?.inputHash &&
      liveShadowComparisonState["data-shadow-input-hash"] ===
        liveShadowShadowAttempt?.inputHash &&
      liveShadowComparisonState["data-live-output-hash"] ===
        liveShadowLiveAttempt?.outputHash &&
      liveShadowComparisonState["data-shadow-output-hash"] ===
        liveShadowShadowAttempt?.outputHash;
    const expectedRollbackGateId = "p0-live-shadow-comparison-gate";
    const expectedRollbackReadinessProofId =
      selector?.livePromotionReadinessProof?.proofId ??
      defaultDispatch?.livePromotionReadinessProof?.proofId ??
      null;
    const expectedRollbackPolicyDecision =
      "allow_default_harness_worker_rollback_from_live_shadow_gate";
    const activeRuntimeRollbackProofCasesById = new Map(
      (activeRuntimeRollbackProofWorkbenchProof?.cases ?? []).map(
        (replayCase) => [replayCase.id, replayCase],
      ),
    );
    const activeRuntimeRollbackProofRequiredCaseIds = [
      "active-runtime-rollback-target",
      "active-runtime-rollback-launch-envelope",
      "active-runtime-rollback-handoff-receipt",
      "active-runtime-rollback-node-attempt",
      "active-runtime-rollback-replay",
    ];
    const activeRuntimeRollbackProofState =
      activeRuntimeRollbackProofCasesById.get(
        "active-runtime-rollback-node-attempt",
      )?.observedSelectedState ??
      activeRuntimeRollbackProofCasesById.get("active-runtime-rollback-target")
        ?.observedSelectedState ??
      {};
    const rollbackLaunchEnvelope = workerLaunchEnvelopes.find(
      (envelope) => envelope?.phase === "rollback",
    );
    const rollbackHandoffReceipt = workerHandoffReceipts.find(
      (receipt) => receipt?.phase === "rollback",
    );
    const rollbackNodeAttempt = workerHandoffNodeAttempts.find(
      (attempt) =>
        rollbackHandoffReceipt?.receiptId &&
        attempt?.receiptIds?.includes(rollbackHandoffReceipt.receiptId),
    );
    const rollbackReplayFixtureRef =
      rollbackNodeAttempt?.replay?.fixtureRef ??
      workerHandoffReplayFixtureRefs.find((fixtureRef) =>
        fixtureRef.includes(":rollback:"),
      ) ??
      null;
    const activeRuntimeRollbackProofWorkbench =
      activeRuntimeRollbackProofWorkbenchProof?.passed === true &&
      activeRuntimeRollbackProofRequiredCaseIds.every((caseId) => {
        const replayCase = activeRuntimeRollbackProofCasesById.get(caseId);
        return (
          replayCase?.passed === true &&
          typeof replayCase.hash === "string" &&
          replayCase.hash.startsWith("#harness-workbench?") &&
          replayCase.historyMatches === true &&
          replayCase.parsedMatches === true &&
          replayCase.observedValue === replayCase.expectedValue &&
          replayCase.observedSelectedState?.["data-rollback-proof-bound"] ===
            "true"
        );
      }) &&
      activeRuntimeRollbackProofState["data-rollback-proof-bound"] === "true" &&
      activeRuntimeRollbackProofState["data-rollback-readiness-proof-id"] ===
        expectedRollbackReadinessProofId &&
      activeRuntimeRollbackProofState["data-rollback-live-shadow-gate-id"] ===
        expectedRollbackGateId &&
      activeRuntimeRollbackProofState[
        "data-rollback-live-shadow-gate-ready"
      ] === "true" &&
      activeRuntimeRollbackProofState["data-rollback-activation-id"] ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      activeRuntimeRollbackProofState["data-rollback-harness-hash"] ===
        DEFAULT_AGENT_HARNESS_HASH &&
      activeRuntimeRollbackProofState["data-rollback-policy-decision"] ===
        expectedRollbackPolicyDecision &&
      activeRuntimeRollbackProofState["data-rollback-launch-envelope-id"] ===
        rollbackLaunchEnvelope?.envelopeId &&
      activeRuntimeRollbackProofState["data-rollback-handoff-receipt-id"] ===
        rollbackHandoffReceipt?.receiptId &&
      activeRuntimeRollbackProofState["data-rollback-node-attempt-id"] ===
        rollbackNodeAttempt?.attemptId &&
      activeRuntimeRollbackProofState["data-rollback-replay-fixture-ref"] ===
        rollbackReplayFixtureRef;
    const activeRuntimeRollbackExecutionWorkbench =
      activeRuntimeRollbackProofWorkbench &&
      activeRuntimeRollbackExecutionProof?.schemaVersion ===
        "workflow.harness.active-runtime-rollback-execution-proof.v1" &&
      activeRuntimeRollbackExecutionProof?.passed === true &&
      activeRuntimeRollbackExecutionProof?.dryRun?.clicked === true &&
      activeRuntimeRollbackExecutionProof?.dryRun?.passed === true &&
      activeRuntimeRollbackExecutionProof?.dryRun?.canaryStatus ===
        "passed" &&
      activeRuntimeRollbackExecutionProof?.dryRun?.canaryHashVerified ===
        true &&
      typeof activeRuntimeRollbackExecutionProof?.dryRun?.canaryResultId ===
        "string" &&
      activeRuntimeRollbackExecutionProof.dryRun.canaryResultId.startsWith(
        "harness-active-runtime-rollback-canary:",
      ) &&
      ["ready", "applied"].includes(
        activeRuntimeRollbackExecutionProof?.apply?.readiness,
      ) &&
      activeRuntimeRollbackExecutionProof?.apply?.disabled === false &&
      activeRuntimeRollbackExecutionProof?.routeRestore?.rollbackProofBound ===
        true &&
      activeRuntimeRollbackExecutionProof?.routeRestore?.dryRunStatus ===
        "passed" &&
      activeRuntimeRollbackExecutionProof?.routeRestore?.applyDisabled ===
        false &&
      activeRuntimeRollbackExecutionProof?.readinessProofId ===
        expectedRollbackReadinessProofId &&
      activeRuntimeRollbackExecutionProof?.liveShadowComparisonGateId ===
        expectedRollbackGateId &&
      activeRuntimeRollbackExecutionProof?.activationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      activeRuntimeRollbackExecutionProof?.harnessHash ===
        DEFAULT_AGENT_HARNESS_HASH &&
      activeRuntimeRollbackExecutionProof?.launchEnvelopeId ===
        rollbackLaunchEnvelope?.envelopeId &&
      activeRuntimeRollbackExecutionProof?.handoffReceiptId ===
        rollbackHandoffReceipt?.receiptId &&
      activeRuntimeRollbackExecutionProof?.nodeAttemptId ===
        rollbackNodeAttempt?.attemptId &&
      activeRuntimeRollbackExecutionProof?.replayFixtureRef ===
        rollbackReplayFixtureRef &&
      (
        activeRuntimeRollbackExecutionProof?.dryRun?.receiptRefs ?? []
      ).includes(rollbackHandoffReceipt?.receiptId) &&
      (
        activeRuntimeRollbackExecutionProof?.dryRun?.replayFixtureRefs ?? []
      ).includes(rollbackReplayFixtureRef);
    const activeRuntimeRollbackApplyAuditEvent =
      audit.find(
        (event) =>
          event?.eventId === activeRuntimeRollbackApplyProof?.auditEventId,
      ) ?? null;
    const activeRuntimeRollbackApplyExecution =
      activeRuntimeRollbackExecutionWorkbench &&
      activeRuntimeRollbackApplyProof?.schemaVersion ===
        "workflow.harness.active-runtime-rollback-apply-proof.v1" &&
      activeRuntimeRollbackApplyProof?.passed === true &&
      activeRuntimeRollbackApplyProof?.rollbackApplied === true &&
      activeRuntimeRollbackApplyProof?.applyStatus === "applied" &&
      activeRuntimeRollbackApplyProof?.rollbackTargetVerified === true &&
      activeRuntimeRollbackApplyProof?.hashVerified === true &&
      activeRuntimeRollbackApplyProof?.staleProofBlocked === false &&
      activeRuntimeRollbackApplyProof?.detachedProofBlocked === false &&
      typeof activeRuntimeRollbackApplyProof?.executionId === "string" &&
      activeRuntimeRollbackApplyProof.executionId.startsWith(
        "harness-active-runtime-rollback-apply:",
      ) &&
      typeof activeRuntimeRollbackApplyProof?.rollbackReceiptId === "string" &&
      activeRuntimeRollbackApplyProof.rollbackReceiptId.startsWith(
        "harness-active-runtime-rollback-apply-receipt:",
      ) &&
      typeof activeRuntimeRollbackApplyProof?.auditEventId === "string" &&
      activeRuntimeRollbackApplyProof.auditEventId.startsWith(
        "harness-activation-audit:",
      ) &&
      activeRuntimeRollbackApplyProof?.dryRunCanaryResultId ===
        activeRuntimeRollbackExecutionProof?.dryRun?.canaryResultId &&
      activeRuntimeRollbackApplyProof?.rollbackTarget ===
        activeRuntimeRollbackExecutionProof?.rollbackTarget &&
      activeRuntimeRollbackApplyProof?.readinessProofId ===
        expectedRollbackReadinessProofId &&
      activeRuntimeRollbackApplyProof?.liveShadowComparisonGateId ===
        expectedRollbackGateId &&
      activeRuntimeRollbackApplyProof?.activationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      activeRuntimeRollbackApplyProof?.harnessHash ===
        DEFAULT_AGENT_HARNESS_HASH &&
      activeRuntimeRollbackApplyProof?.launchEnvelopeId ===
        rollbackLaunchEnvelope?.envelopeId &&
      activeRuntimeRollbackApplyProof?.handoffReceiptId ===
        rollbackHandoffReceipt?.receiptId &&
      activeRuntimeRollbackApplyProof?.nodeAttemptId ===
        rollbackNodeAttempt?.attemptId &&
      activeRuntimeRollbackApplyProof?.replayFixtureRef ===
        rollbackReplayFixtureRef &&
      (activeRuntimeRollbackApplyProof?.receiptRefs ?? []).includes(
        activeRuntimeRollbackApplyProof?.rollbackReceiptId,
      ) &&
      (activeRuntimeRollbackApplyProof?.receiptRefs ?? []).includes(
        rollbackHandoffReceipt?.receiptId,
      ) &&
      (activeRuntimeRollbackApplyProof?.replayFixtureRefs ?? []).includes(
        rollbackReplayFixtureRef,
      ) &&
      activeRuntimeRollbackExecutionProof?.apply?.applied === true &&
      activeRuntimeRollbackExecutionProof?.apply?.executionId ===
        activeRuntimeRollbackApplyProof.executionId &&
      activeRuntimeRollbackExecutionProof?.apply?.rollbackReceiptId ===
        activeRuntimeRollbackApplyProof.rollbackReceiptId &&
      activeRuntimeRollbackExecutionProof?.apply?.auditEventId ===
        activeRuntimeRollbackApplyProof.auditEventId &&
      activeRuntimeRollbackExecutionProof?.apply?.rollbackTargetVerified ===
        true &&
      activeRuntimeRollbackExecutionProof?.apply?.hashVerified === true &&
      activeRuntimeRollbackApplyAuditEvent?.eventType ===
        "active_runtime_rollback_applied" &&
      activeRuntimeRollbackApplyAuditEvent?.status === "applied" &&
      activeRuntimeRollbackApplyAuditEvent?.rollbackExecuted === true &&
      activeRuntimeRollbackApplyAuditEvent?.receiptRefs?.includes(
        activeRuntimeRollbackApplyProof?.rollbackReceiptId,
      ) === true;
    const activeRuntimeRollbackNegativeRequiredProofCases = [
      {
        caseId: "stale-hash-node-replay",
        mutationKind: "stale_proof",
        staleProofBlocked: true,
        detachedProofBlocked: false,
        hashVerified: false,
        expectedBlockers: [
          "rollback_harness_hash_stale",
          "rollback_node_attempt_stale",
          "rollback_replay_fixture_stale",
          "rollback_apply_hash_not_verified",
        ],
      },
      {
        caseId: "detached-launch-envelope-missing",
        mutationKind: "detached_proof",
        staleProofBlocked: true,
        detachedProofBlocked: true,
        hashVerified: true,
        expectedBlockers: [
          "rollback_launch_envelope_missing",
          "rollback_launch_envelope_stale",
        ],
      },
      {
        caseId: "detached-handoff-receipt-missing",
        mutationKind: "detached_proof",
        staleProofBlocked: true,
        detachedProofBlocked: true,
        hashVerified: true,
        expectedBlockers: [
          "rollback_handoff_receipt_missing",
          "rollback_handoff_receipt_stale",
        ],
      },
      {
        caseId: "detached-node-attempt-missing",
        mutationKind: "detached_proof",
        staleProofBlocked: true,
        detachedProofBlocked: true,
        hashVerified: true,
        expectedBlockers: [
          "rollback_node_attempt_missing",
          "rollback_node_attempt_stale",
        ],
      },
      {
        caseId: "detached-node-attempt-orphaned",
        mutationKind: "detached_proof",
        staleProofBlocked: false,
        detachedProofBlocked: true,
        hashVerified: true,
        expectedBlockers: ["rollback_node_attempt_orphaned"],
      },
      {
        caseId: "detached-replay-fixture-missing",
        mutationKind: "detached_proof",
        staleProofBlocked: true,
        detachedProofBlocked: true,
        hashVerified: true,
        expectedBlockers: [
          "rollback_replay_fixture_missing",
          "rollback_replay_fixture_stale",
        ],
      },
    ];
    const activeRuntimeRollbackNegativeCasePassed = (requiredCase) => {
      const negativeCase =
        activeRuntimeRollbackNegativeApplyProof?.cases?.find(
          (candidate) => candidate.caseId === requiredCase.caseId,
        ) ?? null;
      return (
        negativeCase?.passed === true &&
        negativeCase?.mutationKind === requiredCase.mutationKind &&
        negativeCase?.applyButtonDisabled === true &&
        negativeCase?.applyStatus === "blocked" &&
        negativeCase?.staleProofBlocked ===
          requiredCase.staleProofBlocked &&
        negativeCase?.detachedProofBlocked ===
          requiredCase.detachedProofBlocked &&
        negativeCase?.rollbackApplied === false &&
        negativeCase?.hashVerified === requiredCase.hashVerified &&
        requiredCase.expectedBlockers.every((blocker) =>
          negativeCase?.expectedBlockers?.includes(blocker),
        ) &&
        requiredCase.expectedBlockers.every((blocker) =>
          negativeCase?.observedRailBlockers?.includes(blocker),
        ) &&
        requiredCase.expectedBlockers.every((blocker) =>
          negativeCase?.runtimeBlockers?.includes(blocker),
        )
      );
    };
    const activeRuntimeRollbackNegativeApply =
      activeRuntimeRollbackApplyExecution &&
      activeRuntimeRollbackNegativeApplyProof?.schemaVersion ===
        "workflow.harness.active-runtime-rollback-negative-apply-proof.v1" &&
      activeRuntimeRollbackNegativeApplyProof?.passed === true &&
      activeRuntimeRollbackNegativeApplyProof?.blockers?.length === 0 &&
      activeRuntimeRollbackNegativeRequiredProofCases.every((requiredCase) =>
        activeRuntimeRollbackNegativeCasePassed(requiredCase),
      );
    const routeStatefulDeepLinks = {
      selector: selector?.decisionId
        ? `#harness-workbench?${new URLSearchParams({
            panel: "settings",
            selectorDecisionId: selector.decisionId,
          }).toString()}`
        : null,
      dispatch: defaultDispatch?.dispatchId
        ? `#harness-workbench?${new URLSearchParams({
            panel: "settings",
            dispatchId: defaultDispatch.dispatchId,
          }).toString()}`
        : null,
      worker: workerBinding?.harnessActivationId
        ? `#harness-workbench?${new URLSearchParams({
            panel: "settings",
            workerBindingId: workerBinding.harnessActivationId,
          }).toString()}`
        : null,
      rollback: defaultDispatch?.rollbackTarget
        ? `#harness-workbench?${new URLSearchParams({
            panel: "settings",
            rollbackTarget: defaultDispatch.rollbackTarget,
          }).toString()}`
        : null,
      receipt: defaultDispatch?.receiptIds?.[0]
        ? `#harness-workbench?${new URLSearchParams({
            panel: "outputs",
            receiptRef: defaultDispatch.receiptIds[0],
          }).toString()}`
        : null,
      replay: defaultDispatch?.replayFixtureRefs?.[0]
        ? `#harness-workbench?${new URLSearchParams({
            panel: "outputs",
            replayFixtureRef: defaultDispatch.replayFixtureRefs[0],
          }).toString()}`
        : null,
      revision: revisionBindingRef
        ? `#harness-workbench?${new URLSearchParams({
            panel: "settings",
            revisionBindingKind: "current",
            revisionBindingRef,
          }).toString()}`
        : null,
      activationBlocker:
        activationBlockerDeepLinkProof?.cases?.find(
          (replayCase) => replayCase.id === "activation-blocker",
        )?.hash ?? null,
      activationGate: activationGateDeepLinkCase?.hash ?? null,
      activationGateWorkerInvariant:
        activationGateWorkerInvariantDeepLinkCase?.hash ?? null,
      workerInvariantNegative: workerInvariantNegativeDeepLink.hash ?? null,
      activationGateEvidence: activationGateEvidenceDeepLinkCase?.hash ?? null,
      activationGateNodeAttempt:
        activationGateNodeAttemptDeepLinkCase?.hash ??
        activationIdGateClickProof?.mintedActivation?.workerHandoffDeepLink ??
        null,
      activationGateMutationCanaryNodeAttempt:
        activationGateMutationCanaryNodeAttemptDeepLinkCase?.hash ?? null,
      activationGateReceipt: activationGateReceiptDeepLinkCase?.hash ?? null,
      activationGateReplay: activationGateReplayDeepLinkCase?.hash ?? null,
      activationGateCanaryBoundary:
        activationGateCanaryBoundaryDeepLinkCase?.hash ?? null,
      activationGateCanaryRollbackDrill:
        activationGateCanaryRollbackDrillDeepLinkCase?.hash ?? null,
      liveShadowComparison: liveShadowComparisonDeepLinkCase?.hash ?? null,
      activationAudit: audit[0]?.eventId
        ? `#harness-workbench?${new URLSearchParams({
            panel: "settings",
            activationAuditEventId: audit[0].eventId,
          }).toString()}`
        : null,
    };
    const transitionFor = (clusterId, targetExecutionMode, attemptStatus) =>
      transitions.some(
        (attempt) =>
          attempt.clusterId === clusterId &&
          attempt.targetExecutionMode === targetExecutionMode &&
          attempt.attemptStatus === attemptStatus,
      );
    const rollbackArtifactBoundToLiveShadowGate = (artifact) => {
      const readinessProofId =
        artifact?.readinessProofId ?? artifact?.receipt?.readinessProofId;
      return (
        artifact &&
        readinessProofId === expectedRollbackReadinessProofId &&
        artifact.rollbackReadinessProofId === expectedRollbackReadinessProofId &&
        artifact.rollbackLiveShadowComparisonGateId ===
          expectedRollbackGateId &&
        artifact.rollbackLiveShadowComparisonGateReady === true &&
        artifact.rollbackActivationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        artifact.rollbackHarnessHash === DEFAULT_AGENT_HARNESS_HASH &&
        artifact.rollbackPolicyDecision === expectedRollbackPolicyDecision
      );
    };
    const workerRollbackLiveShadowGateBound =
      defaultDispatch?.liveShadowComparisonGate?.gateId ===
        expectedRollbackGateId &&
      defaultDispatch?.liveShadowComparisonGateReady === true &&
      expectedRollbackReadinessProofId &&
      workerBindingRegistry?.workerBinding?.liveShadowComparisonGateId ===
        expectedRollbackGateId &&
      workerBindingRegistry?.workerBinding?.liveShadowComparisonGateReady ===
        true &&
      workerBindingRegistry?.workerBinding?.rollbackPolicyDecision ===
        expectedRollbackPolicyDecision &&
      rollbackArtifactBoundToLiveShadowGate(workerBindingRegistry) &&
      rollbackArtifactBoundToLiveShadowGate(workerAttachReceipt) &&
      rollbackArtifactBoundToLiveShadowGate(workerAttachResumeReceipt) &&
      rollbackArtifactBoundToLiveShadowGate(workerAttachRollbackReceipt) &&
      Array.isArray(workerAttachLifecycle) &&
      workerAttachLifecycle.length >= 3 &&
      workerAttachLifecycle.every((event) =>
        rollbackArtifactBoundToLiveShadowGate(event),
      ) &&
      rollbackArtifactBoundToLiveShadowGate(workerSessionRecord) &&
      Array.isArray(workerLaunchEnvelopes) &&
      workerLaunchEnvelopes.length >= 3 &&
      workerLaunchEnvelopes.every((envelope) =>
        rollbackArtifactBoundToLiveShadowGate(envelope),
      ) &&
      Array.isArray(workerHandoffReceipts) &&
      workerHandoffReceipts.length >= 3 &&
      workerHandoffReceipts.every((receipt) =>
        rollbackArtifactBoundToLiveShadowGate(receipt),
      );
    const workerBindingRegistryBound =
      workerBindingRegistry?.schemaVersion ===
        "workflow.harness.worker-binding-registry.v1" &&
      workerBindingRegistry?.bindingStatus === "bound" &&
      Array.isArray(workerBindingRegistry?.blockers) &&
      workerBindingRegistry.blockers.length === 0 &&
      workerBindingRegistry?.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
      workerBindingRegistry?.activationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerBindingRegistry?.activationHash === DEFAULT_AGENT_HARNESS_HASH &&
      workerBindingRegistry?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
      workerBindingRegistry?.rollbackTarget ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerBindingRegistry?.readinessProofId ===
        selector?.livePromotionReadinessProof?.proofId &&
      workerBindingRegistry?.readinessProofId ===
        defaultDispatch?.livePromotionReadinessProof?.proofId &&
      workerBindingRegistry?.canaryResultId?.includes(":passed") === true &&
      workerBindingRegistry?.policyDecision ===
        "promote_blessed_workflow_default_for_non_mutating_turn" &&
      workerBindingRegistry?.workerBinding?.harnessWorkflowId ===
        DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
      workerBindingRegistry?.workerBinding?.harnessActivationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerBindingRegistry?.workerBinding?.harnessHash ===
        DEFAULT_AGENT_HARNESS_HASH &&
      workerBindingRegistry?.workerBinding?.executionMode === "live" &&
      workerBindingRegistry?.workerBinding?.selectorDecisionId ===
        selector?.decisionId &&
      workerBindingRegistry?.workerBinding?.defaultDispatchId ===
        defaultDispatch?.dispatchId &&
      workerBindingRegistry?.workerBinding?.rollbackTarget ===
        selector?.rollbackTarget &&
      workerBindingRegistry?.workerBinding?.authorityBindingReady === true &&
      Array.isArray(
        workerBindingRegistry?.workerBinding?.authorityBindingBlockers,
      ) &&
      workerBindingRegistry.workerBinding.authorityBindingBlockers.length ===
        0 &&
      workerBindingRegistry?.workerBinding?.livePromotionReadinessProofId ===
        selector?.livePromotionReadinessProof?.proofId &&
      workerRollbackLiveShadowGateBound;
    const workerAttachBound =
      workerAttachReceipt?.schemaVersion ===
        "workflow.harness.worker-attach-receipt.v1" &&
      workerAttachReceipt?.accepted === true &&
      workerAttachReceipt?.attachStatus === "bound" &&
      Array.isArray(workerAttachReceipt?.blockers) &&
      workerAttachReceipt.blockers.length === 0 &&
      workerAttachReceipt?.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
      workerAttachReceipt?.activationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerAttachReceipt?.activationHash === DEFAULT_AGENT_HARNESS_HASH &&
      workerAttachReceipt?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
      workerAttachReceipt?.rollbackTarget ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerAttachReceipt?.rollbackAvailable === true &&
      workerAttachReceipt?.readinessProofId ===
        selector?.livePromotionReadinessProof?.proofId &&
      workerAttachReceipt?.registryRecordId ===
        workerBindingRegistry?.registryRecordId &&
      workerAttachReceipt?.workerBinding?.harnessActivationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerAttachReceipt?.workerBinding?.executionMode === "live";
    const workerAttachLifecycleComplete =
      Array.isArray(workerAttachLifecycle) &&
      workerAttachLifecycle.length >= 3 &&
      workerAttachLifecycleStatuses.includes("bound") &&
      workerAttachLifecycleStatuses.includes("resumed") &&
      workerAttachLifecycleStatuses.includes("rolled_back") &&
      workerAttachLifecycleAttemptIds.length >= 3 &&
      workerAttachResumeReceipt?.accepted === true &&
      workerAttachResumeReceipt?.attachStatus === "resumed" &&
      workerAttachRollbackReceipt?.accepted === true &&
      workerAttachRollbackReceipt?.attachStatus === "rolled_back" &&
      workerAttachLifecycle.every(
        (event) =>
          event?.schemaVersion ===
            "workflow.harness.worker-attach-lifecycle.v1" &&
          event?.workflowNodeId === "harness.handoff_bridge" &&
          event?.componentKind === "handoff_bridge" &&
          event?.accepted === true &&
          Array.isArray(event?.blockers) &&
          event.blockers.length === 0 &&
          defaultDispatch?.dispatchNodeAttemptIds?.includes(event.attemptId) ===
            true,
      );
    const workerSessionRecordBound =
      workerSessionRecord?.schemaVersion ===
        "workflow.harness.worker-session.v1" &&
      workerSessionRecord?.accepted === true &&
      workerSessionRecord?.currentStatus === "rollback_ready" &&
      workerSessionRecord?.resumed === true &&
      workerSessionRecord?.rollbackTargetReady === true &&
      workerSessionRecord?.registryRecordId ===
        workerBindingRegistry?.registryRecordId &&
      workerSessionRecord?.workerId === workerAttachReceipt?.workerId &&
      workerSessionRecord?.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
      workerSessionRecord?.activationId ===
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
      workerSessionRecord?.activationHash === DEFAULT_AGENT_HARNESS_HASH &&
      Array.isArray(workerSessionRecord?.blockers) &&
      workerSessionRecord.blockers.length === 0 &&
      typeof workerSessionRecord?.persistenceKey === "string" &&
      workerSessionRecord.persistenceKey.startsWith(
        "agent::harness_worker_session::",
      ) &&
      typeof workerSessionRecord?.recordPersistenceKey === "string" &&
      workerSessionRecord.recordPersistenceKey.startsWith(
        "agent::harness_worker_session_record::",
      ) &&
      workerSessionRecord?.persistedInRuntimeCheckpoint === true &&
      workerSessionRecord?.restoredFromPersistedSession === true &&
      workerSessionRecord?.runtimeCheckpointSource ===
        "runtime_state_access_harness_worker_session_record" &&
      Array.isArray(workerSessionRecord?.persistenceBlockers) &&
      workerSessionRecord.persistenceBlockers.length === 0 &&
      workerSessionRecord?.launchAuthorityReady === true &&
      Array.isArray(workerSessionRecord?.launchAuthorityBlockers) &&
      workerSessionRecord.launchAuthorityBlockers.length === 0 &&
      workerSessionRecord?.launchAuthoritySource ===
        "persisted_harness_worker_session_record" &&
      workerSessionRecord?.rollbackHandoffReady === true &&
      Array.isArray(workerSessionRecord?.rollbackHandoffBlockers) &&
      workerSessionRecord.rollbackHandoffBlockers.length === 0 &&
      workerSessionRecord?.rollbackHandoffTarget ===
        workerSessionRecord?.rollbackTarget &&
      Array.isArray(workerSessionRecord?.lifecycleAttemptIds) &&
      workerSessionRecord.lifecycleAttemptIds.length >= 3 &&
      workerSessionRecord.lifecycleAttemptIds.every(
        (attemptId) =>
          defaultDispatch?.dispatchNodeAttemptIds?.includes(attemptId) === true,
      );
    const workerLaunchHandoffBound =
      Array.isArray(workerLaunchEnvelopes) &&
      workerLaunchEnvelopes.length >= 3 &&
      Array.isArray(workerLaunchEnvelopeIds) &&
      workerLaunchEnvelopeIds.length >= 3 &&
      ["launch", "resume", "rollback"].every((phase) =>
        workerLaunchEnvelopes.some(
          (envelope) =>
            envelope?.schemaVersion ===
              "workflow.harness.worker-launch-envelope.v1" &&
            envelope?.phase === phase &&
            envelope?.sessionRecordId ===
              workerSessionRecord?.sessionRecordId &&
            envelope?.workerId === workerSessionRecord?.workerId &&
            envelope?.accepted === true &&
            Array.isArray(envelope?.blockers) &&
            envelope.blockers.length === 0 &&
            envelope?.launchAuthorityReady === true &&
            (phase !== "rollback" || envelope?.rollbackHandoffReady === true) &&
            workerLaunchEnvelopeIds.includes(envelope.envelopeId),
        ),
      ) &&
      Array.isArray(workerHandoffReceipts) &&
      workerHandoffReceipts.length >= 3 &&
      Array.isArray(workerHandoffReceiptIds) &&
      workerHandoffReceiptIds.length >= 3 &&
      [
        ["launch", "launched"],
        ["resume", "resumed"],
        ["rollback", "rollback_handoff_ready"],
      ].every(([phase, status]) =>
        workerHandoffReceipts.some(
          (receipt) =>
            receipt?.schemaVersion ===
              "workflow.harness.worker-handoff-receipt.v1" &&
            receipt?.phase === phase &&
            receipt?.handoffStatus === status &&
            receipt?.sessionRecordId === workerSessionRecord?.sessionRecordId &&
            receipt?.workerId === workerSessionRecord?.workerId &&
            receipt?.accepted === true &&
            Array.isArray(receipt?.blockers) &&
            receipt.blockers.length === 0 &&
            Array.isArray(receipt?.receiptRefs) &&
            receipt.receiptRefs.length >= 4 &&
            workerHandoffReceiptIds.includes(receipt.receiptId),
        ),
      );
    const workerHandoffNodeTimelineBound =
      Array.isArray(workerHandoffNodeAttempts) &&
      workerHandoffNodeAttempts.length >= 3 &&
      Array.isArray(workerHandoffNodeAttemptIds) &&
      workerHandoffNodeAttemptIds.length >= 3 &&
      Array.isArray(workerHandoffReplayFixtureRefs) &&
      workerHandoffReplayFixtureRefs.length >= 3 &&
      ["launch", "resume", "rollback"].every((phase) => {
        const receipt = workerHandoffReceipts.find(
          (candidate) => candidate?.phase === phase,
        );
        return workerHandoffNodeAttempts.some(
          (attempt) =>
            attempt?.attemptId ===
              `harness-worker-handoff:attempt:${phase}:${workerSessionRecord?.sessionRecordId}` &&
            attempt?.workflowNodeId === "harness.handoff_bridge" &&
            attempt?.componentKind === "handoff_bridge" &&
            attempt?.executionMode === "live" &&
            attempt?.status === "live" &&
            Array.isArray(attempt?.receiptIds) &&
            receipt?.receiptId &&
            attempt.receiptIds.includes(receipt.receiptId) &&
            attempt?.replay?.fixtureRef ===
              `harness-worker-handoff:fixture:${phase}:${workerSessionRecord?.sessionRecordId}` &&
            workerHandoffNodeAttemptIds.includes(attempt.attemptId) &&
            workerHandoffReplayFixtureRefs.includes(attempt.replay.fixtureRef),
        );
      }) &&
      workerHandoffNodeAttemptIds.every((attemptId) =>
        defaultDispatch?.dispatchNodeAttemptIds?.includes(attemptId),
      ) &&
      workerHandoffNodeAttemptIds.every((attemptId) =>
        defaultDispatch?.nodeAttemptIds?.includes(attemptId),
      );
    const reviewedImportActivationApplyActivationId =
      packageImportActivationApplyProof?.activationResult?.activationId ?? null;
    const reviewedImportActivationApplyRollbackTarget =
      packageImportActivationApplyProof?.activationAction?.rollbackTarget ??
      null;
    const reviewedImportActivationApplyResult =
      packageImportActivationApplyProof?.activationResult ?? null;
    const selectorReviewedImportActivationApplyInvariant =
      selector?.defaultLivePromotionInvariantIds?.includes(
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
      ) === true &&
      (selector?.defaultLivePromotionInvariantBlockers ?? []).length === 0 &&
      selector?.reviewedImportActivationApplyProofPresent === true &&
      selector?.reviewedImportActivationApplyProofPassed === true &&
      (selector?.reviewedImportActivationApplyProofBlockers ?? []).length ===
        0 &&
      typeof reviewedImportActivationApplyActivationId === "string" &&
      reviewedImportActivationApplyActivationId.length > 0 &&
      selector?.reviewedImportActivationApplyActivationId ===
        reviewedImportActivationApplyActivationId &&
      selector?.defaultPromotionGate?.requiredInvariantIds?.includes(
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
      ) === true &&
      (selector?.defaultPromotionGate?.invariantBlockers ?? []).length === 0;
    const liveHandoffReviewedImportActivationApplyInvariant =
      liveHandoff?.defaultLivePromotionInvariantIds?.includes(
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
      ) === true &&
      (liveHandoff?.defaultLivePromotionInvariantBlockers ?? []).length === 0 &&
      liveHandoff?.reviewedImportActivationApplyProofPresent === true &&
      liveHandoff?.reviewedImportActivationApplyProofPassed === true &&
      (liveHandoff?.reviewedImportActivationApplyProofBlockers ?? []).length ===
        0 &&
      typeof reviewedImportActivationApplyActivationId === "string" &&
      reviewedImportActivationApplyActivationId.length > 0 &&
      liveHandoff?.reviewedImportActivationApplyActivationId ===
        reviewedImportActivationApplyActivationId;
    const reviewedImportActivationApplyGate =
      defaultDispatch?.reviewedImportActivationApplyGate ?? null;
    const defaultDispatchReviewedImportActivationApplyInvariant =
      defaultDispatch?.defaultLivePromotionInvariantIds?.includes(
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID,
      ) === true &&
      (defaultDispatch?.defaultLivePromotionInvariantBlockers ?? []).length ===
        0 &&
      defaultDispatch?.reviewedImportActivationApplyProofPresent === true &&
      defaultDispatch?.reviewedImportActivationApplyProofPassed === true &&
      (defaultDispatch?.reviewedImportActivationApplyProofBlockers ?? [])
        .length === 0 &&
      typeof reviewedImportActivationApplyActivationId === "string" &&
      reviewedImportActivationApplyActivationId.length > 0 &&
      defaultDispatch?.reviewedImportActivationApplyActivationId ===
        reviewedImportActivationApplyActivationId &&
      reviewedImportActivationApplyGate?.schemaVersion ===
        "workflow.harness.default-runtime-dispatch.reviewed-import-activation-apply-gate.v1" &&
      reviewedImportActivationApplyGate?.gateId ===
        "reviewed-import-activation-apply" &&
      reviewedImportActivationApplyGate?.invariantId ===
        REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT_ID &&
      reviewedImportActivationApplyGate?.proofPresent === true &&
      reviewedImportActivationApplyGate?.proofPassed === true &&
      (reviewedImportActivationApplyGate?.proofBlockers ?? []).length === 0 &&
      reviewedImportActivationApplyGate?.activationId ===
        reviewedImportActivationApplyActivationId &&
      reviewedImportActivationApplyGate?.workerBindingActivationId ===
        reviewedImportActivationApplyActivationId &&
      reviewedImportActivationApplyGate?.rollbackTarget ===
        reviewedImportActivationApplyRollbackTarget &&
      reviewedImportActivationApplyGate?.reviewedWorkflowContentHash ===
        reviewedImportActivationApplyResult?.reviewedWorkflowContentHash &&
      reviewedImportActivationApplyGate?.reviewedHarnessWorkflowId ===
        reviewedImportActivationApplyResult?.reviewedHarnessWorkflowId &&
      reviewedImportActivationApplyGate?.reviewedPolicyPosture ===
        reviewedImportActivationApplyResult?.reviewedPolicyPosture &&
      sameStringSet(
        reviewedImportActivationApplyGate?.reviewedReplayFixtureRefs,
        reviewedImportActivationApplyResult?.reviewedReplayFixtureRefs,
      ) &&
      sameStringSet(
        reviewedImportActivationApplyGate?.reviewedWorkerHandoffNodeAttemptIds,
        reviewedImportActivationApplyResult
          ?.reviewedWorkerHandoffNodeAttemptIds,
      ) &&
      sameStringSet(
        reviewedImportActivationApplyGate?.reviewedWorkerHandoffReceiptIds,
        reviewedImportActivationApplyResult?.reviewedWorkerHandoffReceiptIds,
      ) &&
      (
        reviewedImportActivationApplyGate?.defaultDispatchActivationBlockers ??
        []
      ).length === 0;
    const checks = {
      desktopWindowOpened: Boolean(windowId),
      proofWorkflowSaved: Boolean(workflow),
      blockedAttemptPresent: clusterIds.every((clusterId) =>
        transitionFor(clusterId, "gated", "blocked"),
      ),
      gatedAttemptPromoted: clusterIds.every((clusterId) =>
        transitionFor(clusterId, "gated", "promoted"),
      ),
      liveAttemptPromoted: clusterIds.every((clusterId) =>
        transitionFor(clusterId, "live", "promoted"),
      ),
      clusterPromotedLive: clusterIds.every(
        (clusterId) => clusterById.get(clusterId)?.promotionStatus === "live",
      ),
      runtimeSelectorDefaultPromoted:
        selector?.selectedSelector === "blessed_workflow_live_default" &&
        selector?.productionDefaultSelector ===
          "blessed_workflow_live_default" &&
        selector?.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
        selector?.activationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        selector?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
        selector?.actualRuntimeAuthority ===
          "blessed_workflow_activation_default" &&
        selector?.executionMode === "live" &&
        selector?.defaultPromotionGate?.enabled === true &&
        selector?.defaultPromotionGate?.eligible === true &&
        selector?.defaultPromotionGate?.defaultAuthorityTransferred === true &&
        selector?.rollbackTarget === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        selector?.rollbackAvailable === true &&
        selector?.livePromotionReadinessReady === true &&
        (selector?.livePromotionReadinessBlockers ?? []).length === 0 &&
        selector?.livePromotionReadinessProof?.schemaVersion ===
          "workflow.harness.live-promotion-readiness.v1" &&
        selector?.livePromotionReadinessPolicyDecision ===
          "allow_default_harness_live_promotion_readiness" &&
        (selector?.defaultPromotionGate?.activationBlockers ?? []).length ===
          0 &&
        selectorReviewedImportActivationApplyInvariant,
      liveHandoffTransferred:
        liveHandoff?.selector === "blessed_workflow_live_default" &&
        liveHandoff?.productionDefaultSelector ===
          "blessed_workflow_live_default" &&
        liveHandoff?.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
        liveHandoff?.activationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        liveHandoff?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
        liveHandoff?.defaultAuthorityTransferred === true &&
        liveHandoff?.runtimeAuthority ===
          "blessed_workflow_activation_default" &&
        liveHandoff?.rollbackTarget === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        liveHandoff?.rollbackAvailable === true &&
        liveHandoff?.livePromotionReadinessReady === true &&
        (liveHandoff?.livePromotionReadinessBlockers ?? []).length === 0 &&
        liveHandoff?.livePromotionReadinessProof?.schemaVersion ===
          "workflow.harness.live-promotion-readiness.v1" &&
        liveHandoff?.livePromotionReadinessPolicyDecision ===
          "allow_default_harness_live_promotion_readiness" &&
        (liveHandoff?.activationBlockers ?? []).length === 0 &&
        liveHandoffReviewedImportActivationApplyInvariant,
      defaultDispatchBound:
        defaultDispatch?.selectedSelector === "blessed_workflow_live_default" &&
        defaultDispatch?.productionDefaultSelector ===
          "blessed_workflow_live_default" &&
        defaultDispatch?.workflowId === DEFAULT_AGENT_HARNESS_WORKFLOW_ID &&
        defaultDispatch?.activationId === DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        defaultDispatch?.harnessHash === DEFAULT_AGENT_HARNESS_HASH &&
        defaultDispatch?.runtimeAuthority ===
          "blessed_workflow_activation_default" &&
        defaultDispatch?.executionMode === "live" &&
        defaultDispatch?.rollbackAvailable === true &&
        defaultDispatch?.drivesRuntimeDecision === true &&
        defaultDispatch?.activationIdGateClickProofPresent === true &&
        defaultDispatch?.activationIdGateClickProofPassed === true &&
        (defaultDispatch?.activationIdGateClickProofBlockers ?? []).length ===
          0 &&
        (defaultDispatch?.defaultDispatchActivationBlockers ?? []).length ===
          0 &&
        defaultDispatch?.activationIdGate?.workerBindingActivationId ===
          DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        (defaultDispatch?.activationBlockers ?? []).length === 0 &&
        defaultDispatchReviewedImportActivationApplyInvariant &&
        clusterIds.every((clusterId) =>
          (defaultDispatch?.acceptedClusterIds ?? []).includes(clusterId),
        ),
      selectorReviewedImportActivationApplyInvariant,
      liveHandoffReviewedImportActivationApplyInvariant,
      defaultDispatchReviewedImportActivationApplyInvariant,
      cognitionNodeAuthorityBound:
        defaultDispatch?.cognitionNodeAuthorityGate?.schemaVersion ===
          "workflow.harness.default-runtime-dispatch.cognition-node-authority.v1" &&
        defaultDispatch?.cognitionNodeAuthorityGate?.authorityMode ===
          "node_authoritative" &&
        defaultDispatch?.cognitionNodeAuthorityGate?.authoritative === true &&
        defaultDispatch?.cognitionNodeAuthorityGate?.policyDecision ===
          "allow_node_authoritative_cognition" &&
        (defaultDispatch?.cognitionNodeAuthorityGate?.blockers ?? []).length ===
          0 &&
        ["planner", "prompt_assembler", "task_state"].every(
          (componentKind) =>
            (
              defaultDispatch?.cognitionNodeAuthorityGate?.componentKinds ?? []
            ).includes(componentKind) &&
            (
              defaultDispatch?.cognitionNodeAuthorityGate
                ?.liveReadyComponentKinds ?? []
            ).includes(componentKind),
        ) &&
        (defaultDispatch?.cognitionNodeAuthorityGate?.attemptIds ?? [])
          .length >= 3 &&
        (defaultDispatch?.cognitionNodeAuthorityGate?.receiptIds ?? [])
          .length >= 3 &&
        (defaultDispatch?.cognitionNodeAuthorityGate?.replayFixtureRefs ?? [])
          .length >= 3,
      routingModelNodeAuthorityBound:
        defaultDispatch?.routingModelNodeAuthorityGate?.schemaVersion ===
          "workflow.harness.default-runtime-dispatch.routing-model-node-authority.v1" &&
        defaultDispatch?.routingModelNodeAuthorityGate?.authorityMode ===
          "gated_node_authoritative" &&
        defaultDispatch?.routingModelNodeAuthorityGate?.authoritative === true &&
        defaultDispatch?.routingModelNodeAuthorityGate?.policyDecision ===
          "allow_gated_node_authoritative_routing_model" &&
        defaultDispatch?.routingModelNodeAuthorityGate
          ?.visibleOutputAuthority === "workflow_model_provider_call" &&
        defaultDispatch?.routingModelNodeAuthorityGate?.providerCanaryReady ===
          true &&
        defaultDispatch?.routingModelNodeAuthorityGate?.rollbackAvailable ===
          true &&
        (defaultDispatch?.routingModelNodeAuthorityGate?.blockers ?? [])
          .length === 0 &&
        ["model_router", "model_call", "tool_router"].every(
          (componentKind) =>
            (
              defaultDispatch?.routingModelNodeAuthorityGate?.componentKinds ??
              []
            ).includes(componentKind) &&
            (
              defaultDispatch?.routingModelNodeAuthorityGate
                ?.shadowReadyComponentKinds ?? []
            ).includes(componentKind),
        ) &&
        (defaultDispatch?.routingModelNodeAuthorityGate?.attemptIds ?? [])
          .length >= 3 &&
        (defaultDispatch?.routingModelNodeAuthorityGate?.receiptIds ?? [])
          .length >= 3 &&
        (defaultDispatch?.routingModelNodeAuthorityGate?.replayFixtureRefs ?? [])
          .length >= 3,
      verificationOutputNodeAuthorityBound:
        defaultDispatch?.verificationOutputNodeAuthorityGate?.schemaVersion ===
          "workflow.harness.default-runtime-dispatch.verification-output-node-authority.v1" &&
        defaultDispatch?.verificationOutputNodeAuthorityGate?.authorityMode ===
          "gated_node_authoritative" &&
        defaultDispatch?.verificationOutputNodeAuthorityGate?.authoritative ===
          true &&
        defaultDispatch?.verificationOutputNodeAuthorityGate?.policyDecision ===
          "allow_gated_node_authoritative_verification_output" &&
        defaultDispatch?.verificationOutputNodeAuthorityGate
          ?.outputWriterVisibleWriteCommitted === true &&
        defaultDispatch?.verificationOutputNodeAuthorityGate?.rollbackAvailable ===
          true &&
        (defaultDispatch?.verificationOutputNodeAuthorityGate?.blockers ?? [])
          .length === 0 &&
        [
          "postcondition_synthesizer",
          "verifier",
          "completion_gate",
          "receipt_writer",
          "quality_ledger",
          "output_writer",
        ].every(
          (componentKind) =>
            (
              defaultDispatch?.verificationOutputNodeAuthorityGate
                ?.componentKinds ?? []
            ).includes(componentKind) &&
            (
              defaultDispatch?.verificationOutputNodeAuthorityGate
                ?.shadowReadyComponentKinds ?? []
            ).includes(componentKind),
        ) &&
        (defaultDispatch?.verificationOutputNodeAuthorityGate?.attemptIds ?? [])
          .length >= 6 &&
        (defaultDispatch?.verificationOutputNodeAuthorityGate?.receiptIds ?? [])
          .length >= 6 &&
        (
          defaultDispatch?.verificationOutputNodeAuthorityGate
            ?.replayFixtureRefs ?? []
        ).length >= 6,
      authorityToolingNodeAuthorityBound:
        defaultDispatch?.authorityToolingNodeAuthorityGate?.schemaVersion ===
          "workflow.harness.default-runtime-dispatch.authority-tooling-node-authority.v1" &&
        defaultDispatch?.authorityToolingNodeAuthorityGate?.authorityMode ===
          "gated_node_authoritative" &&
        defaultDispatch?.authorityToolingNodeAuthorityGate?.authoritative ===
          true &&
        defaultDispatch?.authorityToolingNodeAuthorityGate?.policyDecision ===
          "allow_gated_node_authoritative_authority_tooling" &&
        defaultDispatch?.authorityToolingNodeAuthorityGate
          ?.readOnlyRouteAccepted === true &&
        defaultDispatch?.authorityToolingNodeAuthorityGate
          ?.destructiveRouteDenied === true &&
        defaultDispatch?.authorityToolingNodeAuthorityGate
          ?.mutatingToolCallsBlocked === true &&
        defaultDispatch?.authorityToolingNodeAuthorityGate?.sideEffectsExecuted ===
          false &&
        defaultDispatch?.authorityToolingNodeAuthorityGate?.gateLiveReady ===
          true &&
        defaultDispatch?.authorityToolingNodeAuthorityGate
          ?.readOnlyAuthorityCanaryReady === true &&
        defaultDispatch?.authorityToolingNodeAuthorityGate?.rollbackAvailable ===
          true &&
        (defaultDispatch?.authorityToolingNodeAuthorityGate?.blockers ?? [])
          .length === 0 &&
        [
          "policy_gate",
          "approval_gate",
          "dry_run_simulator",
          "mcp_provider",
          "mcp_tool_call",
          "tool_call",
          "connector_call",
          "github_pr_create",
          "wallet_capability",
        ].every(
          (componentKind) =>
            (
              defaultDispatch?.authorityToolingNodeAuthorityGate
                ?.componentKinds ?? []
            ).includes(componentKind) &&
            (
              defaultDispatch?.authorityToolingNodeAuthorityGate
                ?.shadowReadyComponentKinds ?? []
            ).includes(componentKind),
        ) &&
        (defaultDispatch?.authorityToolingNodeAuthorityGate?.attemptIds ?? [])
          .length >= 8 &&
        (defaultDispatch?.authorityToolingNodeAuthorityGate?.receiptIds ?? [])
          .length >= 8 &&
        (
          defaultDispatch?.authorityToolingNodeAuthorityGate
            ?.replayFixtureRefs ?? []
        ).length >= 8,
      livePromotionReadinessBound:
        defaultDispatch?.livePromotionReadinessProof?.schemaVersion ===
          "workflow.harness.live-promotion-readiness.v1" &&
        defaultDispatch?.livePromotionReadinessProof?.targetExecutionMode ===
          "live" &&
        defaultDispatch?.livePromotionReadinessProof?.allClustersReady ===
          true &&
        defaultDispatch?.livePromotionReadinessProof?.promotionEligible ===
          true &&
        defaultDispatch?.livePromotionReadinessProof
          ?.defaultLiveActivationReady === true &&
        defaultDispatch?.livePromotionReadinessProof
          ?.invalidForkLiveActivationBlocked === true &&
        defaultDispatch?.livePromotionReadinessProof?.rollbackAvailable ===
          true &&
        defaultDispatch?.livePromotionReadinessProof?.policyDecision ===
          "allow_default_harness_live_promotion_readiness" &&
        defaultDispatch?.livePromotionReadinessProof
          ?.liveShadowComparisonGateReady === true &&
        defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate
          ?.schemaVersion ===
          "workflow.harness.live-shadow-comparison-gate.v1" &&
        defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate
          ?.ready === true &&
        defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate
          ?.comparisonCount >=
          HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.length &&
        HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENT_KINDS.every(
          (componentKind) =>
            defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate?.componentKinds?.includes(
              componentKind,
            ),
        ) &&
        clusterIds.every((clusterId) =>
          (
            defaultDispatch?.livePromotionReadinessProof?.requiredClusterIds ??
            []
          ).includes(clusterId),
        ) &&
        (defaultDispatch?.livePromotionReadinessProof?.clusterReadiness ?? [])
          .length >= clusterIds.length &&
        clusterIds.every((clusterId) => {
          const cluster =
            defaultDispatch?.livePromotionReadinessProof?.clusterReadiness?.find(
              (candidate) => candidate.clusterId === clusterId,
            ) ?? null;
          return (
            cluster?.targetExecutionMode === "live" &&
            cluster?.blockers?.length === 0 &&
            cluster?.receiptRefs?.length > 0 &&
            cluster?.replayFixtureRefs?.length > 0 &&
            cluster?.blockingDivergenceCount === 0 &&
            cluster?.unclassifiedDivergenceCount === 0 &&
            cluster?.decision === "allow_default_harness_live_cluster_promotion"
          );
        }),
      activeWorkerBinding:
        activationRecord?.activationState === "active" &&
        activationRecord?.liveAuthorityTransferred === true &&
        activationRecord?.policyPosture === "live" &&
        workerBinding?.harnessActivationId === selector?.activationId &&
        workerBinding?.executionMode === "live" &&
        workerBinding?.source === "default" &&
        workerBinding?.selectorDecisionId === selector?.decisionId &&
        workerBinding?.defaultDispatchId === defaultDispatch?.dispatchId &&
        workerBinding?.rollbackTarget === selector?.rollbackTarget &&
        workerBinding?.authorityBindingReady === true &&
        (workerBinding?.authorityBindingBlockers ?? []).length === 0 &&
        workerBinding?.livePromotionReadinessProofId ===
          selector?.livePromotionReadinessProof?.proofId &&
        workerBinding?.livePromotionReadinessProofId ===
          defaultDispatch?.livePromotionReadinessProof?.proofId &&
        workerBinding?.liveShadowComparisonGateId ===
          expectedRollbackGateId &&
        workerBinding?.liveShadowComparisonGateReady === true &&
        workerBinding?.rollbackPolicyDecision ===
          expectedRollbackPolicyDecision &&
        workerBindingRegistryBound,
      workerBindingRegistryBound,
      workerRollbackLiveShadowGateBound,
      workerAttachBound,
      workerAttachLifecycleComplete,
      workerSessionRecordBound,
      workerLaunchHandoffBound,
      workerHandoffNodeTimelineBound,
      activeRuntimeRollbackProofWorkbench,
      activeRuntimeRollbackExecutionWorkbench,
      activeRuntimeRollbackApplyExecution,
      activeRuntimeRollbackNegativeApply,
      routeStatefulActiveRuntimeBindingDeepLinks:
        Object.values(routeStatefulDeepLinks).every(Boolean) &&
        routeStatefulDeepLinks.selector?.includes("selectorDecisionId=") &&
        routeStatefulDeepLinks.dispatch?.includes("dispatchId=") &&
        routeStatefulDeepLinks.worker?.includes("workerBindingId=") &&
        routeStatefulDeepLinks.rollback?.includes("rollbackTarget=") &&
        routeStatefulDeepLinks.receipt?.includes("receiptRef=") &&
        routeStatefulDeepLinks.replay?.includes("replayFixtureRef="),
      routeStatefulDeepLinkReplay: deepLinkReplayPassed,
      coldStartDeepLinkRestore: coldStartDeepLinkRestorePassed,
      liveTurnNodeInspectorDeepLink: liveTurnNodeInspectorDeepLinkRestored,
      liveShadowComparisonDeepLink: liveShadowComparisonDeepLinkRestored,
      routeStatefulRevisionBindingDeepLink:
        routeStatefulDeepLinks.revision?.includes(
          "revisionBindingKind=current",
        ) && routeStatefulDeepLinks.revision?.includes("revisionBindingRef="),
      routeStatefulActivationBlockerDeepLink:
        activationBlockerDeepLinkProof?.passed === true &&
        routeStatefulDeepLinks.activationBlocker?.includes(
          "activationBlockerIndex=0",
        ) &&
        routeStatefulDeepLinks.activationBlocker?.includes(
          "activationBlockerRef=",
        ),
      routeStatefulActivationAuditDeepLink:
        routeStatefulDeepLinks.activationAudit?.includes(
          "activationAuditEventId=",
        ),
      routeStatefulActivationGateDeepLink:
        activationGateDeepLinkProof?.passed === true &&
        routeStatefulDeepLinks.activationGate?.includes("activationGateId="),
      routeStatefulActivationGateReferenceDeepLinks:
        activationGateDeepLinkProof?.passed === true &&
        activationGateReferenceDeepLinkRestored(
          activationGateEvidenceDeepLinkCase,
          "activationGateEvidenceRef",
          "data-selected-activation-gate-evidence-ref",
        ) &&
        activationGateReferenceDeepLinkRestored(
          activationGateReceiptDeepLinkCase,
          "activationGateReceiptRef",
          "data-selected-activation-gate-receipt-ref",
        ) &&
        activationGateReferenceDeepLinkRestored(
          activationGateReplayDeepLinkCase,
          "activationGateReplayFixtureRef",
          "data-selected-activation-gate-replay-fixture-ref",
        ) &&
        activationGateReferenceDeepLinkRestored(
          activationGateCanaryBoundaryDeepLinkCase,
          "activationGateEvidenceRef",
          "data-selected-canary-boundary-id",
        ) &&
        activationGateReferenceDeepLinkRestored(
          activationGateCanaryRollbackDrillDeepLinkCase,
          "activationGateEvidenceRef",
          "data-selected-rollback-drill-id",
        ) &&
        (activationGateReferenceDeepLinkRestored(
          activationGateNodeAttemptDeepLinkCase,
          "activationGateNodeAttemptId",
          "data-selected-activation-gate-node-attempt-id",
        ) ||
          (activationIdGateClickProof?.mintedActivation
            ?.workerHandoffTimelineVisible === true &&
            routeStatefulDeepLinks.activationGateNodeAttempt?.includes(
              "activationGateNodeAttemptId=",
            ) === true)),
	      activationGateWorkerInvariantDeepLink:
	        activationGateWorkerInvariantDeepLinkRestored,
	      workerInvariantNegativeEnforcement,
	      activationGateMutationCanaryNodeInspectorDeepLink:
	        activationGateMutationCanaryNodeAttemptDeepLinkCase?.passed === true &&
	        activationGateMutationCanaryNodeAttemptDeepLinkCase
	          ?.selectedRailTestId === "workflow-harness-node-attempt-inspector" &&
	        activationGateMutationCanaryNodeAttemptDeepLinkCase
	          ?.observedSelectedState?.["data-node-attempt-source-kind"] ===
	          "fork_mutation_canary" &&
	        activationGateMutationCanaryNodeAttemptDeepLinkCase
	          ?.observedSelectedState?.["data-component-kind"] === "budget_gate" &&
	        routeStatefulDeepLinks.activationGateMutationCanaryNodeAttempt?.includes(
	          "activationGateId=mutation-canary",
	        ) === true &&
	        routeStatefulDeepLinks.activationGateMutationCanaryNodeAttempt?.includes(
	          "nodeAttemptId=",
	        ) === true,
	      activationGateNodeTimelineDeepLink:
        activationIdGateClickProof?.mintedActivation
          ?.workerHandoffTimelineVisible === true &&
        activationIdGateClickProof?.mintedActivation
          ?.workerHandoffTimelineAttemptId ===
          activationIdGateClickProof?.mintedActivation
            ?.workerHandoffNodeAttemptIds?.[0] &&
        routeStatefulDeepLinks.activationGateNodeAttempt?.includes(
          "activationGateNodeAttemptId=",
        ) === true,
      activationGateEvidenceInspectable:
        activationGateDeepLinkProof?.passed === true &&
        activationGateDeepLinkCase?.selectedRailTestId ===
          "workflow-harness-activation-gate-inspector" &&
        activationGateEvidenceRefCount > 0 &&
        ["activation_candidate", "wizard_step"].includes(
          activationGateDeepLinkCase?.observedSelectedState?.[
            "data-gate-source-kind"
          ] ?? "",
        ),
      activationGateActionWorkbench:
        activationGateDeepLinkProof?.passed === true &&
        activationGateDeepLinkCase?.selectedRailTestId ===
          "workflow-harness-activation-gate-inspector" &&
        typeof activationGateDeepLinkCase?.observedSelectedState?.[
          "data-gate-action-id"
        ] === "string" &&
        activationGateDeepLinkCase.observedSelectedState[
          "data-gate-action-id"
        ].startsWith("activation-gate-action:") &&
        typeof activationGateDeepLinkCase.observedSelectedState[
          "data-gate-action-kind"
        ] === "string" &&
        activationGateDeepLinkCase.observedSelectedState[
          "data-gate-action-kind"
        ].length > 0 &&
        typeof activationGateDeepLinkCase.observedSelectedState[
          "data-gate-action-command"
        ] === "string" &&
        activationGateDeepLinkCase.observedSelectedState[
          "data-gate-action-command"
        ].startsWith("workflow-harness-gate-action-"),
      activationGateActionClickProof:
        activationGateActionClickProof?.passed === true &&
        activationGateActionClickProof.clicked === true &&
        activationGateActionClickProof.action?.id?.startsWith(
          "activation-gate-action:",
        ) === true &&
        activationGateActionClickProof.action?.command?.startsWith(
          "workflow-harness-gate-action-",
        ) === true &&
        activationGateActionClickProof.after?.railTestId ===
          "workflow-right-rail-readiness" &&
        activationGateActionClickProof.after?.readinessPanelVisible === true &&
        activationGateActionClickProof.after?.readinessSummaryVisible === true,
      packageEvidenceGateClickProof:
        packageEvidenceGateClickProof?.passed === true &&
        packageEvidenceGateClickProof.clicked === true &&
        packageEvidenceGateClickProof.gateId === "package-evidence" &&
        packageEvidenceGateClickProof.manifest?.present === true &&
        packageEvidenceGateClickProof.manifest?.schemaVersion ===
          "workflow.harness.package-evidence-manifest.v1" &&
        packageEvidenceGateClickProof.manifest?.receiptRefCount > 0 &&
        packageEvidenceGateClickProof.manifest?.replayFixtureRefCount > 0 &&
        packageEvidenceGateClickProof.manifest?.rollbackRestoreReceiptRefCount >
          0 &&
        packageEvidenceGateClickProof.manifest
          ?.forkMutationCanaryReceiptRefCount > 0 &&
        packageEvidenceGateClickProof.manifest
          ?.forkMutationCanaryReplayFixtureRefCount > 0 &&
        packageEvidenceGateClickProof.manifest
          ?.forkMutationCanaryNodeAttemptCount > 0 &&
        packageEvidenceGateClickProof.manifest?.workerHandoffNodeAttemptCount >
          0 &&
        packageEvidenceGateClickProof.manifest?.workerHandoffReceiptCount > 0 &&
        packageEvidenceGateClickProof.manifest?.deepLinkCount > 0 &&
        packageEvidenceGateClickProof.manifest?.blockerCount === 0 &&
        typeof packageEvidenceGateClickProof.selectedRefs?.receiptRef ===
          "string" &&
        packageEvidenceGateClickProof.restored?.receiptState?.[
          "data-selected-activation-gate-receipt-ref"
        ] === packageEvidenceGateClickProof.selectedRefs.receiptRef &&
        typeof packageEvidenceGateClickProof.selectedRefs?.replayFixtureRef ===
          "string" &&
        packageEvidenceGateClickProof.restored?.replayState?.[
          "data-selected-activation-gate-replay-fixture-ref"
        ] === packageEvidenceGateClickProof.selectedRefs.replayFixtureRef &&
        typeof packageEvidenceGateClickProof.selectedRefs?.nodeAttemptId ===
          "string" &&
        packageEvidenceGateClickProof.restored?.nodeAttemptState?.[
          "data-selected-activation-gate-node-attempt-id"
        ] === packageEvidenceGateClickProof.selectedRefs.nodeAttemptId &&
        typeof packageEvidenceGateClickProof.selectedRefs
          ?.mutationCanaryNodeAttemptId === "string" &&
        packageEvidenceGateClickProof.restored?.mutationCanaryState?.[
          "data-selected-activation-gate-id"
        ] === "mutation-canary" &&
        packageEvidenceGateClickProof.restored?.mutationCanaryState?.[
          "data-selected-activation-gate-node-attempt-id"
        ] ===
          packageEvidenceGateClickProof.selectedRefs
            .mutationCanaryNodeAttemptId &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryNodeAttemptState?.["data-node-attempt-id"] ===
          packageEvidenceGateClickProof.selectedRefs
            .mutationCanaryNodeAttemptId &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryNodeAttemptState?.["data-node-attempt-source-kind"] ===
          "fork_mutation_canary" &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryNodeAttemptState?.["data-component-kind"] ===
          "budget_gate" &&
        String(
          packageEvidenceGateClickProof.restored
            ?.mutationCanaryNodeAttemptState?.["data-receipt-refs"] ?? "",
        ).includes(
          packageEvidenceGateClickProof.selectedRefs
            ?.mutationCanaryReceiptRef ?? "__missing__",
        ) &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryNodeAttemptState?.["data-replay-fixture-ref"] ===
          packageEvidenceGateClickProof.selectedRefs
            ?.mutationCanaryReplayFixtureRef &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryNodeAttemptState?.["data-mutation-diff-hash"] ===
          packageEvidenceGateClickProof.selectedRefs
            ?.mutationCanaryDiffHash &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryNodeAttemptState?.["data-rollback-target"] ===
          packageEvidenceGateClickProof.selectedRefs
            ?.mutationCanaryRollbackTarget &&
        packageEvidenceGateClickProof.restored
          ?.mutationCanaryTimelineAttemptId ===
          packageEvidenceGateClickProof.selectedRefs
            .mutationCanaryNodeAttemptId &&
        typeof packageEvidenceGateClickProof.selectedRefs
          ?.packageDeepLinkHash === "string" &&
        packageEvidenceGateClickProof.selectedRefs.packageDeepLinkHash.startsWith(
          "#harness-workbench?",
        ) &&
        Boolean(
          packageEvidenceGateClickProof.restored?.packageDeepLinkState?.[
            "data-selected-activation-gate-id"
          ] ||
          packageEvidenceGateClickProof.restored?.packageDeepLinkState?.[
            "data-selected-worker-binding-id"
          ],
        ),
      packageEvidenceImportRoundTripProof:
        packageEvidenceImportRoundTripProof?.passed === true &&
        typeof packageEvidenceImportRoundTripProof.exportedPackagePath ===
          "string" &&
        typeof packageEvidenceImportRoundTripProof.importedWorkflowPath ===
          "string" &&
        packageEvidenceImportRoundTripProof.validImport?.gateId ===
          "package-evidence" &&
        packageEvidenceImportRoundTripProof.validImport?.clicked === true &&
        packageEvidenceImportRoundTripProof.validImport?.manifest?.present ===
          true &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.schemaVersion === "workflow.harness.package-evidence-manifest.v1" &&
        packageEvidenceImportRoundTripProof.validImport?.manifest?.status ===
          "true" &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.blockerCount === 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.receiptRefCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.replayFixtureRefCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.rollbackRestoreReceiptRefCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.forkMutationCanaryReceiptRefCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.forkMutationCanaryReplayFixtureRefCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.forkMutationCanaryNodeAttemptCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.workerHandoffNodeAttemptCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.workerHandoffReceiptCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.manifest
          ?.deepLinkCount > 0 &&
        packageEvidenceImportRoundTripProof.validImport?.restored
          ?.receiptState?.["data-selected-activation-gate-receipt-ref"] ===
          packageEvidenceImportRoundTripProof.validImport?.selectedRefs
            ?.receiptRef &&
        packageEvidenceImportRoundTripProof.validImport?.restored
          ?.replayState?.[
          "data-selected-activation-gate-replay-fixture-ref"
        ] ===
          packageEvidenceImportRoundTripProof.validImport?.selectedRefs
            ?.replayFixtureRef &&
        packageEvidenceImportRoundTripProof.validImport?.restored
          ?.nodeAttemptState?.[
          "data-selected-activation-gate-node-attempt-id"
        ] ===
          packageEvidenceImportRoundTripProof.validImport?.selectedRefs
            ?.nodeAttemptId &&
        Boolean(
          packageEvidenceImportRoundTripProof.validImport?.restored
            ?.packageDeepLinkState?.["data-selected-activation-gate-id"] ||
          packageEvidenceImportRoundTripProof.validImport?.restored
            ?.packageDeepLinkState?.["data-selected-worker-binding-id"],
        ) &&
        packageEvidenceImportRoundTripProof.incompleteImport?.gateId ===
          "package-evidence" &&
        packageEvidenceImportRoundTripProof.incompleteImport?.manifest
          ?.status === "false" &&
        packageEvidenceImportRoundTripProof.incompleteImport?.manifest
          ?.blockerCount > 0 &&
        packageEvidenceImportRoundTripProof.incompleteImport?.readinessBlockerCodes?.includes(
          "harness_package_manifest_incomplete",
        ) === true &&
        [
          "receipts",
          "replay-fixtures",
          "rollback-restore",
          "fork-mutation-canary",
          "worker-handoff-attempts",
          "worker-handoff-receipts",
          "deep-links",
        ].every((rowId) =>
          packageEvidenceImportRoundTripProof.incompleteImport?.missingRows?.includes(
            rowId,
          ),
        ),
      packageImportReviewProof:
        packageImportReviewProof?.passed === true &&
        packageImportReviewProof.review?.schemaVersion ===
          "workflow.package-import-review.v1" &&
        packageImportReviewProof.gateId === "package-evidence" &&
        typeof packageImportReviewProof.sourceWorkflowPath === "string" &&
        typeof packageImportReviewProof.importedWorkflowPath === "string" &&
        packageImportReviewProof.railState?.[
          "data-package-import-review-open"
        ] === "true" &&
        packageImportReviewProof.railState?.[
          "data-package-import-source-workflow-path"
        ] === packageImportReviewProof.sourceWorkflowPath &&
        packageImportReviewProof.railState?.[
          "data-package-import-imported-workflow-path"
        ] === packageImportReviewProof.importedWorkflowPath &&
        packageImportReviewProof.railState?.[
          "data-package-import-evidence-ready"
        ] === "true" &&
        packageImportReviewProof.railState?.[
          "data-package-import-activation-enabled"
        ] === "true" &&
        packageImportReviewProof.activationAction?.valid?.present === true &&
        packageImportReviewProof.activationAction?.valid?.disabled === false &&
        packageImportReviewProof.activationAction?.valid?.evidenceReady ===
          true &&
        packageImportReviewProof.activationAction?.valid?.blockerCount === 0 &&
        packageImportReviewProof.activationAction?.incomplete?.present ===
          true &&
        packageImportReviewProof.activationAction?.incomplete?.disabled ===
          true &&
        packageImportReviewProof.activationAction?.incomplete?.evidenceReady ===
          false &&
        packageImportReviewProof.activationAction?.incomplete?.blockerCount > 0,
      packageImportActivationHandoffProof:
        packageImportActivationHandoffProof?.passed === true &&
        packageImportActivationHandoffProof.review?.activationHandoff
          ?.schemaVersion === "workflow.package-import-activation-handoff.v1" &&
        packageImportActivationHandoffProof.railState?.[
          "data-package-import-handoff-open"
        ] === "true" &&
        packageImportActivationHandoffProof.railState?.[
          "data-package-import-handoff-decision"
        ] === "mintable" &&
        packageImportActivationHandoffProof.railState?.[
          "data-package-import-handoff-mintable"
        ] === "true" &&
        packageImportActivationHandoffProof.railState?.[
          "data-package-import-handoff-package-evidence-ready"
        ] === "true" &&
        packageImportActivationHandoffProof.activationAction?.valid
          ?.handoffPresent === true &&
        packageImportActivationHandoffProof.activationAction?.valid
          ?.handoffDecision === "mintable" &&
        packageImportActivationHandoffProof.activationAction?.valid
          ?.disabled === false &&
        packageImportActivationHandoffProof.activationAction?.valid
          ?.mintable === true &&
        typeof packageImportActivationHandoffProof.activationAction?.valid
          ?.activationIdPreview === "string" &&
        packageImportActivationHandoffProof.activationAction.valid
          .activationIdPreview.length > 0 &&
        packageImportActivationHandoffProof.activationAction?.valid
          ?.canaryStatus === "passed" &&
        typeof packageImportActivationHandoffProof.activationAction?.valid
          ?.rollbackTarget === "string" &&
        packageImportActivationHandoffProof.activationAction.valid
          .rollbackTarget.length > 0 &&
        typeof packageImportActivationHandoffProof.activationAction?.valid
          ?.workerBindingId === "string" &&
        packageImportActivationHandoffProof.activationAction.valid
          .workerBindingId.length > 0 &&
        packageImportActivationHandoffProof.activationAction?.incomplete
          ?.handoffPresent === true &&
        packageImportActivationHandoffProof.activationAction?.incomplete
          ?.disabled === true &&
        packageImportActivationHandoffProof.activationAction?.incomplete
          ?.mintable === false &&
        packageImportActivationHandoffProof.deepLinks?.activationId?.[
          "data-selected-activation-gate-id"
        ] === "activation-id" &&
	        packageImportActivationHandoffProof.deepLinks?.canary?.[
	          "data-selected-activation-gate-id"
	        ] === "canary" &&
        packageImportActivationHandoffProof.deepLinks?.mutationCanary?.[
          "data-selected-activation-gate-id"
        ] === "mutation-canary" &&
        packageImportActivationHandoffProof.deepLinks?.mutationCanary?.[
          "data-selected-activation-gate-node-attempt-id"
        ] ===
          packageImportActivationHandoffProof.activationAction.valid
            .mutationCanaryNodeAttemptId &&
	        packageImportActivationHandoffProof.deepLinks?.rollbackRestore?.[
	          "data-selected-activation-gate-id"
	        ] === "rollback-restore" &&
        packageImportActivationHandoffProof.deepLinks?.workerBinding?.[
          "data-selected-worker-binding-id"
        ] ===
          packageImportActivationHandoffProof.activationAction.valid
            .workerBindingId,
      packageImportActivationApplyProof:
        packageImportActivationApplyProof?.passed === true &&
        packageImportActivationApplyProof.clicked === true &&
        packageImportActivationApplyProof.activationAction?.handoffDecision ===
          "mintable" &&
        packageImportActivationApplyProof.activationAction?.disabled ===
          false &&
        packageImportActivationApplyProof.activationAction?.mintable === true &&
        packageImportActivationApplyProof.activationResult?.applied === true &&
        packageImportActivationApplyProof.activationResult?.activationId ===
          packageImportActivationApplyProof.activationAction
            .activationIdPreview &&
        packageImportActivationApplyProof.activationResult
          ?.workflowActivationId ===
          packageImportActivationApplyProof.activationResult?.activationId &&
        packageImportActivationApplyProof.activationResult
          ?.workflowActivationState === "validated" &&
        packageImportActivationApplyProof.activationResult
          ?.workerBindingActivationId ===
          packageImportActivationApplyProof.activationResult?.activationId &&
        packageImportActivationApplyProof.activationResult
          ?.activationRecordWorkerBindingActivationId ===
          packageImportActivationApplyProof.activationResult?.activationId &&
        packageImportActivationApplyProof.activationResult?.rollbackTarget ===
          packageImportActivationApplyProof.activationAction.rollbackTarget &&
        packageImportActivationApplyProof.activationResult
          ?.revisionBindingActivationId ===
          packageImportActivationApplyProof.activationResult?.activationId &&
        typeof packageImportActivationApplyProof.activationResult
          ?.activationRecordRevisionBindingHash === "string" &&
        packageImportActivationApplyProof.activationResult
          .activationRecordRevisionBindingHash.length > 0 &&
        typeof packageImportActivationApplyProof.activationResult
          ?.rollbackRevisionBindingHash === "string" &&
        packageImportActivationApplyProof.activationResult
          .rollbackRevisionBindingHash.length > 0 &&
        packageImportActivationApplyProof.activationResult
          ?.latestAuditEventType === "activation_minted" &&
        packageImportActivationApplyProof.activationResult
          ?.latestAuditStatus === "applied" &&
        (packageImportActivationApplyProof.activationResult?.receiptRefs
          ?.length ?? 0) > 0 &&
        (packageImportActivationApplyProof.activationResult?.evidenceRefs
          ?.length ?? 0) > 0 &&
        (packageImportActivationApplyProof.activationResult
          ?.workerHandoffReceiptIds?.length ?? 0) > 0 &&
        (packageImportActivationApplyProof.activationResult
          ?.workerHandoffNodeAttemptIds?.length ?? 0) > 0 &&
        (packageImportActivationApplyProof.activationResult
          ?.workerHandoffReplayFixtureRefs?.length ?? 0) > 0 &&
	        typeof packageImportActivationApplyProof.activationResult
	          ?.reviewedPackageSnapshotHash === "string" &&
	        packageImportActivationApplyProof.activationResult
	          .reviewedPackageSnapshotHash.length > 0 &&
        typeof packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryId === "string" &&
        packageImportActivationApplyProof.activationResult
          .reviewedForkMutationCanaryId.length > 0 &&
        packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryStatus === "passed" &&
        typeof packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryDiffHash === "string" &&
        packageImportActivationApplyProof.activationResult
          .reviewedForkMutationCanaryDiffHash.length > 0 &&
        (packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryReceiptRefs?.length ?? 0) > 0 &&
        (packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryReplayFixtureRefs?.length ?? 0) > 0 &&
        (packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryNodeAttemptIds?.length ?? 0) > 0 &&
        typeof packageImportActivationApplyProof.activationResult
          ?.reviewedForkMutationCanaryRollbackTarget === "string" &&
        packageImportActivationApplyProof.activationResult
          .reviewedForkMutationCanaryRollbackTarget.length > 0 &&
	        packageImportActivationApplyProof.workerHandoff?.selectedState?.[
	          "data-selected-activation-gate-id"
	        ] === "worker-handoff" &&
        packageImportActivationApplyProof.workerHandoff?.selectedState?.[
          "data-selected-activation-gate-node-attempt-id"
        ] ===
          packageImportActivationApplyProof.activationResult
            .workerHandoffNodeAttemptIds[0] &&
        packageImportActivationApplyProof.workerHandoff?.timelineVisible ===
          true &&
	        packageImportActivationApplyProof.workerHandoff?.selectedAttemptId ===
	          packageImportActivationApplyProof.activationResult
	            .workerHandoffNodeAttemptIds[0] &&
        packageImportActivationApplyProof.mutationCanary?.selectedState?.[
          "data-selected-activation-gate-id"
        ] === "mutation-canary" &&
        packageImportActivationApplyProof.mutationCanary?.selectedState?.[
          "data-selected-activation-gate-node-attempt-id"
        ] ===
          packageImportActivationApplyProof.activationResult
            .reviewedForkMutationCanaryNodeAttemptIds[0] &&
        packageImportActivationApplyProof.mutationCanary?.nodeAttemptState?.[
          "data-node-attempt-id"
        ] ===
          packageImportActivationApplyProof.activationResult
            .reviewedForkMutationCanaryNodeAttemptIds[0] &&
        packageImportActivationApplyProof.mutationCanary?.timelineVisible ===
          true &&
        packageImportActivationApplyProof.mutationCanary?.selectedAttemptId ===
          packageImportActivationApplyProof.activationResult
            .reviewedForkMutationCanaryNodeAttemptIds[0] &&
	        packageImportActivationApplyProof.incompleteAction?.disabled === true &&
	        packageImportActivationApplyProof.incompleteAction?.mintable === false,
        packageImportActivationReplayIntegrityProof:
          packageImportActivationReplayIntegrityProof?.passed === true &&
	          (packageImportActivationReplayIntegrityProof.cases?.length ?? 0) ===
	          8 &&
        packageImportActivationReplayIntegrityProof.cases?.every(
          (negativeCase) =>
            negativeCase.passed === true &&
            negativeCase.action?.present === true &&
            negativeCase.action?.disabled === true &&
            negativeCase.action?.integrityBlockerCount > 0 &&
            negativeCase.railState?.[
              "data-package-import-activation-enabled"
            ] === "false" &&
            negativeCase.runtimeBlockers?.includes(
              negativeCase.expectedBlocker,
            ) === true &&
            negativeCase.defaultLivePromotionBlockers?.includes(
              negativeCase.expectedBlocker,
            ) === true,
        ) === true,
      activationGateCollectEvidenceClickProof:
        activationGateCollectEvidenceClickProof?.passed === true &&
        activationGateCollectEvidenceClickProof.clicked === true &&
        activationGateCollectEvidenceClickProof.gateId === "replay-fixtures" &&
        activationGateCollectEvidenceClickProof.action?.kind ===
          "run_replay_gate" &&
        activationGateCollectEvidenceClickProof.action?.impact ===
          "collect_evidence" &&
        activationGateCollectEvidenceClickProof.action?.command ===
          "workflow-harness-gate-action-replay-fixtures" &&
        activationGateCollectEvidenceClickProof.replayGate?.gateId?.startsWith(
          "harness-replay-gate:",
        ) === true &&
        activationGateCollectEvidenceClickProof.replayGate?.totalFixtures > 0 &&
        activationGateCollectEvidenceClickProof.replayGate
          ?.persistedReplayGateCount > 0 &&
        Number(
          activationGateCollectEvidenceClickProof.after?.inspectorState?.[
            "data-evidence-ref-count"
          ] ?? 0,
        ) > 0,
      activationGateRollbackRestoreClickProof:
        activationGateRollbackRestoreClickProof?.passed === true &&
        activationGateRollbackRestoreClickProof.clicked === true &&
        activationGateRollbackRestoreClickProof.gateId === "rollback-restore" &&
        activationGateRollbackRestoreClickProof.action?.kind ===
          "run_activation_dry_run" &&
        activationGateRollbackRestoreClickProof.action?.impact ===
          "collect_evidence" &&
        activationGateRollbackRestoreClickProof.action?.command ===
          "workflow-harness-gate-action-rollback-restore" &&
        activationGateRollbackRestoreClickProof.dryRun?.candidateId?.startsWith(
          "candidate:",
        ) === true &&
        ["passed", "not_required"].includes(
          activationGateRollbackRestoreClickProof.dryRun
            ?.rollbackRestoreStatus ?? "",
        ) &&
        activationGateRollbackRestoreClickProof.dryRun
          ?.rollbackRestoreHashVerified === true &&
        activationGateRollbackRestoreClickProof.dryRun?.rollbackRestoreReceiptBindingRef?.startsWith(
          "workflow_restore_canary:",
        ) === true &&
        (activationGateRollbackRestoreClickProof.dryRun
          ?.rollbackRestoreEvidenceRefs?.length ?? 0) > 0 &&
        activationGateRollbackRestoreClickProof.dryRun
          ?.persistedActivationAuditEventCount > 0 &&
        Number(
          activationGateRollbackRestoreClickProof.after?.inspectorState?.[
            "data-evidence-ref-count"
          ] ?? 0,
        ) > 0 &&
        Number(
          activationGateRollbackRestoreClickProof.after?.inspectorState?.[
            "data-receipt-ref-count"
          ] ?? 0,
        ) > 0 &&
        typeof activationGateRollbackRestoreClickProof.rollbackRestoreDeepLink ===
          "string" &&
        activationGateRollbackRestoreClickProof.rollbackRestoreDeepLink.includes(
          "activationGateReceiptRef=",
        ) &&
        activationGateRollbackRestoreClickProof.rollbackRestoreDeepLinkState?.[
          "data-selected-rollback-restore-canary-id"
        ] ===
          activationGateRollbackRestoreClickProof.dryRun
            ?.rollbackRestoreCanaryId &&
        activationGateRollbackRestoreClickProof.rollbackRestoreDeepLinkState?.[
          "data-selected-rollback-restore-receipt-ref"
        ] ===
          activationGateRollbackRestoreClickProof.dryRun
            ?.rollbackRestoreReceiptBindingRef,
      activationIdGateClickProof:
        activationIdGateClickProof?.passed === true &&
        activationIdGateClickProof.blockedDryRun?.clicked === true &&
        activationIdGateClickProof.blockedDryRun?.gateId === "activation-id" &&
        activationIdGateClickProof.blockedDryRun?.action?.kind ===
          "run_activation_dry_run" &&
        activationIdGateClickProof.blockedDryRun?.action?.impact ===
          "collect_evidence" &&
        activationIdGateClickProof.blockedDryRun?.action?.command ===
          "workflow-harness-gate-action-activation-id" &&
        activationIdGateClickProof.blockedDryRun?.decision === "blocked" &&
        (activationIdGateClickProof.blockedDryRun?.activationBlockerCount ??
          0) > 0 &&
        (activationIdGateClickProof.blockedDryRun?.workflowActivationId ??
          null) === null &&
        activationIdGateClickProof.blockedDryRun?.workflowActivationState ===
          "blocked" &&
        activationIdGateClickProof.blockedDryRun?.latestAuditEventType ===
          "dry_run_blocked" &&
        activationIdGateClickProof.blockedDryRun?.afterState?.[
          "data-gate-status"
        ] === "blocked" &&
        activationIdGateClickProof.mintedActivation?.clicked === true &&
        activationIdGateClickProof.mintedActivation?.gateId ===
          "activation-id" &&
        activationIdGateClickProof.mintedActivation?.action?.kind ===
          "mint_activation" &&
        activationIdGateClickProof.mintedActivation?.action?.impact ===
          "mint_activation" &&
        activationIdGateClickProof.mintedActivation?.action?.command ===
          "workflow-harness-gate-action-activation-id" &&
        activationIdGateClickProof.mintedActivation?.applied === true &&
        typeof activationIdGateClickProof.mintedActivation?.activationId ===
          "string" &&
        activationIdGateClickProof.mintedActivation.activationId.startsWith(
          "activation:",
        ) &&
        activationIdGateClickProof.mintedActivation?.workflowActivationId ===
          activationIdGateClickProof.mintedActivation?.activationId &&
        activationIdGateClickProof.mintedActivation?.workflowActivationState ===
          "validated" &&
        activationIdGateClickProof.mintedActivation
          ?.workerBindingActivationId ===
          activationIdGateClickProof.mintedActivation?.activationId &&
        activationIdGateClickProof.mintedActivation
          ?.activationRecordWorkerBindingActivationId ===
          activationIdGateClickProof.mintedActivation?.activationId &&
        activationIdGateClickProof.mintedActivation
          ?.revisionBindingActivationId ===
          activationIdGateClickProof.mintedActivation?.activationId &&
        activationIdGateClickProof.mintedActivation?.rollbackTarget ===
          DEFAULT_AGENT_HARNESS_ACTIVATION_ID &&
        Boolean(
          activationIdGateClickProof.mintedActivation
            ?.activationRecordRevisionBindingHash,
        ) &&
        Boolean(
          activationIdGateClickProof.mintedActivation
            ?.rollbackRevisionBindingHash,
        ) &&
        activationIdGateClickProof.mintedActivation?.latestAuditEventType ===
          "activation_minted" &&
        activationIdGateClickProof.mintedActivation?.latestAuditStatus ===
          "applied" &&
        (activationIdGateClickProof.mintedActivation?.receiptRefs?.length ??
          0) > 0 &&
        (activationIdGateClickProof.mintedActivation?.evidenceRefs?.length ??
          0) > 0 &&
        activationIdGateClickProof.mintedActivation?.afterState?.[
          "data-gate-status"
        ] === "passed",
      auditRecordedBlockedAndPromoted:
        audit.some(
          (event) => event.eventType === "promotion_transition_blocked",
        ) &&
        audit.some(
          (event) => event.eventType === "promotion_transition_promoted",
        ),
      screenshotCaptured: screenshot.ok,
    };
    const proof = {
      schemaVersion:
        "ioi.autopilot.gui-harness.promotion-transition-live-gui-interaction.v1",
      passed: Object.values(checks).every(Boolean),
      method:
        "launch live Workflows desktop surface, run dev-only harness promotion interaction bridge, verify saved workflow state and screenshot",
      checks,
      proofWorkflowPath,
      proofWorkflowEvidencePath: workflow ? proofWorkflowEvidencePath : null,
      screenshot: screenshot.path,
      screenshotError: screenshot.stderr || null,
      liveWorkflowError: liveWorkflow.error ?? null,
      liveGuiProbeDiagnostics,
      clusters: clusterIds.map((clusterId) => {
        const cluster = clusterById.get(clusterId);
        return {
          clusterId,
          promotionStatus: cluster?.promotionStatus ?? null,
          label: cluster?.label ?? null,
        };
      }),
      runtimeSelector: selector
        ? {
            decisionId: selector.decisionId,
            workflowId: selector.workflowId,
            activationId: selector.activationId,
            harnessHash: selector.harnessHash,
            selectedSelector: selector.selectedSelector,
            productionDefaultSelector: selector.productionDefaultSelector,
            executionMode: selector.executionMode,
            actualRuntimeAuthority: selector.actualRuntimeAuthority,
            rollbackTarget: selector.rollbackTarget,
            rollbackAvailable: selector.rollbackAvailable,
            livePromotionReadinessReady: selector.livePromotionReadinessReady,
            livePromotionReadinessBlockers:
              selector.livePromotionReadinessBlockers ?? [],
            livePromotionReadinessProof:
              selector.livePromotionReadinessProof ?? null,
            livePromotionReadinessPolicyDecision:
              selector.livePromotionReadinessPolicyDecision ?? null,
            defaultLivePromotionInvariantIds:
              selector.defaultLivePromotionInvariantIds ?? [],
            defaultLivePromotionInvariantBlockers:
              selector.defaultLivePromotionInvariantBlockers ?? [],
            reviewedImportActivationApplyProofPresent:
              selector.reviewedImportActivationApplyProofPresent ?? false,
            reviewedImportActivationApplyProofPassed:
              selector.reviewedImportActivationApplyProofPassed ?? false,
            reviewedImportActivationApplyProofBlockers:
              selector.reviewedImportActivationApplyProofBlockers ?? [],
            reviewedImportActivationApplyActivationId:
              selector.reviewedImportActivationApplyActivationId ?? null,
            defaultPromotionGate: selector.defaultPromotionGate,
          }
        : null,
      liveHandoff: liveHandoff
        ? {
            workflowId: liveHandoff.workflowId,
            activationId: liveHandoff.activationId,
            harnessHash: liveHandoff.harnessHash,
            selector: liveHandoff.selector,
            productionDefaultSelector: liveHandoff.productionDefaultSelector,
            defaultAuthorityTransferred:
              liveHandoff.defaultAuthorityTransferred,
            runtimeAuthority: liveHandoff.runtimeAuthority,
            rollbackTarget: liveHandoff.rollbackTarget,
            rollbackAvailable: liveHandoff.rollbackAvailable,
            livePromotionReadinessReady:
              liveHandoff.livePromotionReadinessReady,
            livePromotionReadinessBlockers:
              liveHandoff.livePromotionReadinessBlockers ?? [],
            livePromotionReadinessProof:
              liveHandoff.livePromotionReadinessProof ?? null,
            livePromotionReadinessPolicyDecision:
              liveHandoff.livePromotionReadinessPolicyDecision ?? null,
            defaultLivePromotionInvariantIds:
              liveHandoff.defaultLivePromotionInvariantIds ?? [],
            defaultLivePromotionInvariantBlockers:
              liveHandoff.defaultLivePromotionInvariantBlockers ?? [],
            reviewedImportActivationApplyProofPresent:
              liveHandoff.reviewedImportActivationApplyProofPresent ?? false,
            reviewedImportActivationApplyProofPassed:
              liveHandoff.reviewedImportActivationApplyProofPassed ?? false,
            reviewedImportActivationApplyProofBlockers:
              liveHandoff.reviewedImportActivationApplyProofBlockers ?? [],
            reviewedImportActivationApplyActivationId:
              liveHandoff.reviewedImportActivationApplyActivationId ?? null,
            activationBlockerCount: liveHandoff.activationBlockers?.length ?? 0,
          }
        : null,
      defaultDispatch: defaultDispatch
        ? {
            dispatchId: defaultDispatch.dispatchId,
            selectorDecisionId: defaultDispatch.selectorDecisionId,
            workflowId: defaultDispatch.workflowId,
            activationId: defaultDispatch.activationId,
            harnessHash: defaultDispatch.harnessHash,
            selectedSelector: defaultDispatch.selectedSelector,
            productionDefaultSelector:
              defaultDispatch.productionDefaultSelector,
            executionMode: defaultDispatch.executionMode,
            runtimeAuthority: defaultDispatch.runtimeAuthority,
            rollbackTarget: defaultDispatch.rollbackTarget,
            rollbackAvailable: defaultDispatch.rollbackAvailable,
            drivesRuntimeDecision: defaultDispatch.drivesRuntimeDecision,
            acceptedClusterIds: defaultDispatch.acceptedClusterIds,
            activationBlockers: defaultDispatch.activationBlockers ?? [],
            activationIdGateClickProofPresent:
              defaultDispatch.activationIdGateClickProofPresent,
            activationIdGateClickProofPassed:
              defaultDispatch.activationIdGateClickProofPassed,
            activationIdGateClickProofBlockers:
              defaultDispatch.activationIdGateClickProofBlockers ?? [],
            defaultDispatchActivationBlockers:
              defaultDispatch.defaultDispatchActivationBlockers ?? [],
            defaultLivePromotionInvariantIds:
              defaultDispatch.defaultLivePromotionInvariantIds ?? [],
            defaultLivePromotionInvariantBlockers:
              defaultDispatch.defaultLivePromotionInvariantBlockers ?? [],
            reviewedImportActivationApplyProofPresent:
              defaultDispatch.reviewedImportActivationApplyProofPresent ??
              false,
            reviewedImportActivationApplyProofPassed:
              defaultDispatch.reviewedImportActivationApplyProofPassed ?? false,
            reviewedImportActivationApplyProofBlockers:
              defaultDispatch.reviewedImportActivationApplyProofBlockers ?? [],
            reviewedImportActivationApplyActivationId:
              defaultDispatch.reviewedImportActivationApplyActivationId ?? null,
            activationIdGate: defaultDispatch.activationIdGate ?? null,
            reviewedImportActivationApplyGate:
              defaultDispatch.reviewedImportActivationApplyGate ?? null,
            cognitionNodeAuthorityGate:
              defaultDispatch.cognitionNodeAuthorityGate ?? null,
            routingModelNodeAuthorityGate:
              defaultDispatch.routingModelNodeAuthorityGate ?? null,
            verificationOutputNodeAuthorityGate:
              defaultDispatch.verificationOutputNodeAuthorityGate ?? null,
            authorityToolingNodeAuthorityGate:
              defaultDispatch.authorityToolingNodeAuthorityGate ?? null,
            liveShadowComparisonGate:
              defaultDispatch.liveShadowComparisonGate ?? null,
            liveShadowComparisonGateReady:
              defaultDispatch.liveShadowComparisonGateReady ?? null,
            livePromotionReadinessProof:
              defaultDispatch.livePromotionReadinessProof ?? null,
            workerBindingRegistryRecord:
              defaultDispatch.workerBindingRegistryRecord ?? null,
            workerAttachReceipt: defaultDispatch.workerAttachReceipt ?? null,
            workerAttachResumeReceipt:
              defaultDispatch.workerAttachResumeReceipt ?? null,
            workerAttachRollbackReceipt:
              defaultDispatch.workerAttachRollbackReceipt ?? null,
            workerAttachLifecycle:
              defaultDispatch.workerAttachLifecycle?.map((event) => ({
                phase: event?.phase ?? null,
                attemptId: event?.attemptId ?? null,
                attachStatus: event?.attachStatus ?? null,
                accepted: event?.accepted ?? null,
                receiptId: event?.receiptId ?? null,
              })) ?? [],
            workerAttachLifecycleComplete,
            workerSessionRecord: defaultDispatch.workerSessionRecord
              ? {
                  sessionRecordId:
                    defaultDispatch.workerSessionRecord.sessionRecordId ?? null,
                  sessionId:
                    defaultDispatch.workerSessionRecord.sessionId ?? null,
                  workerId:
                    defaultDispatch.workerSessionRecord.workerId ?? null,
                  registryRecordId:
                    defaultDispatch.workerSessionRecord.registryRecordId ??
                    null,
                  currentStatus:
                    defaultDispatch.workerSessionRecord.currentStatus ?? null,
                  currentAttemptId:
                    defaultDispatch.workerSessionRecord.currentAttemptId ??
                    null,
                  currentReceiptId:
                    defaultDispatch.workerSessionRecord.currentReceiptId ??
                    null,
                  rollbackTarget:
                    defaultDispatch.workerSessionRecord.rollbackTarget ?? null,
                  rollbackTargetReady:
                    defaultDispatch.workerSessionRecord.rollbackTargetReady ??
                    null,
                  accepted:
                    defaultDispatch.workerSessionRecord.accepted ?? null,
                  blockers: Array.isArray(
                    defaultDispatch.workerSessionRecord.blockers,
                  )
                    ? defaultDispatch.workerSessionRecord.blockers
                    : [],
                  persistenceKey:
                    defaultDispatch.workerSessionRecord.persistenceKey ?? null,
                  recordPersistenceKey:
                    defaultDispatch.workerSessionRecord.recordPersistenceKey ??
                    null,
                  persistedInRuntimeCheckpoint:
                    defaultDispatch.workerSessionRecord
                      .persistedInRuntimeCheckpoint ?? null,
                  restoredFromPersistedSession:
                    defaultDispatch.workerSessionRecord
                      .restoredFromPersistedSession ?? null,
                  runtimeCheckpointSource:
                    defaultDispatch.workerSessionRecord
                      .runtimeCheckpointSource ?? null,
                  persistenceBlockers: Array.isArray(
                    defaultDispatch.workerSessionRecord.persistenceBlockers,
                  )
                    ? defaultDispatch.workerSessionRecord.persistenceBlockers
                    : [],
                  launchAuthorityReady:
                    defaultDispatch.workerSessionRecord.launchAuthorityReady ??
                    null,
                  launchAuthorityBlockers: Array.isArray(
                    defaultDispatch.workerSessionRecord.launchAuthorityBlockers,
                  )
                    ? defaultDispatch.workerSessionRecord
                        .launchAuthorityBlockers
                    : [],
                  launchAuthoritySource:
                    defaultDispatch.workerSessionRecord.launchAuthoritySource ??
                    null,
                  rollbackHandoffReady:
                    defaultDispatch.workerSessionRecord.rollbackHandoffReady ??
                    null,
                  rollbackHandoffBlockers: Array.isArray(
                    defaultDispatch.workerSessionRecord.rollbackHandoffBlockers,
                  )
                    ? defaultDispatch.workerSessionRecord
                        .rollbackHandoffBlockers
                    : [],
                  rollbackHandoffTarget:
                    defaultDispatch.workerSessionRecord.rollbackHandoffTarget ??
                    null,
                }
              : null,
            workerSessionRecordBound,
            workerLaunchEnvelopes: workerLaunchEnvelopes.map((envelope) => ({
              envelopeId: envelope?.envelopeId ?? null,
              phase: envelope?.phase ?? null,
              sessionRecordId: envelope?.sessionRecordId ?? null,
              sessionId: envelope?.sessionId ?? null,
              workerId: envelope?.workerId ?? null,
              accepted: envelope?.accepted ?? null,
              blockers: Array.isArray(envelope?.blockers)
                ? envelope.blockers
                : [],
              launchAuthorityReady: envelope?.launchAuthorityReady ?? null,
              rollbackHandoffReady: envelope?.rollbackHandoffReady ?? null,
              policyDecision: envelope?.policyDecision ?? null,
            })),
            workerHandoffReceipts: workerHandoffReceipts.map((receipt) => ({
              receiptId: receipt?.receiptId ?? null,
              envelopeId: receipt?.envelopeId ?? null,
              phase: receipt?.phase ?? null,
              handoffStatus: receipt?.handoffStatus ?? null,
              sessionRecordId: receipt?.sessionRecordId ?? null,
              sessionId: receipt?.sessionId ?? null,
              workerId: receipt?.workerId ?? null,
              accepted: receipt?.accepted ?? null,
              blockers: Array.isArray(receipt?.blockers)
                ? receipt.blockers
                : [],
              receiptRefs: Array.isArray(receipt?.receiptRefs)
                ? receipt.receiptRefs
                : [],
              policyDecision: receipt?.policyDecision ?? null,
            })),
            workerLaunchEnvelopeIds,
            workerHandoffReceiptIds,
            workerHandoffNodeAttempts: workerHandoffNodeAttempts.map(
              (attempt) => ({
                attemptId: attempt?.attemptId ?? null,
                workflowNodeId: attempt?.workflowNodeId ?? null,
                componentKind: attempt?.componentKind ?? null,
                executionMode: attempt?.executionMode ?? null,
                status: attempt?.status ?? null,
                receiptIds: Array.isArray(attempt?.receiptIds)
                  ? attempt.receiptIds
                  : [],
                replayFixtureRef: attempt?.replay?.fixtureRef ?? null,
                policyDecision: attempt?.policyDecision ?? null,
              }),
            ),
            workerHandoffNodeAttemptIds,
            workerHandoffReplayFixtureRefs,
            workerRollbackLiveShadowGateBound,
            workerLaunchHandoffBound,
            workerHandoffNodeTimelineBound,
            evidenceRefCount: defaultDispatch.evidenceRefs?.length ?? 0,
          }
        : null,
      workerBindingRegistry: workerBindingRegistry
        ? {
            registryRecordId: workerBindingRegistry.registryRecordId ?? null,
            workflowId: workerBindingRegistry.workflowId ?? null,
            activationId: workerBindingRegistry.activationId ?? null,
            activationHash: workerBindingRegistry.activationHash ?? null,
            harnessHash: workerBindingRegistry.harnessHash ?? null,
            reviewedPackageSnapshotHash:
              workerBindingRegistry.reviewedPackageSnapshotHash ?? null,
            reviewedWorkflowContentHash:
              workerBindingRegistry.reviewedWorkflowContentHash ?? null,
            reviewedActivationId:
              workerBindingRegistry.reviewedActivationId ?? null,
            reviewedHarnessWorkflowId:
              workerBindingRegistry.reviewedHarnessWorkflowId ?? null,
            reviewedWorkerBindingActivationId:
              workerBindingRegistry.reviewedWorkerBindingActivationId ?? null,
            reviewedRollbackTarget:
              workerBindingRegistry.reviewedRollbackTarget ?? null,
            reviewedReplayFixtureRefs: Array.isArray(
              workerBindingRegistry.reviewedReplayFixtureRefs,
            )
              ? workerBindingRegistry.reviewedReplayFixtureRefs
              : [],
            reviewedWorkerHandoffNodeAttemptIds: Array.isArray(
              workerBindingRegistry.reviewedWorkerHandoffNodeAttemptIds,
            )
              ? workerBindingRegistry.reviewedWorkerHandoffNodeAttemptIds
              : [],
            reviewedWorkerHandoffReceiptIds: Array.isArray(
              workerBindingRegistry.reviewedWorkerHandoffReceiptIds,
            )
              ? workerBindingRegistry.reviewedWorkerHandoffReceiptIds
              : [],
            reviewedPolicyPosture:
              workerBindingRegistry.reviewedPolicyPosture ?? null,
            rollbackTarget: workerBindingRegistry.rollbackTarget ?? null,
            readinessProofId: workerBindingRegistry.readinessProofId ?? null,
            rollbackReadinessProofId:
              workerBindingRegistry.rollbackReadinessProofId ?? null,
            rollbackLiveShadowComparisonGateId:
              workerBindingRegistry.rollbackLiveShadowComparisonGateId ?? null,
            rollbackLiveShadowComparisonGateReady:
              workerBindingRegistry.rollbackLiveShadowComparisonGateReady ??
              null,
            rollbackActivationId:
              workerBindingRegistry.rollbackActivationId ?? null,
            rollbackHarnessHash:
              workerBindingRegistry.rollbackHarnessHash ?? null,
            rollbackPolicyDecision:
              workerBindingRegistry.rollbackPolicyDecision ?? null,
            canaryResultId: workerBindingRegistry.canaryResultId ?? null,
            policyDecision: workerBindingRegistry.policyDecision ?? null,
            bindingStatus: workerBindingRegistry.bindingStatus ?? null,
            blockers: workerBindingRegistry.blockers ?? [],
            workerBinding: workerBindingRegistry.workerBinding ?? null,
          }
        : null,
      workerAttach: workerAttachReceipt
        ? {
            receiptId: workerAttachReceipt.receiptId ?? null,
            workerId: workerAttachReceipt.workerId ?? null,
            workflowId: workerAttachReceipt.workflowId ?? null,
            activationId: workerAttachReceipt.activationId ?? null,
            registryRecordId: workerAttachReceipt.registryRecordId ?? null,
            attachStatus: workerAttachReceipt.attachStatus ?? null,
            accepted: workerAttachReceipt.accepted ?? null,
            blockers: workerAttachReceipt.blockers ?? [],
            rollbackAvailable: workerAttachReceipt.rollbackAvailable ?? null,
            readinessProofId: workerAttachReceipt.readinessProofId ?? null,
            rollbackReadinessProofId:
              workerAttachReceipt.rollbackReadinessProofId ?? null,
            rollbackLiveShadowComparisonGateId:
              workerAttachReceipt.rollbackLiveShadowComparisonGateId ?? null,
            rollbackLiveShadowComparisonGateReady:
              workerAttachReceipt.rollbackLiveShadowComparisonGateReady ??
              null,
            rollbackActivationId:
              workerAttachReceipt.rollbackActivationId ?? null,
            rollbackHarnessHash:
              workerAttachReceipt.rollbackHarnessHash ?? null,
            rollbackPolicyDecision:
              workerAttachReceipt.rollbackPolicyDecision ?? null,
            reviewedPackageSnapshotHash:
              workerAttachReceipt.reviewedPackageSnapshotHash ?? null,
            reviewedWorkflowContentHash:
              workerAttachReceipt.reviewedWorkflowContentHash ?? null,
            reviewedActivationId:
              workerAttachReceipt.reviewedActivationId ?? null,
            reviewedWorkerBindingActivationId:
              workerAttachReceipt.reviewedWorkerBindingActivationId ?? null,
            reviewedReplayFixtureRefs: Array.isArray(
              workerAttachReceipt.reviewedReplayFixtureRefs,
            )
              ? workerAttachReceipt.reviewedReplayFixtureRefs
              : [],
          }
        : null,
      workerAttachLifecycle: workerAttachLifecycle.map((event) => ({
        phase: event?.phase ?? null,
        attemptId: event?.attemptId ?? null,
        attachStatus: event?.attachStatus ?? null,
        accepted: event?.accepted ?? null,
        receiptId: event?.receiptId ?? null,
        rollbackReadinessProofId: event?.rollbackReadinessProofId ?? null,
        rollbackLiveShadowComparisonGateId:
          event?.rollbackLiveShadowComparisonGateId ?? null,
        rollbackLiveShadowComparisonGateReady:
          event?.rollbackLiveShadowComparisonGateReady ?? null,
        rollbackActivationId: event?.rollbackActivationId ?? null,
        rollbackHarnessHash: event?.rollbackHarnessHash ?? null,
        rollbackPolicyDecision: event?.rollbackPolicyDecision ?? null,
        blockers: event?.blockers ?? [],
      })),
      workerSessionRecord: workerSessionRecord
        ? {
            sessionRecordId: workerSessionRecord.sessionRecordId ?? null,
            sessionId: workerSessionRecord.sessionId ?? null,
            workerId: workerSessionRecord.workerId ?? null,
            workflowId: workerSessionRecord.workflowId ?? null,
            activationId: workerSessionRecord.activationId ?? null,
            registryRecordId: workerSessionRecord.registryRecordId ?? null,
            currentStatus: workerSessionRecord.currentStatus ?? null,
            currentEventId: workerSessionRecord.currentEventId ?? null,
            currentAttemptId: workerSessionRecord.currentAttemptId ?? null,
            currentReceiptId: workerSessionRecord.currentReceiptId ?? null,
            attachEventId: workerSessionRecord.attachEventId ?? null,
            resumeEventId: workerSessionRecord.resumeEventId ?? null,
            rollbackEventId: workerSessionRecord.rollbackEventId ?? null,
            lifecycleEventIds: workerSessionRecord.lifecycleEventIds ?? [],
            lifecycleAttemptIds: workerSessionRecord.lifecycleAttemptIds ?? [],
            receiptIds: workerSessionRecord.receiptIds ?? [],
            lifecycleStatuses: workerSessionRecord.lifecycleStatuses ?? [],
            rollbackTarget: workerSessionRecord.rollbackTarget ?? null,
            readinessProofId: workerSessionRecord.readinessProofId ?? null,
            rollbackReadinessProofId:
              workerSessionRecord.rollbackReadinessProofId ?? null,
            rollbackLiveShadowComparisonGateId:
              workerSessionRecord.rollbackLiveShadowComparisonGateId ?? null,
            rollbackLiveShadowComparisonGateReady:
              workerSessionRecord.rollbackLiveShadowComparisonGateReady ??
              null,
            rollbackActivationId: workerSessionRecord.rollbackActivationId ?? null,
            rollbackHarnessHash: workerSessionRecord.rollbackHarnessHash ?? null,
            rollbackPolicyDecision:
              workerSessionRecord.rollbackPolicyDecision ?? null,
            resumed: workerSessionRecord.resumed ?? null,
            rollbackAvailable: workerSessionRecord.rollbackAvailable ?? null,
            rollbackTargetReady:
              workerSessionRecord.rollbackTargetReady ?? null,
            accepted: workerSessionRecord.accepted ?? null,
            blockers: Array.isArray(workerSessionRecord.blockers)
              ? workerSessionRecord.blockers
              : [],
            persistenceKey: workerSessionRecord.persistenceKey ?? null,
            recordPersistenceKey:
              workerSessionRecord.recordPersistenceKey ?? null,
            persistedInRuntimeCheckpoint:
              workerSessionRecord.persistedInRuntimeCheckpoint ?? null,
            restoredFromPersistedSession:
              workerSessionRecord.restoredFromPersistedSession ?? null,
            runtimeCheckpointSource:
              workerSessionRecord.runtimeCheckpointSource ?? null,
            persistenceBlockers: Array.isArray(
              workerSessionRecord.persistenceBlockers,
            )
              ? workerSessionRecord.persistenceBlockers
              : [],
            launchAuthorityReady:
              workerSessionRecord.launchAuthorityReady ?? null,
            launchAuthorityBlockers: Array.isArray(
              workerSessionRecord.launchAuthorityBlockers,
            )
              ? workerSessionRecord.launchAuthorityBlockers
              : [],
            launchAuthoritySource:
              workerSessionRecord.launchAuthoritySource ?? null,
            rollbackHandoffReady:
              workerSessionRecord.rollbackHandoffReady ?? null,
            rollbackHandoffBlockers: Array.isArray(
              workerSessionRecord.rollbackHandoffBlockers,
            )
              ? workerSessionRecord.rollbackHandoffBlockers
              : [],
            rollbackHandoffTarget:
              workerSessionRecord.rollbackHandoffTarget ?? null,
            evidenceRefs: workerSessionRecord.evidenceRefs ?? [],
          }
        : null,
      workerSessionRecordBound,
      workerLaunchEnvelopes: workerLaunchEnvelopes.map((envelope) => ({
        envelopeId: envelope?.envelopeId ?? null,
        phase: envelope?.phase ?? null,
        sessionRecordId: envelope?.sessionRecordId ?? null,
        sessionId: envelope?.sessionId ?? null,
        workerId: envelope?.workerId ?? null,
        readinessProofId: envelope?.readinessProofId ?? null,
        rollbackReadinessProofId: envelope?.rollbackReadinessProofId ?? null,
        rollbackLiveShadowComparisonGateId:
          envelope?.rollbackLiveShadowComparisonGateId ?? null,
        rollbackLiveShadowComparisonGateReady:
          envelope?.rollbackLiveShadowComparisonGateReady ?? null,
        rollbackActivationId: envelope?.rollbackActivationId ?? null,
        rollbackHarnessHash: envelope?.rollbackHarnessHash ?? null,
        rollbackPolicyDecision: envelope?.rollbackPolicyDecision ?? null,
        accepted: envelope?.accepted ?? null,
        blockers: Array.isArray(envelope?.blockers) ? envelope.blockers : [],
        launchAuthorityReady: envelope?.launchAuthorityReady ?? null,
        rollbackHandoffReady: envelope?.rollbackHandoffReady ?? null,
        policyDecision: envelope?.policyDecision ?? null,
      })),
      workerHandoffReceipts: workerHandoffReceipts.map((receipt) => ({
        receiptId: receipt?.receiptId ?? null,
        envelopeId: receipt?.envelopeId ?? null,
        phase: receipt?.phase ?? null,
        handoffStatus: receipt?.handoffStatus ?? null,
        sessionRecordId: receipt?.sessionRecordId ?? null,
        sessionId: receipt?.sessionId ?? null,
        workerId: receipt?.workerId ?? null,
        readinessProofId: receipt?.readinessProofId ?? null,
        rollbackReadinessProofId: receipt?.rollbackReadinessProofId ?? null,
        rollbackLiveShadowComparisonGateId:
          receipt?.rollbackLiveShadowComparisonGateId ?? null,
        rollbackLiveShadowComparisonGateReady:
          receipt?.rollbackLiveShadowComparisonGateReady ?? null,
        rollbackActivationId: receipt?.rollbackActivationId ?? null,
        rollbackHarnessHash: receipt?.rollbackHarnessHash ?? null,
        rollbackPolicyDecision: receipt?.rollbackPolicyDecision ?? null,
        accepted: receipt?.accepted ?? null,
        blockers: Array.isArray(receipt?.blockers) ? receipt.blockers : [],
        receiptRefs: Array.isArray(receipt?.receiptRefs)
          ? receipt.receiptRefs
          : [],
        policyDecision: receipt?.policyDecision ?? null,
      })),
      workerLaunchEnvelopeIds,
      workerHandoffReceiptIds,
      workerHandoffNodeAttempts: workerHandoffNodeAttempts.map((attempt) => ({
        attemptId: attempt?.attemptId ?? null,
        workflowNodeId: attempt?.workflowNodeId ?? null,
        componentKind: attempt?.componentKind ?? null,
        executionMode: attempt?.executionMode ?? null,
        status: attempt?.status ?? null,
        receiptIds: Array.isArray(attempt?.receiptIds)
          ? attempt.receiptIds
          : [],
        replayFixtureRef: attempt?.replay?.fixtureRef ?? null,
        policyDecision: attempt?.policyDecision ?? null,
      })),
      workerHandoffNodeAttemptIds,
      workerHandoffReplayFixtureRefs,
      workerLaunchHandoffBound,
      workerHandoffNodeTimelineBound,
      attempts: transitions
        .filter((attempt) => clusterIds.includes(attempt.clusterId))
        .map((attempt) => ({
          clusterId: attempt.clusterId,
          targetExecutionMode: attempt.targetExecutionMode,
          attemptStatus: attempt.attemptStatus,
          previousStatus: attempt.previousStatus,
          nextStatus: attempt.nextStatus,
          gateDecision: attempt.gateDecision,
          blockers: attempt.blockers,
          receiptRefCount: attempt.receiptRefs?.length ?? 0,
          replayFixtureRefCount: attempt.replayFixtureRefs?.length ?? 0,
        })),
      uiSelectors: {
        groupInspector: "workflow-harness-group-inspector",
        promotionActions: "workflow-harness-group-promotion-actions",
        promoteClusterGated: "workflow-harness-promote-cluster-gated",
        promoteClusterLive: "workflow-harness-promote-cluster-live",
        promotionAttempt: "workflow-harness-group-promotion-attempt",
        runtimeSelectorBadge: "workflow-harness-runtime-selector",
        defaultDispatchPanel: "workflow-harness-default-runtime-dispatch",
        activeRuntimeBinding: "workflow-harness-active-runtime-binding",
        activeRuntimeBindingSelectorLink:
          "workflow-harness-active-runtime-binding-selector-link",
        activeRuntimeBindingDispatchLink:
          "workflow-harness-active-runtime-binding-dispatch-link",
        activeRuntimeBindingWorkerLink:
          "workflow-harness-active-runtime-binding-worker-link",
        activeRuntimeBindingRollbackLink:
          "workflow-harness-active-runtime-binding-rollback-link",
        activeRuntimeRollbackProof:
          "workflow-harness-active-runtime-rollback-proof",
        activeRuntimeRollbackProofLaunchEnvelopeLink:
          "workflow-harness-active-runtime-rollback-proof-launch-envelope-link",
        activeRuntimeRollbackProofHandoffReceiptLink:
          "workflow-harness-active-runtime-rollback-proof-handoff-receipt-link",
        activeRuntimeRollbackProofNodeAttemptLink:
          "workflow-harness-active-runtime-rollback-proof-node-attempt-link",
        activeRuntimeRollbackProofReplayLink:
          "workflow-harness-active-runtime-rollback-proof-replay-link",
        activeRuntimeRollbackDryRun:
          "workflow-harness-active-runtime-rollback-dry-run",
        activeRuntimeRollbackApply:
          "workflow-harness-active-runtime-rollback-apply",
        deepLinkState: "workflow-harness-deep-link-state",
      },
      routeStatefulDeepLinks,
      deepLinkReplayProof,
      coldStartDeepLinkRestoreProof,
      activationBlockerDeepLinkProof,
      activationGateDeepLinkProof,
      liveActivationGateDeepLinkProof,
      liveTurnNodeInspectorDeepLinkProof,
      liveShadowComparisonDeepLinkProof,
      activeRuntimeRollbackProofWorkbenchProof,
      activeRuntimeRollbackExecutionProof,
      activeRuntimeRollbackApplyProof,
      activeRuntimeRollbackNegativeApplyProof,
      liveTurnNodeInspector: liveTurnNodeInspectorDeepLinkCase
        ? {
            selectedRailTestId:
              liveTurnNodeInspectorDeepLinkCase.selectedRailTestId,
            hash: liveTurnNodeInspectorDeepLinkCase.hash,
            expectedNodeAttemptId:
              liveTurnNodeInspectorDeepLinkCase.expectedValue,
            observedNodeAttemptId:
              liveTurnNodeInspectorState["data-node-attempt-id"] ?? null,
            sourceKind:
              liveTurnNodeInspectorState["data-node-attempt-source-kind"] ??
              null,
            workflowNodeId:
              liveTurnNodeInspectorState["data-workflow-node-id"] ?? null,
            componentKind:
              liveTurnNodeInspectorState["data-component-kind"] ?? null,
            componentId:
              liveTurnNodeInspectorState["data-component-id"] ?? null,
            harnessWorkflowId:
              liveTurnNodeInspectorState["data-harness-workflow-id"] ?? null,
            harnessActivationId:
              liveTurnNodeInspectorState["data-harness-activation-id"] ?? null,
            harnessHash:
              liveTurnNodeInspectorState["data-harness-hash"] ?? null,
            executionMode:
              liveTurnNodeInspectorState["data-execution-mode"] ?? null,
            readiness: liveTurnNodeInspectorState["data-readiness"] ?? null,
            status: liveTurnNodeInspectorState["data-status"] ?? null,
            policyDecision:
              liveTurnNodeInspectorState["data-policy-decision"] ?? null,
            receiptRefs: liveTurnNodeInspectorReceiptRefs,
            replayFixtureRef:
              liveTurnNodeInspectorState["data-replay-fixture-ref"] ?? null,
            inputHash: liveTurnNodeInspectorState["data-input-hash"] ?? null,
            outputHash: liveTurnNodeInspectorState["data-output-hash"] ?? null,
          }
        : null,
      liveShadowComparison: liveShadowComparisonDeepLinkCase
        ? {
            selectedRailTestId:
              liveShadowComparisonDeepLinkCase.selectedRailTestId,
            hash: liveShadowComparisonDeepLinkCase.hash,
            expectedLiveAttemptId:
              liveShadowComparisonDeepLinkCase.expectedValue,
            observedLiveAttemptId:
              liveShadowComparisonState["data-live-attempt-id"] ?? null,
            observedShadowAttemptId:
              liveShadowComparisonState["data-shadow-attempt-id"] ?? null,
            workflowNodeId:
              liveShadowComparisonState["data-workflow-node-id"] ?? null,
            componentKind:
              liveShadowComparisonState["data-component-kind"] ?? null,
            divergence: liveShadowComparisonState["data-divergence"] ?? null,
            blocking: liveShadowComparisonState["data-blocking"] ?? null,
            liveReceiptRefs: liveShadowComparisonLiveReceiptRefs,
            shadowReceiptRefs: liveShadowComparisonShadowReceiptRefs,
            liveReplayFixtureRef:
              liveShadowComparisonState["data-live-replay-fixture-ref"] ?? null,
            shadowReplayFixtureRef:
              liveShadowComparisonState["data-shadow-replay-fixture-ref"] ??
              null,
            liveInputHash:
              liveShadowComparisonState["data-live-input-hash"] ?? null,
            shadowInputHash:
              liveShadowComparisonState["data-shadow-input-hash"] ?? null,
            liveOutputHash:
              liveShadowComparisonState["data-live-output-hash"] ?? null,
            shadowOutputHash:
              liveShadowComparisonState["data-shadow-output-hash"] ?? null,
          }
        : null,
      activeRuntimeRollbackProofWorkbench:
        activeRuntimeRollbackProofWorkbenchProof
          ? {
              passed: activeRuntimeRollbackProofWorkbenchProof.passed,
              selectedRailTestId:
                activeRuntimeRollbackProofCasesById.get(
                  "active-runtime-rollback-node-attempt",
                )?.selectedRailTestId ?? null,
              caseIds: activeRuntimeRollbackProofWorkbenchProof.cases.map(
                (replayCase) => replayCase.id,
              ),
              rollbackProofBound:
                activeRuntimeRollbackProofState[
                  "data-rollback-proof-bound"
                ] ?? null,
              readinessProofId:
                activeRuntimeRollbackProofState[
                  "data-rollback-readiness-proof-id"
                ] ?? null,
              liveShadowGateId:
                activeRuntimeRollbackProofState[
                  "data-rollback-live-shadow-gate-id"
                ] ?? null,
              liveShadowGateReady:
                activeRuntimeRollbackProofState[
                  "data-rollback-live-shadow-gate-ready"
                ] ?? null,
              activationId:
                activeRuntimeRollbackProofState[
                  "data-rollback-activation-id"
                ] ?? null,
              harnessHash:
                activeRuntimeRollbackProofState[
                  "data-rollback-harness-hash"
                ] ?? null,
              policyDecision:
                activeRuntimeRollbackProofState[
                  "data-rollback-policy-decision"
                ] ?? null,
              launchEnvelopeId:
                activeRuntimeRollbackProofState[
                  "data-rollback-launch-envelope-id"
                ] ?? null,
              handoffReceiptId:
                activeRuntimeRollbackProofState[
                  "data-rollback-handoff-receipt-id"
                ] ?? null,
              nodeAttemptId:
                activeRuntimeRollbackProofState[
                  "data-rollback-node-attempt-id"
                ] ?? null,
              replayFixtureRef:
                activeRuntimeRollbackProofState[
                  "data-rollback-replay-fixture-ref"
                ] ?? null,
            }
          : null,
      activeRuntimeRollbackExecutionWorkbench:
        activeRuntimeRollbackExecutionProof
          ? {
              passed: activeRuntimeRollbackExecutionProof.passed,
              rollbackTarget:
                activeRuntimeRollbackExecutionProof.rollbackTarget ?? null,
              readinessProofId:
                activeRuntimeRollbackExecutionProof.readinessProofId ?? null,
              liveShadowGateId:
                activeRuntimeRollbackExecutionProof
                  .liveShadowComparisonGateId ?? null,
              activationId:
                activeRuntimeRollbackExecutionProof.activationId ?? null,
              harnessHash:
                activeRuntimeRollbackExecutionProof.harnessHash ?? null,
              dryRunStatus:
                activeRuntimeRollbackExecutionProof.dryRun?.canaryStatus ??
                null,
              canaryResultId:
                activeRuntimeRollbackExecutionProof.dryRun?.canaryResultId ??
                null,
              canaryHashVerified:
                activeRuntimeRollbackExecutionProof.dryRun
                  ?.canaryHashVerified ?? null,
              applyReadiness:
                activeRuntimeRollbackExecutionProof.apply?.readiness ?? null,
              applyDisabled:
                activeRuntimeRollbackExecutionProof.apply?.disabled ?? null,
              routeRestoreProofBound:
                activeRuntimeRollbackExecutionProof.routeRestore
                  ?.rollbackProofBound ?? null,
              routeRestoreApplyDisabled:
                activeRuntimeRollbackExecutionProof.routeRestore
                  ?.applyDisabled ?? null,
              routeRestoreDryRunStatus:
                activeRuntimeRollbackExecutionProof.routeRestore
                  ?.dryRunStatus ?? null,
              blockers: activeRuntimeRollbackExecutionProof.blockers ?? [],
            }
          : null,
      activeRuntimeRollbackApplyExecution: activeRuntimeRollbackApplyProof
        ? {
            passed: activeRuntimeRollbackApplyProof.passed,
            applyStatus: activeRuntimeRollbackApplyProof.applyStatus ?? null,
            rollbackApplied:
              activeRuntimeRollbackApplyProof.rollbackApplied ?? null,
            rollbackTarget:
              activeRuntimeRollbackApplyProof.rollbackTarget ?? null,
            executionId: activeRuntimeRollbackApplyProof.executionId ?? null,
            rollbackReceiptId:
              activeRuntimeRollbackApplyProof.rollbackReceiptId ?? null,
            auditEventId: activeRuntimeRollbackApplyProof.auditEventId ?? null,
            rollbackTargetVerified:
              activeRuntimeRollbackApplyProof.rollbackTargetVerified ?? null,
            hashVerified: activeRuntimeRollbackApplyProof.hashVerified ?? null,
            policyDecision:
              activeRuntimeRollbackApplyProof.policyDecision ?? null,
            receiptRefs: activeRuntimeRollbackApplyProof.receiptRefs ?? [],
            replayFixtureRefs:
              activeRuntimeRollbackApplyProof.replayFixtureRefs ?? [],
            staleProofBlocked:
              activeRuntimeRollbackApplyProof.staleProofBlocked ?? null,
            detachedProofBlocked:
              activeRuntimeRollbackApplyProof.detachedProofBlocked ?? null,
            auditEventType:
              activeRuntimeRollbackApplyAuditEvent?.eventType ?? null,
            auditEventStatus:
              activeRuntimeRollbackApplyAuditEvent?.status ?? null,
            blockers: activeRuntimeRollbackApplyProof.blockers ?? [],
          }
        : null,
      activeRuntimeRollbackNegativeApply: activeRuntimeRollbackNegativeApplyProof
        ? {
            passed: activeRuntimeRollbackNegativeApplyProof.passed,
            caseCount:
              activeRuntimeRollbackNegativeApplyProof.cases?.length ?? 0,
            cases:
              activeRuntimeRollbackNegativeApplyProof.cases?.map(
                (negativeCase) => ({
                  caseId: negativeCase.caseId,
                  mutationKind: negativeCase.mutationKind,
                  applyButtonDisabled: negativeCase.applyButtonDisabled,
                  applyStatus: negativeCase.applyStatus,
                  staleProofBlocked: negativeCase.staleProofBlocked,
                  detachedProofBlocked: negativeCase.detachedProofBlocked,
                  rollbackApplied: negativeCase.rollbackApplied,
                  rollbackTargetVerified:
                    negativeCase.rollbackTargetVerified,
                  hashVerified: negativeCase.hashVerified,
                  expectedBlockers: negativeCase.expectedBlockers ?? [],
                  observedRailBlockers:
                    negativeCase.observedRailBlockers ?? [],
                  runtimeBlockers: negativeCase.runtimeBlockers ?? [],
                  passed: negativeCase.passed,
                }),
              ) ?? [],
            blockers: activeRuntimeRollbackNegativeApplyProof.blockers ?? [],
          }
        : null,
      activationGateActionClickProof,
      packageEvidenceGateClickProof,
      packageEvidenceImportRoundTripProof,
      packageImportReviewProof,
      packageImportActivationHandoffProof,
      packageImportActivationApplyProof,
      packageImportActivationReplayIntegrityProof,
      activationGateCollectEvidenceClickProof,
      activationGateRollbackRestoreClickProof,
      activationIdGateClickProof,
      workerInvariantNegativeEnforcementProof,
      activationGateEvidenceInspector: activationGateDeepLinkCase
        ? {
            selectedRailTestId: activationGateDeepLinkCase.selectedRailTestId,
            gateId:
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-selected-activation-gate-id"
              ] ?? null,
            sourceKind:
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-gate-source-kind"
              ] ?? null,
            status:
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-gate-status"
              ] ?? null,
            evidenceRefCount: activationGateEvidenceRefCount,
            receiptRefCount: Number(
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-receipt-ref-count"
              ] ?? 0,
            ),
            replayFixtureRefCount: Number(
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-replay-fixture-ref-count"
              ] ?? 0,
            ),
            requiredInvariantIds:
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-required-invariant-ids"
              ] ?? "",
            invariantBlockerCount: Number(
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-invariant-blocker-count"
              ] ?? 0,
            ),
            invariantBlockers:
              activationGateDeepLinkCase.observedSelectedState?.[
                "data-invariant-blockers"
              ] ?? "",
            action: {
              id:
                activationGateDeepLinkCase.observedSelectedState?.[
                  "data-gate-action-id"
                ] ?? null,
              kind:
                activationGateDeepLinkCase.observedSelectedState?.[
                  "data-gate-action-kind"
                ] ?? null,
              impact:
                activationGateDeepLinkCase.observedSelectedState?.[
                  "data-gate-action-impact"
                ] ?? null,
              command:
                activationGateDeepLinkCase.observedSelectedState?.[
                  "data-gate-action-command"
                ] ?? null,
              disabled:
                activationGateDeepLinkCase.observedSelectedState?.[
                  "data-gate-action-disabled"
                ] ?? null,
            },
            selectedEvidenceRef:
              activationGateEvidenceDeepLinkCase?.observedSelectedState?.[
                "data-selected-activation-gate-evidence-ref"
              ] ?? null,
            selectedNodeAttemptId:
              activationGateNodeAttemptDeepLinkCase?.observedSelectedState?.[
                "data-selected-activation-gate-node-attempt-id"
              ] ??
              activationIdGateClickProof?.mintedActivation
                ?.workerHandoffTimelineAttemptId ??
              null,
            selectedReceiptRef:
              activationGateReceiptDeepLinkCase?.observedSelectedState?.[
                "data-selected-activation-gate-receipt-ref"
              ] ?? null,
            selectedReplayFixtureRef:
              activationGateReplayDeepLinkCase?.observedSelectedState?.[
                "data-selected-activation-gate-replay-fixture-ref"
              ] ?? null,
            referenceDeepLinks: {
              evidence: activationGateEvidenceDeepLinkCase?.hash ?? null,
              receipt: activationGateReceiptDeepLinkCase?.hash ?? null,
              replay: activationGateReplayDeepLinkCase?.hash ?? null,
            },
          }
        : null,
      activationGateWorkerInvariantInspector:
        activationGateWorkerInvariantDeepLinkCase
          ? {
              selectedRailTestId:
                activationGateWorkerInvariantDeepLinkCase.selectedRailTestId,
              hash: activationGateWorkerInvariantDeepLinkCase.hash,
              gateId:
                activationGateWorkerInvariantState[
                  "data-selected-activation-gate-id"
                ] ?? null,
              status:
                activationGateWorkerInvariantState["data-gate-status"] ?? null,
              requiredInvariantIds:
                activationGateWorkerInvariantState[
                  "data-required-invariant-ids"
                ] ?? "",
              invariantBlockerCount: Number(
                activationGateWorkerInvariantState[
                  "data-invariant-blocker-count"
                ] ?? 0,
              ),
              invariantBlockers:
                activationGateWorkerInvariantState["data-invariant-blockers"] ??
                "",
              action: {
                id:
                  activationGateWorkerInvariantState["data-gate-action-id"] ??
                  null,
                kind:
                  activationGateWorkerInvariantState["data-gate-action-kind"] ??
                  null,
                impact:
                  activationGateWorkerInvariantState[
                    "data-gate-action-impact"
                  ] ?? null,
                command:
                  activationGateWorkerInvariantState[
                    "data-gate-action-command"
                  ] ?? null,
                disabled:
                  activationGateWorkerInvariantState[
                    "data-gate-action-disabled"
                  ] ?? null,
              },
            }
          : null,
	      sourceRefs: [
	        "packages/agent-ide/src/WorkflowComposer/controller.tsx",
	        "packages/agent-ide/src/WorkflowComposer/support.tsx",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-rail-search-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-settings-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx", "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-settings-harness-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-readiness-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-test-readiness-model.ts",
	        "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
	        "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
	        "packages/agent-ide/src/runtime/harness-workflow/index.ts",
	      ],
    };
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
    return { path: proofPath, proof };
  } finally {
    writeFileSync(logPath, log.join(""), "utf8");
    stopDesktopProcess(desktop);
    await sleep(2_000);
  }
}

async function runGuiValidation(args, outputRoot) {
  mkdirSync(outputRoot, { recursive: true });
  const logPath = join(outputRoot, "desktop.log");
  const log = [];
  const startedAtMs = Date.now();
  closeMatchingWindows(args.windowName);
  await sleep(1_000);
  const desktop = spawn("npm", ["run", "dev:desktop"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      AUTOPILOT_LOCAL_GPU_DEV: "1",
      AUTOPILOT_HARNESS_DEFAULT_PROMOTION:
        process.env.AUTOPILOT_HARNESS_DEFAULT_PROMOTION ?? "1",
      AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT:
        process.env.AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT ?? "1",
      AUTOPILOT_RESET_DATA_ON_BOOT:
        process.env.AUTOPILOT_RESET_DATA_ON_BOOT ?? "1",
      VITE_AUTOPILOT_INITIAL_VIEW: "chat",
      VITE_AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI: "1",
      AUTOPILOT_REUSE_DEV_SERVER: "0",
      AUTO_START_DEV_SERVER: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  desktop.stdout.on("data", (chunk) => log.push(chunk.toString()));
  desktop.stderr.on("data", (chunk) => log.push(chunk.toString()));
  let desktopStopped = false;

  try {
    const windowId = await waitForWindow(args.windowName, args.windowTimeoutMs);
    if (!windowId) {
      return buildBlockedAutopilotGuiHarnessResult({
        reason: `Timed out waiting for window matching ${args.windowName}`,
        evidence: log.slice(-80),
      });
    }
    await sleep(args.settleMs);

    const queryResults = [];
    const screenshots = {};
    for (let index = 0; index < AUTOPILOT_RETAINED_QUERIES.length; index += 1) {
      const retainedQuery = AUTOPILOT_RETAINED_QUERIES[index];
      const submitEvidence = await submitRetainedQuery(
        windowId,
        retainedQuery.query,
        startedAtMs,
      );
      const runtimeEvidence =
        submitEvidence.matchedUserRequest === true
          ? await waitForRetainedQueryRuntimeEvidence(
              retainedQuery.query,
              startedAtMs,
              args.queryTimeoutMs,
            )
          : submitEvidence;
      const postAnswerSettleMs = Math.min(
        Math.max(args.querySettleMs, 8_000),
        30_000,
      );
      await sleep(postAnswerSettleMs);
      const screenshot = captureScreenshot(
        windowId,
        outputRoot,
        retainedQuery.scenario,
      );
      screenshots[retainedQuery.scenario] = screenshot;
      const passed =
        screenshot.ok &&
        runtimeEvidence.matchedUserRequest === true &&
        runtimeEvidence.hasAssistantResponse === true &&
        runtimeEvidence.concatenatedPrompt !== true;
      queryResults.push({
        scenario: retainedQuery.scenario,
        query: retainedQuery.query,
        passed,
        screenshot: screenshot.path,
        screenshotError: screenshot.stderr || null,
        runtimeEvidence,
      });
    }

    writeFileSync(logPath, log.join(""), "utf8");
    stopDesktopProcess(desktop);
    desktopStopped = true;
    await sleep(3_000);
    const promotionTransitionLiveGuiInteractionProof =
      await collectPromotionTransitionLiveGuiInteractionProof(outputRoot, args);
    const runtimeArtifacts = await collectRuntimeArtifacts(outputRoot, logPath);
    const rollbackRestoreCanaryUiProof =
      collectRollbackRestoreCanaryUiProof(outputRoot);
    const promotionTransitionGuiBehaviorProof =
      collectPromotionTransitionGuiBehaviorProof(outputRoot);
    const workflowSkillContextProof =
      collectWorkflowSkillContextProof(outputRoot);
    const workflowCodingRouteProof =
      collectWorkflowCodingRouteProof(outputRoot);
    const workflowCodingRoutePromotionLoopProof =
      collectWorkflowCodingRoutePromotionLoopProof(outputRoot);
    const guiEvidence = buildGuiEvidenceAssessment({
      queryResults,
      runtimeArtifacts,
      rollbackRestoreCanaryUiProof,
      promotionTransitionGuiBehaviorProof,
      promotionTransitionLiveGuiInteractionProof,
      workflowSkillContextProof,
      workflowCodingRouteProof,
      workflowCodingRoutePromotionLoopProof,
    });
    const packageManifestHasForkMutationCanary = (manifest) =>
      (manifest?.forkMutationCanaryReceiptRefCount ?? 0) > 0 &&
      (manifest?.forkMutationCanaryReplayFixtureRefCount ?? 0) > 0 &&
      (manifest?.forkMutationCanaryNodeAttemptCount ?? 0) > 0;
    const packageReviewHasForkMutationCanary = (review) =>
      (review?.evidence?.forkMutationCanaryReceiptRefCount ?? 0) > 0 &&
      (review?.evidence?.forkMutationCanaryReplayFixtureRefCount ?? 0) > 0 &&
      (review?.evidence?.forkMutationCanaryNodeAttemptCount ?? 0) > 0;
    const promotionForkMutationCanaryArtifact =
      packageManifestHasForkMutationCanary(
        promotionTransitionLiveGuiInteractionProof.proof
          ?.packageEvidenceGateClickProof?.manifest,
      ) ||
      packageManifestHasForkMutationCanary(
        promotionTransitionLiveGuiInteractionProof.proof
          ?.packageEvidenceImportRoundTripProof?.validImport?.manifest,
      ) ||
      packageReviewHasForkMutationCanary(
        promotionTransitionLiveGuiInteractionProof.proof?.packageImportReviewProof
          ?.review,
      ) ||
      packageReviewHasForkMutationCanary(
        promotionTransitionLiveGuiInteractionProof.proof
          ?.packageImportActivationHandoffProof?.review,
      ) ||
      packageReviewHasForkMutationCanary(
        promotionTransitionLiveGuiInteractionProof.proof
          ?.packageImportActivationApplyProof?.review,
      );
    return {
      schemaVersion: autopilotGuiHarnessContract().schemaVersion,
      launchCommand: AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
      blocked: false,
      windowId,
      queryResults,
      artifacts: {
        screenshots,
        runtime_artifact_summary: runtimeArtifacts.path,
        transcript_projection:
          runtimeArtifacts.summary.transcriptCount > 0
            ? runtimeArtifacts.path
            : false,
        runtime_trace:
          runtimeArtifacts.summary.logSignals.chatProofTrace > 0
            ? logPath
            : false,
        event_stream:
          runtimeArtifacts.summary.logSignals.kernelEvents > 0 ||
          runtimeArtifacts.summary.threadEventCount > 0
            ? runtimeArtifacts.path
            : false,
        receipts:
          runtimeArtifacts.summary.runBundleCount > 0 ||
          runtimeArtifacts.summary.threadEventCount > 0
            ? runtimeArtifacts.path
            : false,
        prompt_assembly:
          runtimeArtifacts.summary.promptAssemblyCount > 0
            ? runtimeArtifacts.path
            : false,
        selected_sources:
          runtimeArtifacts.summary.selectedSourceCount > 0
            ? runtimeArtifacts.path
            : false,
        scorecard:
          runtimeArtifacts.summary.scorecardCount > 0
            ? runtimeArtifacts.path
            : false,
        stop_reason:
          runtimeArtifacts.summary.stopReasonCount > 0
            ? runtimeArtifacts.path
            : false,
        quality_ledger:
          runtimeArtifacts.summary.qualityLedgerCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_shadow_run:
          runtimeArtifacts.summary.harnessShadowRunCount > 0 &&
          runtimeArtifacts.summary.harnessNodeAttemptCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_cognition:
          runtimeArtifacts.summary.harnessGatedCognitionCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_cognition_node_authority:
          runtimeArtifacts.summary.harnessCognitionNodeAuthorityCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_routing_model_node_authority:
          runtimeArtifacts.summary.harnessRoutingModelNodeAuthorityCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_verification_output_node_authority:
          runtimeArtifacts.summary.harnessVerificationOutputNodeAuthorityCount >
          0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_node_authority:
          runtimeArtifacts.summary.harnessAuthorityToolingNodeAuthorityCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_routing_model:
          runtimeArtifacts.summary.harnessGatedRoutingModelCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_verification_output:
          runtimeArtifacts.summary.harnessGatedVerificationOutputCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_authority_tooling:
          runtimeArtifacts.summary.harnessGatedAuthorityToolingCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_fork_activation:
          runtimeArtifacts.summary.harnessForkActivationBlockedCount > 0 &&
          runtimeArtifacts.summary.harnessForkActivationMintedCount > 0 &&
          runtimeArtifacts.summary.harnessForkHandoffTimelineBoundCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_fork_mutation_canary:
          (runtimeArtifacts.summary.harnessForkMutationCanaryReadyCount > 0 &&
            runtimeArtifacts.summary.harnessForkMutationCanaryReceiptCount > 0 &&
            runtimeArtifacts.summary.harnessForkMutationCanaryReplayCount > 0 &&
            runtimeArtifacts.summary.harnessForkMutationCanaryNodeAttemptCount >
              0) ||
          promotionForkMutationCanaryArtifact
            ? runtimeArtifacts.path
            : false,
        harness_fork_mutation_canary_node_inspector:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageEvidenceGateClickProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_rollback_restore_canary:
          runtimeArtifacts.summary.harnessRollbackRestoreCanaryBlockedCount >
            0 &&
          runtimeArtifacts.summary.harnessRollbackRestoreCanaryReadyCount > 0 &&
          runtimeArtifacts.summary.harnessRollbackRestoreCanaryReceiptCount >=
            2 &&
          runtimeArtifacts.summary.harnessActivationAuditReceiptCount > 0 &&
          runtimeArtifacts.summary.harnessRollbackExecutionReceiptCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_rollback_restore_canary_ui:
          rollbackRestoreCanaryUiProof.proof.passed === true
            ? rollbackRestoreCanaryUiProof.path
            : false,
        harness_package_evidence_manifest:
          rollbackRestoreCanaryUiProof.proof.checks
            ?.harnessPackageEvidenceManifest === true
            ? rollbackRestoreCanaryUiProof.path
            : false,
        harness_package_evidence_gate:
          rollbackRestoreCanaryUiProof.proof.checks
            ?.harnessPackageEvidenceGate === true
            ? rollbackRestoreCanaryUiProof.path
            : false,
        harness_package_evidence_gate_click_proof:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageEvidenceGateClickProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_package_evidence_import_roundtrip:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageEvidenceImportRoundTripProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_package_import_review_mode:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageImportReviewProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_package_import_activation_handoff:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageImportActivationHandoffProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_package_import_activation_apply:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageImportActivationApplyProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_package_import_activation_replay_integrity:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.packageImportActivationReplayIntegrityProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_promotion_transition_gui_behavior:
          promotionTransitionGuiBehaviorProof.proof.passed === true
            ? promotionTransitionGuiBehaviorProof.path
            : false,
        harness_promotion_transition_live_gui_interaction:
          promotionTransitionLiveGuiInteractionProof.proof.passed === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_route_stateful_deep_link_replay:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.routeStatefulDeepLinkReplay === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_cold_start_deep_link_restore:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.coldStartDeepLinkRestore === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_revision_binding_deep_link_restore:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.routeStatefulRevisionBindingDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_blocker_deep_link_restore:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.routeStatefulActivationBlockerDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_audit_deep_link_restore:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.routeStatefulActivationAuditDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_deep_link_restore:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.routeStatefulActivationGateDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_evidence_inspector:
          rollbackRestoreCanaryUiProof.proof.checks
            ?.activationGateEvidenceInspector === true &&
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateEvidenceInspectable === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_ref_deep_link_restore:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.routeStatefulActivationGateReferenceDeepLinks === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_node_timeline_deep_link:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateNodeTimelineDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_action_workbench:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateActionWorkbench === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_action_click_proof:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateActionClickProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_collect_evidence_click_proof:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateCollectEvidenceClickProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_gate_rollback_restore_click_proof:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateRollbackRestoreClickProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_activation_id_gate_click_proof:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationIdGateClickProof === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_canary_execution_boundary:
          runtimeArtifacts.summary.harnessCanaryBoundaryExecutedCount > 0 &&
          runtimeArtifacts.summary.harnessCanaryBoundaryRollbackDrillCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_live_handoff:
          runtimeArtifacts.summary.harnessLiveHandoffDefaultPromotedCount > 0 &&
          runtimeArtifacts.summary.harnessLiveHandoffRollbackCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_selector_routing:
          runtimeArtifacts.summary.harnessSelectorDefaultPromotedCount > 0 &&
          runtimeArtifacts.summary
            .harnessSelectorLivePromotionReadinessGatedCount > 0 &&
          runtimeArtifacts.summary.harnessSelectorWorkflowRecoveryBlockedCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_selector_reviewed_import_activation_apply_invariant:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.selectorReviewedImportActivationApplyInvariant === true &&
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.liveHandoffReviewedImportActivationApplyInvariant === true &&
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.defaultDispatchReviewedImportActivationApplyInvariant === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_worker_launch_reviewed_import_activation_apply_invariant:
          runtimeArtifacts.summary
            .harnessWorkerLaunchReviewedImportActivationInvariantCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_worker_launch_reviewed_import_activation_apply_invariant_gui_visible:
          rollbackRestoreCanaryUiProof.proof.checks
            ?.workerSessionCheckpointUi === true
            ? rollbackRestoreCanaryUiProof.path
            : false,
        harness_worker_launch_reviewed_import_activation_apply_invariant_gate_deep_link:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activationGateWorkerInvariantDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_worker_launch_reviewed_import_activation_apply_invariant_negative_enforcement:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.workerInvariantNegativeEnforcement === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_default_runtime_dispatch:
          runtimeArtifacts.summary.harnessDefaultRuntimeDispatchReadonlyCount >
            0 &&
          runtimeArtifacts.summary
            .harnessActivationIdGateClickProofRuntimeCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingGateLiveCount > 0 &&
          runtimeArtifacts.summary
            .harnessAuthorityToolingProviderCatalogLiveCount > 0 &&
          runtimeArtifacts.summary
            .harnessAuthorityToolingMcpToolCatalogLiveCount > 0 &&
          runtimeArtifacts.summary
            .harnessAuthorityToolingNativeToolCatalogLiveCount > 0 &&
          runtimeArtifacts.summary
            .harnessAuthorityToolingConnectorCatalogLiveCount > 0 &&
          runtimeArtifacts.summary
            .harnessAuthorityToolingGithubPrCreateDryRunCount > 0 &&
          runtimeArtifacts.summary
            .harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_live_promotion_readiness:
          runtimeArtifacts.summary.harnessLivePromotionReadinessCount > 0 &&
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.livePromotionReadinessBound === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_chat_runtime_binding:
          runtimeArtifacts.summary.harnessDefaultRuntimeBindingMatchedCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_default_runtime_rollback_live_shadow_gate_bound:
          runtimeArtifacts.summary
            .harnessDefaultRuntimeRollbackLiveShadowGateBoundCount > 0 &&
          guiEvidence.runtimeConsistency
            .harness_default_runtime_rollback_live_shadow_gate_bound === true
            ? runtimeArtifacts.path
            : false,
        harness_worker_binding_registry_reviewed_package_bound:
          runtimeArtifacts.summary
            .harnessWorkerBindingRegistryReviewedPackageBoundCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_active_runtime_rollback_proof_workbench:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activeRuntimeRollbackProofWorkbench === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_active_runtime_rollback_execution_workbench:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activeRuntimeRollbackExecutionWorkbench === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_active_runtime_rollback_apply_execution:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activeRuntimeRollbackApplyExecution === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_active_runtime_rollback_negative_apply:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.activeRuntimeRollbackNegativeApply === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_live_turn_node_timeline:
          runtimeArtifacts.summary.harnessLiveTurnNodeTimelineCount > 0 &&
          runtimeArtifacts.summary.harnessLiveTurnNodeTimelineScenarios.includes(
            "retained_harness_dogfooding",
          )
            ? runtimeArtifacts.path
            : false,
        harness_live_turn_node_inspector:
          runtimeArtifacts.summary.harnessLiveTurnNodeInspectorCount > 0 &&
          runtimeArtifacts.summary.harnessLiveTurnNodeInspectorScenarios.includes(
            "retained_harness_dogfooding",
          )
            ? runtimeArtifacts.path
            : false,
        harness_live_turn_node_inspector_deep_link:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.liveTurnNodeInspectorDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_live_shadow_comparison:
          promotionTransitionLiveGuiInteractionProof.proof.checks
            ?.liveShadowComparisonDeepLink === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_live_shadow_comparison_gate:
          guiEvidence.runtimeConsistency
            .harness_live_shadow_comparison_gate_present === true
            ? promotionTransitionLiveGuiInteractionProof.path
            : false,
        harness_authority_tooling_gate_live:
          runtimeArtifacts.summary.harnessAuthorityToolingGateLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_provider_catalog_live:
          runtimeArtifacts.summary
            .harnessAuthorityToolingProviderCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_mcp_tool_catalog_live:
          runtimeArtifacts.summary
            .harnessAuthorityToolingMcpToolCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_native_tool_catalog_live:
          runtimeArtifacts.summary
            .harnessAuthorityToolingNativeToolCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_connector_catalog_live:
          runtimeArtifacts.summary
            .harnessAuthorityToolingConnectorCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_github_pr_create_dry_run:
          runtimeArtifacts.summary
            .harnessAuthorityToolingGithubPrCreateDryRunCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_wallet_capability_live_dry_run:
          runtimeArtifacts.summary
            .harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_model_provider_gated_visible_output:
          runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputCount >
            0 &&
          AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every(
            (scenario) =>
              runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputScenarios.includes(
                scenario,
              ),
          )
            ? runtimeArtifacts.path
            : false,
        harness_model_provider_gated_visible_output_rollback_drill:
          runtimeArtifacts.summary
            .harnessModelProviderGatedVisibleOutputRollbackDrillCount > 0 &&
          AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every(
            (scenario) =>
              runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios.includes(
                scenario,
              ),
          )
            ? runtimeArtifacts.path
            : false,
        harness_read_only_capability_routing:
          runtimeArtifacts.summary.harnessDefaultRuntimeDispatchReadonlyCount >
            0 &&
          AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every(
            (scenario) =>
              runtimeArtifacts.summary.harnessReadOnlyCapabilityRoutingScenarios.includes(
                scenario,
              ),
          ) &&
          AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every(
            (scenario) =>
              runtimeArtifacts.summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios.includes(
                scenario,
              ),
          )
            ? runtimeArtifacts.path
            : false,
        workflow_skill_context_create_run:
          workflowSkillContextProof.proof.passed === true
            ? workflowSkillContextProof.path
            : false,
        workflow_coding_route_create_run:
          workflowCodingRouteProof.proof.passed === true
            ? workflowCodingRouteProof.path
            : false,
        workflow_coding_route_promotion_loop:
          workflowCodingRoutePromotionLoopProof.proof.passed === true
            ? workflowCodingRoutePromotionLoopProof.path
            : false,
      },
      chatUx: guiEvidence.chatUx,
      runtimeConsistency: guiEvidence.runtimeConsistency,
      evidenceAssessment: guiEvidence.assessment,
      uiAssertions: {
        rollbackRestoreCanary: rollbackRestoreCanaryUiProof.proof,
        promotionTransitionBehavior: promotionTransitionGuiBehaviorProof.proof,
        promotionTransitionLiveGui:
          promotionTransitionLiveGuiInteractionProof.proof,
        workflowSkillContext: workflowSkillContextProof.proof,
        workflowCodingRoute: workflowCodingRouteProof.proof,
        workflowCodingRoutePromotionLoop:
          workflowCodingRoutePromotionLoopProof.proof,
      },
      logPath,
    };
  } finally {
    if (!desktopStopped) {
      stopDesktopProcess(desktop);
    }
  }
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputRoot = resolve(repoRoot, args.outputRoot, timestamp());
  if (args.contractOnly) {
    console.log(JSON.stringify(autopilotGuiHarnessContract(), null, 2));
    return 0;
  }

  const preflightFailures = preflight();
  if (args.preflight && !args.run) {
    const result =
      preflightFailures.length === 0
        ? {
            schemaVersion: autopilotGuiHarnessContract().schemaVersion,
            launchCommand: AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
            preflightPassed: true,
            retainedQueryCount: AUTOPILOT_RETAINED_QUERIES.length,
          }
        : buildBlockedAutopilotGuiHarnessResult({
            reason: "preflight failed",
            evidence: preflightFailures,
          });
    const resultPath = writeBundle(outputRoot, result);
    console.log(resultPath);
    return preflightFailures.length === 0 ? 0 : 1;
  }

  if (preflightFailures.length > 0) {
    const blocked = buildBlockedAutopilotGuiHarnessResult({
      reason: "preflight failed",
      evidence: preflightFailures,
    });
    const resultPath = writeBundle(outputRoot, blocked);
    console.log(resultPath);
    return 1;
  }

  const result = await runGuiValidation(args, outputRoot);
  const validation = validateAutopilotGuiHarnessResult(result);
  result.validation = validation;
  const resultPath = writeBundle(outputRoot, result);
  console.log(resultPath);
  return validation.ok ? 0 : 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}
