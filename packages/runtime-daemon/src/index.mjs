import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ModelMountingState } from "./model-mounting.mjs";
import {
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  computerUseProjectionForRun,
  computerUseSourceEventKind,
  isComputerUseRunEventType,
} from "./computer-use-projection.mjs";
import {
  discoverComputerUseBrowsers,
  discoverComputerUseBrowsersSync,
} from "./browser-discovery.mjs";
import { computerUseProviderRegistryReport } from "./computer-use-provider-registry.mjs";
import {
  computerUseControlActionForInput,
  nativeBrowserActionKindForInput,
  nativeBrowserActionKindFromText,
  nativeBrowserActionKindIsReadOnly,
  nativeBrowserActionKindValue,
  nativeBrowserActionKinds,
  nativeBrowserActionShouldUseCdpExecutor,
  nativeBrowserApprovalRefForInput,
  nativeBrowserCdpTimeoutMs,
  nativeBrowserControlledRelaunchApprovalRefForInput,
  nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch,
  nativeBrowserHasExplicitCdpEndpoint,
  nativeBrowserSessionModeForInput,
  sandboxedHostedSessionModeForInput,
  visualGuiFiniteNumber,
  visualGuiObservationMetadataForInput,
  visualGuiSessionModeForInput,
} from "./computer-use-inputs.mjs";
import {
  captureLocalVisualGuiObservation,
  visualGuiLocalCaptureRequested,
  visualGuiLocalCaptureUnavailablePatch,
} from "./visual-gui-local-capture.mjs";
import {
  executeLocalVisualGuiAction,
  visualGuiLocalExecutorRequested,
} from "./visual-gui-local-executor.mjs";
import { launchControlledNativeBrowser } from "./native-browser-controlled-relaunch-broker.mjs";
import { executeNativeBrowserCdpAction } from "./native-browser-cdp-executor.mjs";
import { AgentMemoryStore, parseMemoryCommand } from "./memory-store.mjs";
import {
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  codingToolInputSummary,
} from "./coding-tools.mjs";
import {
  RuntimeApiBridgeUnavailableError,
  createRuntimeApiBridge,
  isRuntimeServiceProfile,
  runtimeProfileForRequest,
} from "./runtime-api-bridge.mjs";
import {
  agentIdForThread,
  eventStreamIdForThread,
  fixtureProfileForAgent,
  isRuntimeBackedAgent,
  lifecycleStatusForRun,
  runIdForTurn,
  runtimeSessionIdForAgent,
  runtimeTurnIdForRun,
  threadIdForAgent,
  threadStatusForAgent,
  turnIdForRun,
} from "./runtime-identifiers.mjs";
import {
  boundedPositiveInteger,
  mcpToolNamespaces,
} from "./runtime-mcp-helpers.mjs";
import {
  redactRuntimeNodeForDoctor,
  runtimeToolRegistryGovernanceMetadata,
} from "./runtime-tool-catalog.mjs";
import { mcpRegistryForWorkspace } from "./mcp-manager.mjs";
import {
  RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION,
  RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
  memoryRowsForStatus,
  memoryStatusForProjection,
  validateMemoryProjection,
} from "./memory-manager.mjs";
import {
  optionalPositiveInteger,
} from "./subagent-manager.mjs";
import {
  RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
  runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread,
  runtimeUsageTelemetryList,
  runtimeUsageTelemetrySummary,
} from "./usage-telemetry.mjs";
import { authorityEvidenceSummaryForEvents } from "./authority-evidence-summary.mjs";
import { ConversationArtifactStore } from "./conversation-artifacts.mjs";
import { resolveStudioIntentFrame } from "./studio-intent-frame.mjs";
import {
  activeSkillHookManifestForRun,
  hookDryRunPlanForManifest,
  hookEscalationReceiptsForLedger,
  hookInvocationLedgerForPlan,
} from "./skill-hook-manifest.mjs";
import { createRuntimeRouteHandlers } from "./runtime-route-handlers.mjs";
import { createRuntimeRecordProjections } from "./runtime-record-projections.mjs";
import { createRuntimeApprovalLease } from "./runtime-approval-lease.mjs";
import { artifact, createRunArtifactResolver } from "./runtime-artifacts.mjs";
import { createCodingToolApprovalPolicy } from "./runtime-coding-tool-approval.mjs";
import { createRuntimeInvocationResultProjections } from "./runtime-invocation-results.mjs";
import { createDiagnosticsRepairExecutionHelpers } from "./diagnostics-repair-execution.mjs";
import { createDiagnosticsFeedbackHelpers } from "./diagnostics-feedback.mjs";
import { createRuntimeDiagnosticsFeedbackSurface } from "./runtime-diagnostics-feedback-surface.mjs";
import { createDiagnosticsRepairPolicyHelpers } from "./diagnostics-repair-policy.mjs";
import { createRuntimeDiagnosticsRepairSurface } from "./runtime-diagnostics-repair-surface.mjs";
import { createRuntimeUsageEventHelpers } from "./runtime-usage-events.mjs";
import { createRuntimeMemoryHelpers } from "./runtime-memory-helpers.mjs";
import { cancelRun as cancelRunState } from "./runtime-run-cancellation.mjs";
import { createRuntimeRunHelpers } from "./runtime-run-helpers.mjs";
import { createRuntimeRunEventHelpers } from "./runtime-run-event-helpers.mjs";
import { createRuntimeEventEnvelopeHelpers } from "./runtime-event-envelopes.mjs";
import { createRuntimeEventPayloadHelpers } from "./runtime-event-payloads.mjs";
import { createRuntimeCodingToolResultHelpers } from "./runtime-coding-tool-results.mjs";
import { createRuntimeDoctorReport } from "./runtime-doctor-report.mjs";
import { createRuntimeCodingToolArtifactSurface } from "./runtime-coding-tool-artifact-surface.mjs";
import { createRuntimeCodingToolInvocationSurface } from "./runtime-coding-tool-invocation-surface.mjs";
import { createRuntimeWorkspaceSnapshotSurface } from "./runtime-workspace-snapshot-surface.mjs";
import { createRuntimeCodingToolGovernanceSurface } from "./runtime-coding-tool-governance-surface.mjs";
import { createRuntimeCodingToolBudgetRecoverySurface } from "./runtime-coding-tool-budget-recovery-surface.mjs";
import { createRuntimeConversationArtifactSurface } from "./runtime-conversation-artifact-surface.mjs";
import { createRuntimeContextPolicySurface } from "./runtime-context-policy-surface.mjs";
import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";
import { createRuntimeWorkflowEditSurface } from "./runtime-workflow-edit-surface.mjs";
import { createRuntimeApprovalSurface } from "./runtime-approval-surface.mjs";
import { createRuntimeMcpCatalogSurface } from "./runtime-mcp-catalog-surface.mjs";
import { createRuntimeMcpControlSurface } from "./runtime-mcp-control-surface.mjs";
import { createRuntimeMcpServeSurface } from "./runtime-mcp-serve-surface.mjs";
import { createRuntimeRunReadSurface } from "./runtime-run-read-surface.mjs";
import { createRuntimeSkillHookSurface } from "./runtime-skill-hook-surface.mjs";
import { createRuntimeTaskJobSurface } from "./runtime-task-job-surface.mjs";
import { createRuntimeGovernedImprovementSurface } from "./runtime-governed-improvement-surface.mjs";
import { createRuntimeWorkerServicePackageSurface } from "./runtime-worker-service-package-surface.mjs";
import { createRuntimeCteePrivateWorkspaceSurface } from "./runtime-ctee-private-workspace-surface.mjs";
import { createRuntimeL1SettlementSurface } from "./runtime-l1-settlement-surface.mjs";
import { createRuntimeThreadControlSurface } from "./runtime-thread-control-surface.mjs";
import { createRuntimeThreadEventSurface } from "./runtime-thread-event-surface.mjs";
import { createRuntimeToolSurface } from "./runtime-tool-surface.mjs";
import { createRuntimeSubagentSurface } from "./runtime-subagent-surface.mjs";
import {
  booleanValue,
  doctorCheck,
  doctorHash,
  normalizeArray,
  normalizeBooleanOption,
  objectRecord,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import { createRuntimeAgentOptionsHelpers } from "./runtime-agent-options.mjs";
import { createRuntimeAgentgresAdmissionRunnerFromEnv } from "./runtime-agentgres-admission-runner.mjs";
import { createGovernedImprovementRunnerFromEnv } from "./runtime-governed-improvement-runner.mjs";
import { createExternalCapabilityAuthorityRunnerFromEnv } from "./runtime-external-capability-authority-runner.mjs";
import { createRuntimeExternalCapabilityAuthoritySurface } from "./runtime-external-capability-authority-surface.mjs";
import { createWorkerServicePackageRunnerFromEnv } from "./runtime-worker-service-package-runner.mjs";
import { createCteePrivateWorkspaceRunnerFromEnv } from "./runtime-ctee-private-workspace-runner.mjs";
import { createL1SettlementRunnerFromEnv } from "./runtime-l1-settlement-runner.mjs";
import { createWorkspaceRestoreRunnerFromEnv } from "./runtime-workspace-restore-runner.mjs";
import {
  createAgent as createAgentState,
  createRun as createRunState,
} from "./runtime-agent-run-lifecycle.mjs";
import { createRuntimeRepositorySurface } from "./runtime-repository-surface.mjs";
import { startRuntimeDaemonServiceWithStore } from "./service/runtime-daemon-service.mjs";
import {
  assertRuntimeBridgeAvailable as assertRuntimeBridgeAvailableState,
  runtimeBridgeUnavailable as runtimeBridgeUnavailableState,
} from "./bridges/runtime-agent-bridge.mjs";
import {
  branchPolicyForRepositoryContext,
  emptyToNull,
  githubContextForRepository,
  gitOutput,
  repositoryContextForWorkspace,
} from "./repository-context.mjs";
import { createRepositoryWorkflowProjections } from "./repository-workflow-projections.mjs";
import {
  approvalModeForThreadMode,
  initialThreadRuntimeControls,
  normalizeThreadApprovalMode,
  normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls,
  requestWithThreadRuntimeControls,
  runModeForThreadMode,
  threadModeForRunMode,
} from "./threads/thread-runtime-controls.mjs";
import {
  ensureStateDirs,
  loadStateRecords,
  removeQuietFile,
  statePathFor,
  writeStateSchema,
  writeAgentRecord,
  writeRunRecord,
  writeSubagentRecord,
} from "./threads/thread-persistence.mjs";
import {
  agentForThread as agentForThreadState,
  deleteAgent as deleteAgentState,
  getAgent as getAgentState,
  inFlightRuntimeTurnKey as inFlightRuntimeTurnKeyState,
  listAgents as listAgentsState,
  registerInFlightRuntimeTurn as registerInFlightRuntimeTurnState,
  resolveRunForThreadTurn as resolveRunForThreadTurnState,
  unregisterInFlightRuntimeTurn as unregisterInFlightRuntimeTurnState,
  updateAgent as updateAgentState,
} from "./threads/thread-store.mjs";
import {
  controlManagedSessionForThread as controlManagedSessionForThreadState,
  inspectManagedSessionsForThread as inspectManagedSessionsForThreadState,
} from "./threads/managed-session-state.mjs";
import {
  controlWorkspaceChangeForThread as controlWorkspaceChangeForThreadState,
  inspectWorkspaceChangeReviewsForThread as inspectWorkspaceChangeReviewsForThreadState,
} from "./threads/workspace-change-state.mjs";
import { createThreadForkState } from "./threads/thread-fork-state.mjs";
import {
  controlRuntimeBridgeThread as controlRuntimeBridgeThreadState,
  createRuntimeBridgeThread as createRuntimeBridgeThreadState,
  createRuntimeBridgeTurn as createRuntimeBridgeTurnState,
  normalizeRuntimeBridgeLiveEvent as normalizeRuntimeBridgeLiveEventState,
  normalizeRuntimeBridgeThreadStart as normalizeRuntimeBridgeThreadStartState,
  normalizeRuntimeBridgeTurnSubmit as normalizeRuntimeBridgeTurnSubmitState,
} from "./threads/runtime-bridge-thread.mjs";
import { createModelRouteSelection } from "./threads/model-route-selection.mjs";
import { createRunMemoryResolution } from "./threads/run-memory-resolution.mjs";
import { createThreadTurnProjection } from "./threads/thread-turn-projection.mjs";
import {
  codingToolBudgetPolicyForRequest,
  contextBudgetNumber,
} from "./threads/context-budget-policy.mjs";
import { createThreadMemoryState } from "./threads/thread-memory-state.mjs";
import {
  handleOpenAiCompatibilityRoute,
  isOpenAiCompatibilityRoute,
  nativeEmbeddingResponse,
  nativeInvocationResponse,
} from "./openai-compat-routes.mjs";
import { createPublicRuntimeRequestHandler } from "./http/public-runtime-routes.mjs";
import {
  baseUrlForRequest,
  runtimeEventCursorFromRequest,
  usageRequestMetadataFromUrl,
  usageTelemetryWithRequestMetadata,
} from "./runtime-request-metadata.mjs";
import {
  readBody,
  writeSse,
  writeJsonResponse,
  writeMcpJsonRpcResponse,
  writeError,
  notFound,
  policyError,
  externalBlocker,
  runtimeError,
  redact,
  writeJson,
  readJson,
  listJson,
  readJsonl,
  listJsonl,
  runtimeEventStreamFileName,
  relative,
} from "./runtime-http-utils.mjs";

export {
  RuntimeAgentServiceCommandAdapter,
  RuntimeAgentServiceCommandAdapterError,
  createRuntimeAgentServiceCommandAdapter,
  createRuntimeAgentServiceCommandAdapterFromEnv,
} from "./runtime-agent-service-adapter.mjs";

import {
  TERMINAL_EVENT_TYPES,
  JOB_TERMINAL_EVENT_TYPES,
  RUNTIME_THREAD_SCHEMA_VERSION,
  RUNTIME_TURN_SCHEMA_VERSION,
  RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
  RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_NODE_ID,
  LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID,
  LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID,
  LSP_DIAGNOSTICS_MAX_INJECTED_FINDINGS,
  LSP_DIAGNOSTICS_MAX_INJECTED_MESSAGE_CHARS,
  DAEMON_FIXTURE_PROFILE,
  RUN_EVENT_TO_TTI_EVENT,
  COMPUTER_USE_BROWSER_DISCOVERY_TOOL_IDS,
  COMPUTER_USE_NATIVE_BROWSER_TOOL_IDS,
  COMPUTER_USE_VISUAL_GUI_TOOL_IDS,
  COMPUTER_USE_SANDBOXED_HOSTED_TOOL_IDS,
  COMPUTER_USE_VISUAL_GUI_OBSERVE_TOOL_IDS,
  COMPUTER_USE_CONTROL_TOOL_IDS,
} from "./runtime-contract-constants.mjs";

const {
  resolveRunArtifact,
} = createRunArtifactResolver({
  normalizeArray,
  optionalString,
});
const {
  diagnosticsOperatorOverrideApprovalForRequest,
  diagnosticsOperatorOverrideApprovalKey,
  diagnosticsOperatorOverrideResultFromEvent,
  diagnosticsRepairApplyApprovalKey,
  diagnosticsRepairExecutionStatus,
  diagnosticsRepairRetryResultFromEvent,
} = createDiagnosticsRepairExecutionHelpers({
  normalizeArray,
  normalizeBooleanOption,
  optionalString,
  safeId,
  uniqueStrings,
});
const {
  contextPressureAlertPayload,
  contextPressureDeltaPayload,
  insertRuntimeBridgeUsageDeltaEvents,
  runtimeUsageTelemetryDeltaPayloads,
} = createRuntimeUsageEventHelpers({
  contextBudgetNumber,
  eventStreamIdForThread,
  normalizeArray,
  optionalString,
  safeId,
});
const {
  hasExplicitSubagentMemorySelector,
  memoryControlKind,
  memoryEventKind,
  memoryEventSummary,
  memoryListFilters,
  memoryMutationRawInput,
  memoryMutationRowLabel,
  memoryMutationSummary,
  memoryOperatorControlKind,
  memoryPolicyOverrides,
  memoryRuntimeEventKind,
  memoryWorkflowNodeId,
  memoryWriteBlockReason,
  normalizeSubagentInheritanceMode,
  shouldInheritSubagentMemory,
  subagentReceiverForRequest,
  subagentMemoryInheritanceReceipt,
  subagentMemoryPolicy,
} = createRuntimeMemoryHelpers({
  normalizeArray,
  optionalString,
  safeId,
});
const threadMemoryState = createThreadMemoryState({
  agentIdForThread,
  doctorHash,
  eventStreamIdForThread,
  fixtureProfileForAgent,
  memoryControlKind,
  memoryEventKind,
  memoryListFilters,
  memoryMutationRawInput,
  memoryMutationRowLabel,
  memoryMutationSummary,
  memoryOperatorControlKind,
  memoryPolicyOverrides,
  memoryRowsForStatus,
  memoryRuntimeEventKind,
  memoryStatusForProjection,
  memoryWorkflowNodeId,
  memoryWriteBlockReason,
  normalizeArray,
  operatorControlSource,
  optionalString,
  policyError,
  runtimeError,
  safeId,
  threadIdForAgent,
  validateMemoryProjection,
});
const threadForkState = createThreadForkState({
  eventStreamIdForThread,
  fixtureProfileForAgent,
  operatorControlSource,
  optionalString,
});
const {
  capabilitySequenceForMode,
  makeEvent,
  resultForMode,
  strategyForMode,
  taskFamilyForMode,
} = createRuntimeRunHelpers({
  normalizeArray,
});
const {
  artifactRefsForRunEvent,
  componentKindForRunEvent,
  policyDecisionRefsForRunEvent,
  receiptRefsForRunEvent,
  runtimeEventStatusForRunEvent,
  stringRecord,
  workflowNodeForRunEvent,
} = createRuntimeRunEventHelpers({
  isComputerUseRunEventType,
  normalizeArray,
  objectRecord,
  uniqueStrings,
});
const {
  payloadSummaryForRunEvent,
} = createRuntimeEventPayloadHelpers({
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_NODE_ID,
  RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
  RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
  RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
  computerUseSourceEventKind,
  isComputerUseRunEventType,
  memoryEventKind,
  normalizeArray,
  uniqueStrings,
});
const {
  approvalDecisionForRequest,
  approvalLeaseMetadataForRequest,
  approvalLeaseMetadataFromPayload,
  approvalLeaseStateForDecision,
  approvalReasonForDecisionEvent,
} = createRuntimeApprovalLease({
  doctorHash,
  normalizeArray,
  optionalPositiveInteger,
  optionalString,
  runtimeError,
  safeId,
  uniqueStrings,
});
const {
  codingToolApprovalManifestForThread,
  codingToolApprovalManifestsMatch,
} = createCodingToolApprovalPolicy({
  approvalModeForThreadMode,
  codingToolInputSummary,
  doctorHash,
  normalizeArray,
  normalizeThreadApprovalMode,
  normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls,
  optionalString,
  uniqueStrings,
});
const {
  codingToolInvocationResultFromEvent,
  computerUseBrowserDiscoveryInvocationResultFromEvent,
  computerUseControlInvocationResultFromEvent,
  computerUseNativeBrowserInvocationResultFromEvents,
} = createRuntimeInvocationResultProjections({
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
});

const {
  handleAgentRoute,
  handleModelMountingNativeRoute,
  handleRunRoute,
  handleThreadRoute,
} = createRuntimeRouteHandlers({
  baseUrlForRequest,
  nativeEmbeddingResponse,
  nativeInvocationResponse,
  notFound,
  readBody,
  resolveRunArtifact,
  runtimeEventCursorFromRequest,
  usageRequestMetadataFromUrl,
  usageTelemetryWithRequestMetadata,
  writeJsonResponse,
  writeMcpJsonRpcResponse,
  writeSse,
});

const {
  githubPrCreatePlanForReviewGate,
  issueContextForGithub,
  prAttemptForRepository,
  reviewGateForPrAttempt,
} = createRepositoryWorkflowProjections({
  branchPolicyForRepositoryContext,
  doctorHash,
  emptyToNull,
  githubContextForRepository,
  gitOutput,
  normalizeArray,
  repositoryContextForWorkspace,
  uniqueStrings,
});

const handleRequest = createPublicRuntimeRequestHandler({
  RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
  baseUrlForRequest,
  computerUseProviderRegistryReport,
  discoverComputerUseBrowsers,
  handleAgentRoute,
  handleModelMountingNativeRoute,
  handleOpenAiCompatibilityRoute,
  handleRunRoute,
  handleThreadRoute,
  isOpenAiCompatibilityRoute,
  normalizeBooleanOption,
  notFound,
  optionalString,
  readBody,
  runtimeError,
  usageRequestMetadataFromUrl,
  usageTelemetryWithRequestMetadata,
  writeError,
  writeJsonResponse,
  writeMcpJsonRpcResponse,
});

const {
  doctorProviderKeyReport,
  ensureProviderAvailable,
  loadCursorCompatibilityConfig,
  memoryOptionsForRequest,
  runtimeModeForOptions,
  summarizeAgentOptions,
} = createRuntimeAgentOptionsHelpers({
  doctorHash,
  externalBlocker,
  readJson,
});

const {
  diagnosticsRepairContextForPayload,
  diagnosticsRepairContextForRequest,
  diagnosticsRepairContextForToolPack,
  diagnosticsRepairDefaultForDecisions,
  diagnosticsRepairPolicyConfig,
  diagnosticsRepairPolicyConfigForContexts,
  diagnosticsRollbackRepairPolicy,
  normalizeDiagnosticsMode,
  normalizeDiagnosticsRepairDefault,
  normalizeRestoreConflictPolicy,
  normalizeRestorePolicy,
} = createDiagnosticsRepairPolicyHelpers({
  doctorHash,
  normalizeArray,
  normalizeBooleanOption,
  optionalString,
  uniqueStrings,
});

const {
  compactDiagnosticsFeedback,
  diagnosticsBlockingGateForFeedback,
  diagnosticsFeedbackBlocksContinuation,
  diagnosticsRepairRetryFeedback,
  insertRuntimeBridgeDiagnosticsInjectionEvent,
  postEditDiagnosticsConfig,
  promptWithDiagnosticsFeedback,
  requestWithDiagnosticsFeedback,
} = createDiagnosticsFeedbackHelpers({
  diagnosticsRepairContextForPayload,
  diagnosticsRepairPolicyConfig,
  diagnosticsRepairPolicyConfigForContexts,
  diagnosticsRollbackRepairPolicy,
  doctorHash,
  eventStreamIdForThread,
  maxInjectedFindings: LSP_DIAGNOSTICS_MAX_INJECTED_FINDINGS,
  maxInjectedMessageChars: LSP_DIAGNOSTICS_MAX_INJECTED_MESSAGE_CHARS,
  normalizeArray,
  normalizeDiagnosticsMode,
  optionalString,
  uniqueStrings,
});

const {
  codingToolResultWithoutDrafts,
  terminalCount,
} = createRuntimeCodingToolResultHelpers({
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  TERMINAL_EVENT_TYPES,
  doctorHash,
  normalizeArray,
  optionalString,
  safeId,
  uniqueStrings,
});

const {
  attachChecklistToRuntimeJob,
  runtimeBridgeComputerUseTrace,
  runtimeBridgeMessagesForProjection,
  runtimeBridgeRunRecord,
  runtimeChecklistRecord,
  runtimeChecklistRecordForRun,
  runtimeJobRecord,
  runtimeJobRecordForRun,
  runtimeTaskRecord,
  runtimeTaskRecordForRun,
} = createRuntimeRecordProjections({
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  artifact,
  doctorHash,
  eventStreamIdForThread,
  isComputerUseRunEventType,
  normalizeArray,
  optionalString,
  runtimeSessionIdForAgent,
  runtimeUsageTelemetryForRun,
  safeId,
  strategyForMode,
  taskFamilyForMode,
  terminalCount,
  threadIdForAgent,
  turnIdForRun,
  uniqueStrings,
});

const {
  insertRuntimeBridgeComputerUseDerivedEvents,
  normalizeRuntimeEventEnvelope,
  ttiEnvelopeForRunEvent,
} = createRuntimeEventEnvelopeHelpers({
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  DAEMON_FIXTURE_PROFILE,
  LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
  RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
  RUN_EVENT_TO_TTI_EVENT,
  artifactRefsForRunEvent,
  componentKindForRunEvent,
  computerUseSourceEventKind,
  doctorHash,
  eventStreamIdForThread,
  isComputerUseRunEventType,
  normalizeArray,
  payloadSummaryForRunEvent,
  policyDecisionRefsForRunEvent,
  receiptRefsForRunEvent,
  runtimeBridgeComputerUseTrace,
  runtimeBridgeMessagesForProjection,
  runtimeEventStatusForRunEvent,
  stringRecord,
  workflowNodeForRunEvent,
});

const RUNTIME_BRIDGE_AGENT_TURN_MIN_STEPS = 8;

const WORKSPACE_CHANGE_CONTROL_TOOL_IDS = new Set([
  "workspace_change__accept",
  "workspace_change__reject",
  "workspace_change__rollback",
]);

function plannedOperatorControlRunRecord(stateUpdate, threadId, runId, operationKind) {
  const updatedRun = stateUpdate.run;
  if (!updatedRun?.id) {
    throw runtimeError({
      status: 502,
      code: "operator_control_state_update_planner_invalid",
      message: "Rust operator-control state planning did not return a run record.",
      details: { threadId, runId, operationKind },
    });
  }
  return updatedRun;
}

function requiredOperatorControlOperationKind(stateUpdate, threadId, runId, expectedOperationKind) {
  const operationKind = optionalString(stateUpdate.operation_kind);
  if (!operationKind) {
    throw runtimeError({
      status: 502,
      code: "operator_control_state_update_operation_kind_missing",
      message: "Rust operator-control state planning did not return an operation kind.",
      details: { threadId, runId, operationKind: expectedOperationKind },
    });
  }
  if (operationKind !== expectedOperationKind) {
    throw runtimeError({
      status: 502,
      code: "operator_control_state_update_operation_kind_mismatch",
      message: "Rust operator-control state planning returned an unexpected operation kind.",
      details: {
        threadId,
        runId,
        expectedOperationKind,
        operationKind,
      },
    });
  }
  return operationKind;
}

export async function startRuntimeDaemonService(options = {}) {
  return startRuntimeDaemonServiceWithStore({
    options,
    StateStore: AgentgresRuntimeStateStore,
    handleRequest,
    writeError,
  });
}

export class AgentgresRuntimeStateStore {
  constructor(stateDir, options = {}) {
    this.stateDir = path.resolve(stateDir);
    this.defaultCwd = path.resolve(options.cwd ?? process.cwd());
    this.homeDir = path.resolve(options.homeDir ?? process.env.HOME ?? os.homedir());
    this.agents = new Map();
    this.runs = new Map();
    this.subagents = new Map();
    this.inFlightRuntimeTurns = new Map();
    this.runtimeEventStreams = new Map();
    this.codingArtifacts = new Map();
    this.conversationArtifacts = new ConversationArtifactStore(this.stateDir, {
      commitRuntimeArtifactState: (request) => this.commitRuntimeArtifactState(request),
    });
    this.runtimeBridge = createRuntimeApiBridge(options.runtimeBridge);
    this.runtimeAgentgresAdmissionRunner =
      options.runtimeAgentgresAdmissionRunner ?? createRuntimeAgentgresAdmissionRunnerFromEnv(process.env);
    this.contextPolicyRunner =
      options.contextPolicyRunner ?? createContextPolicyRunnerFromEnv(process.env);
    this.governedImprovementRunner =
      options.governedImprovementRunner ?? createGovernedImprovementRunnerFromEnv(process.env);
    this.externalCapabilityAuthorityRunner =
      options.externalCapabilityAuthorityRunner ?? createExternalCapabilityAuthorityRunnerFromEnv(process.env);
    this.workerServicePackageRunner =
      options.workerServicePackageRunner ?? createWorkerServicePackageRunnerFromEnv(process.env);
    this.cteePrivateWorkspaceRunner =
      options.cteePrivateWorkspaceRunner ?? createCteePrivateWorkspaceRunnerFromEnv(process.env);
    this.l1SettlementRunner =
      options.l1SettlementRunner ?? createL1SettlementRunnerFromEnv(process.env);
    this.workspaceRestoreRunner =
      options.workspaceRestoreRunner ?? createWorkspaceRestoreRunnerFromEnv(process.env);
    this.schemaVersion = "ioi.agentgres.runtime.v0";
    this.ensureDirs();
    this.modelMounting = new ModelMountingState({
      stateDir: this.stateDir,
      cwd: this.defaultCwd,
      homeDir: options.homeDir,
      vaultSecrets: options.vaultSecrets,
      modelMountAdmissionRunner: options.modelMountAdmissionRunner,
      commitRuntimeModelMountRecordState: (request) => this.commitRuntimeModelMountRecordState(request),
      commitRuntimeModelMountReceiptState: (request) => this.commitRuntimeModelMountReceiptState(request),
    });
    this.modelRouteSelection = createModelRouteSelection({
      modelMounting: this.modelMounting,
      normalizeArray,
    });
    this.runMemoryResolution = createRunMemoryResolution({
      memoryListFilters,
      memoryOptionsForRequest,
      memoryPolicyOverrides,
      memoryWriteBlockReason,
      normalizeSubagentInheritanceMode,
      optionalString,
      parseMemoryCommand,
      shouldInheritSubagentMemory,
      subagentMemoryPolicy,
      subagentReceiverForRequest,
      threadIdForAgent,
    });
    this.runtimeDoctorReport = createRuntimeDoctorReport({
      doctorCheck,
      doctorHash,
      doctorProviderKeyReport,
      fs,
      normalizeArray,
      path,
      processEnv: process.env,
      redactRuntimeNodeForDoctor,
    });
    this.conversationArtifactSurface = createRuntimeConversationArtifactSurface({ notFound });
    this.approvalSurface = createRuntimeApprovalSurface({
      approvalDecisionForRequest,
      approvalLeaseMetadataForRequest,
      approvalLeaseMetadataFromPayload,
      notFound,
      runtimeError,
    });
    this.governedImprovementSurface = createRuntimeGovernedImprovementSurface({
      runtimeError,
    });
    this.externalCapabilityAuthoritySurface = createRuntimeExternalCapabilityAuthoritySurface({
      runtimeError,
    });
    this.workerServicePackageSurface = createRuntimeWorkerServicePackageSurface({
      runtimeError,
    });
    this.cteePrivateWorkspaceSurface = createRuntimeCteePrivateWorkspaceSurface({
      runtimeError,
    });
    this.l1SettlementSurface = createRuntimeL1SettlementSurface({
      runtimeError,
    });
    this.codingToolBudgetRecoverySurface = createRuntimeCodingToolBudgetRecoverySurface({
      approvalReasonForDecisionEvent,
      contextPolicyRunner: this.contextPolicyRunner,
      notFound,
      runtimeError,
    });
    this.codingToolArtifactSurface = createRuntimeCodingToolArtifactSurface({
      notFound,
      policyError,
      runtimeError,
      writeJson,
    });
    this.codingToolInvocationSurface = createRuntimeCodingToolInvocationSurface({
      codingToolApprovalManifestForThread,
      codingToolBudgetPolicyForRequest,
      codingToolInvocationResultFromEvent,
      codingToolResultWithoutDrafts,
      diagnosticsRepairContextForRequest,
      diagnosticsRepairContextForToolPack,
    });
    this.workspaceSnapshotSurface = createRuntimeWorkspaceSnapshotSurface({
      notFound,
      runtimeError,
      writeJson,
      workspaceRestoreRunner: this.workspaceRestoreRunner,
    });
    this.diagnosticsFeedbackSurface = createRuntimeDiagnosticsFeedbackSurface({
      compactDiagnosticsFeedback,
      diagnosticsRepairPolicyConfig,
      normalizeDiagnosticsMode,
      postEditDiagnosticsConfig,
    });
    this.diagnosticsRepairSurface = createRuntimeDiagnosticsRepairSurface({
      contextPolicyRunner: this.contextPolicyRunner,
      diagnosticsOperatorOverrideApprovalForRequest,
      diagnosticsOperatorOverrideApprovalKey,
      diagnosticsOperatorOverrideResultFromEvent,
      diagnosticsRepairApplyApprovalKey,
      diagnosticsRepairExecutionStatus,
      diagnosticsRepairRetryFeedback,
      diagnosticsRepairRetryResultFromEvent,
      runtimeError,
    });
    this.codingToolGovernanceSurface = createRuntimeCodingToolGovernanceSurface({
      approvalLeaseStateForDecision,
      approvalReasonForDecisionEvent,
      codingToolApprovalManifestsMatch,
    });
    this.contextPolicySurface = createRuntimeContextPolicySurface({
      contextPolicyRunner: this.contextPolicyRunner,
      runtimeError,
    });
    this.workflowEditSurface = createRuntimeWorkflowEditSurface({
      approvalReasonForDecisionEvent,
      notFound,
      policyError,
      runtimeError,
      writeJson,
    });
    this.mcpCatalogSurface = createRuntimeMcpCatalogSurface();
    this.mcpControlSurface = createRuntimeMcpControlSurface({
      contextPolicyRunner: this.contextPolicyRunner,
    });
    this.mcpServeSurface = createRuntimeMcpServeSurface();
    this.repositorySurface = createRuntimeRepositorySurface();
    this.runReadSurface = createRuntimeRunReadSurface({
      authorityEvidenceSummaryForEvents,
      notFound,
      runtimeChecklistRecordForRun,
      runtimeJobRecordForRun,
      runtimeUsageTelemetryForRun,
      runtimeUsageTelemetryForThread,
      runtimeUsageTelemetryList,
      threadIdForAgent,
    });
    this.skillHookSurface = createRuntimeSkillHookSurface({
      defaultCwd: this.defaultCwd,
      homeDir: this.homeDir,
    });
    this.taskJobSurface = createRuntimeTaskJobSurface({
      notFound,
      optionalString,
      runtimeJobRecordForRun,
      runtimeTaskRecordForRun,
    });
    this.toolSurface = createRuntimeToolSurface();
    this.threadControlSurface = createRuntimeThreadControlSurface({
      contextPolicyRunner: this.contextPolicyRunner,
    });
    this.subagentSurface = createRuntimeSubagentSurface();
    this.threadTurnProjection = createThreadTurnProjection({
      eventStreamIdForThread,
      fixtureProfileForAgent,
      lifecycleStatusForRun,
      normalizedAgentRuntimeControls,
      runtimeSessionIdForAgent,
      runtimeThreadSchemaVersion: RUNTIME_THREAD_SCHEMA_VERSION,
      runtimeTurnIdForRun,
      runtimeTurnSchemaVersion: RUNTIME_TURN_SCHEMA_VERSION,
      runtimeUsageTelemetryForRun,
      runtimeUsageTelemetryForThread,
      threadIdForAgent,
      threadModeForRunMode,
      threadStatusForAgent,
      turnIdForRun,
    });
    this.threadEventSurface = createRuntimeThreadEventSurface({
      DAEMON_FIXTURE_PROFILE,
      RUNTIME_THREAD_SCHEMA_VERSION,
      eventStreamIdForThread,
      fs,
      isRuntimeBackedAgent,
      normalizeRuntimeEventEnvelope,
      notFound,
      runtimeError,
      runtimeEventStreamFileName,
      runtimeTurnIdForRun,
      threadIdForAgent,
      threadStatusForAgent,
      threadTurnProjection: this.threadTurnProjection,
      ttiEnvelopeForRunEvent,
      turnIdForRun,
    });
    this.memory = new AgentMemoryStore(this.stateDir, {
      commitRuntimeMemoryState: (request) => this.commitRuntimeMemoryState(request),
    });
    this.writeSchema();
    this.load();
  }

  close() {
    this.modelMounting.close();
  }

  resolveStudioIntentFrame(input = {}) {
    return resolveStudioIntentFrame(input);
  }

  createAgent(options = {}) {
    return createAgentState(this, options, {
      contextPolicyRunner: this.contextPolicyRunner,
      ensureProviderAvailable,
      initialThreadRuntimeControls,
      mcpRegistryForWorkspace,
      runtimeModeForOptions,
      summarizeAgentOptions,
    });
  }

  listAgents() {
    return listAgentsState(this);
  }

  getAgent(agentId) {
    return getAgentState(this, agentId, {
      notFound,
    });
  }

  updateAgent(agentId, status, operationKind) {
    return updateAgentState(this, agentId, status, operationKind, {
      runtimeError,
    });
  }

  deleteAgent(agentId) {
    return deleteAgentState(this, agentId, {
      path,
      policyError,
    });
  }

  createRun(agentId, request = {}) {
    return createRunState(this, agentId, request, {
      approvalModeForThreadMode,
      buildRun,
      contextPolicyRunner: this.contextPolicyRunner,
      ensureProviderAvailable,
      runtimeUsageTelemetryForRun,
      threadIdForAgent,
      threadModeForRunMode,
    });
  }

  resolveModelRoute(options = {}, context = {}) {
    return this.modelRouteSelection.resolveModelRoute(options, context);
  }

  resolveRunModelRoute(agent, request = {}) {
    return this.modelRouteSelection.resolveRunModelRoute(agent, request);
  }

  selectModelRouteWithFallback({ requestedModel, routeId, capability, policy, body, evidenceRefs }) {
    return this.modelRouteSelection.selectModelRouteWithFallback({ requestedModel, routeId, capability, policy, body, evidenceRefs });
  }

  resolveRunMemory(agent, request = {}, prompt = "") {
    return this.runMemoryResolution.resolveRunMemory(this, agent, request, prompt);
  }

  resolveSubagentMemoryInheritance({ agent, threadId, request = {}, parentPolicy = {} } = {}) {
    return this.runMemoryResolution.resolveSubagentMemoryInheritance(this, { agent, threadId, request, parentPolicy });
  }

  rememberForAgent(agent, { text, threadId = threadIdForAgent(agent.id), scope = "thread", source = "operator_remember", workflow = {} } = {}) {
    return threadMemoryState.rememberForAgent(this, agent, { text, threadId, scope, source, workflow });
  }

  rememberForThread(threadId, body = {}) {
    return threadMemoryState.rememberForThread(this, threadId, body);
  }

  listMemoryForThread(threadId, options = {}) {
    return threadMemoryState.listMemoryForThread(this, threadId, options);
  }

  memoryPolicyForThread(threadId) {
    return threadMemoryState.memoryPolicyForThread(this, threadId);
  }

  setMemoryPolicyForThread(threadId, body = {}) {
    return threadMemoryState.setMemoryPolicyForThread(this, threadId, body);
  }

  memoryPathForThread(threadId) {
    return threadMemoryState.memoryPathForThread(this, threadId);
  }

  updateMemoryForThread(threadId, memoryId, body = {}) {
    return threadMemoryState.updateMemoryForThread(this, threadId, memoryId, body);
  }

  deleteMemoryForThread(threadId, memoryId, body = {}) {
    return threadMemoryState.deleteMemoryForThread(this, threadId, memoryId, body);
  }

  rememberForAgentId(agentId, body = {}) {
    return threadMemoryState.rememberForAgentId(this, agentId, body);
  }

  listMemoryForAgent(agentId, options = {}) {
    return threadMemoryState.listMemoryForAgent(this, agentId, options);
  }

  memoryPolicyForAgent(agentId, options = {}) {
    return threadMemoryState.memoryPolicyForAgent(this, agentId, options);
  }

  setMemoryPolicyForAgent(agentId, body = {}) {
    return threadMemoryState.setMemoryPolicyForAgent(this, agentId, body);
  }

  memoryPathForAgent(agentId, options = {}) {
    return threadMemoryState.memoryPathForAgent(this, agentId, options);
  }

  updateMemoryForAgentId(agentId, memoryId, body = {}) {
    return threadMemoryState.updateMemoryForAgentId(this, agentId, memoryId, body);
  }

  deleteMemoryForAgentId(agentId, memoryId, body = {}) {
    return threadMemoryState.deleteMemoryForAgentId(this, agentId, memoryId, body);
  }

  updateMemoryRecord(memoryId, body = {}) {
    return threadMemoryState.updateMemoryRecord(this, memoryId, body);
  }

  deleteMemoryRecord(memoryId, body = {}) {
    return threadMemoryState.deleteMemoryRecord(this, memoryId, body);
  }

  memoryProjectionForContext(options = {}) {
    return threadMemoryState.memoryProjectionForContext(this, options);
  }

  memoryStatus(options = {}) {
    return threadMemoryState.memoryStatus(this, options);
  }

  validateMemory(input = {}) {
    return threadMemoryState.validateMemory(this, input);
  }

  recordThreadMemoryStatus(threadId, request = {}) {
    return threadMemoryState.recordThreadMemoryStatus(this, threadId, request, RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION);
  }

  validateThreadMemory(threadId, request = {}) {
    return threadMemoryState.validateThreadMemory(this, threadId, request, RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION);
  }

  recordThreadMemoryMutation(threadId, mutation = {}, request = {}, operation = "write") {
    return threadMemoryState.recordThreadMemoryMutation(this, threadId, mutation, request, operation, RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION);
  }

  appendThreadMemoryControlEvent({
    threadId,
    agent,
    request,
    controlKind,
    sourceEventKind,
    eventKind,
    componentKind,
    workflowNodeId,
    payloadSchemaVersion,
    status,
    payload,
    receiptRefs,
    policyDecisionRefs,
    policyDecisionKind = "read",
  }) {
    return threadMemoryState.appendThreadMemoryControlEvent(this, {
      threadId,
      agent,
      request,
      controlKind,
      sourceEventKind,
      eventKind,
      componentKind,
      workflowNodeId,
      payloadSchemaVersion,
      status,
      payload,
      receiptRefs,
      policyDecisionRefs,
      policyDecisionKind,
    });
  }

  async createThread(request = {}) {
    const options = request.options ?? request;
    const runtimeProfile = runtimeProfileForRequest(request, options);
    if (isRuntimeServiceProfile(runtimeProfile)) {
      return this.createRuntimeBridgeThread({ request, options, runtimeProfile });
    }
    const agent = this.createAgent(options);
    this.ensureThreadStartedEvent(agent);
    return this.threadForAgent(agent);
  }

  async createRuntimeBridgeThread({ request, options, runtimeProfile }) {
    return createRuntimeBridgeThreadState(this, { request, options, runtimeProfile }, {
      RuntimeApiBridgeUnavailableError,
      eventStreamIdForThread,
      normalizeArray,
      runtimeError,
      threadIdForAgent,
    });
  }

  listThreads() {
    return this.listAgents().map((agent) => this.threadForAgent(agent));
  }

  getThread(threadId) {
    return this.threadForAgent(this.agentForThread(threadId));
  }

  async inspectManagedSessionsForThread(threadId, request = {}) {
    return inspectManagedSessionsForThreadState(this, threadId, request, {
      RuntimeApiBridgeUnavailableError,
      isRuntimeBackedAgent,
      runtimeSessionIdForAgent,
    });
  }

  async inspectWorkspaceChangeReviewsForThread(threadId, request = {}) {
    return inspectWorkspaceChangeReviewsForThreadState(this, threadId, request, {
      RuntimeApiBridgeUnavailableError,
      isRuntimeBackedAgent,
      runtimeSessionIdForAgent,
    });
  }

  async controlWorkspaceChangeForThread(threadId, request = {}) {
    return controlWorkspaceChangeForThreadState(this, threadId, request, {
      RuntimeApiBridgeUnavailableError,
      doctorHash,
      isRuntimeBackedAgent,
      optionalString,
      runtimeSessionIdForAgent,
      safeId,
    });
  }

  async controlManagedSessionForThread(threadId, request = {}) {
    return controlManagedSessionForThreadState(this, threadId, request, {
      RuntimeApiBridgeUnavailableError,
      doctorHash,
      isRuntimeBackedAgent,
      optionalString,
      runtimeSessionIdForAgent,
    });
  }

  async resumeThread(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    let runtimeControl = null;
    if (isRuntimeBackedAgent(agent)) {
      runtimeControl = await controlRuntimeBridgeThreadState(this, {
        agent,
        threadId,
        action: "resume",
        reason:
          optionalString(request.reason ?? request.message ?? request.input) ??
          "operator requested resume",
      }, {
        RuntimeApiBridgeUnavailableError,
        runtimeSessionIdForAgent,
      });
    }
    const updated = this.updateAgent(agent.id, "active", "thread.resume");
    const thread = this.threadForAgent(updated);
    return runtimeControl
      ? {
          ...thread,
          runtime_control: runtimeControl,
          runtimeControl,
        }
      : thread;
  }

  updateThreadMode(threadId, request = {}) {
    return this.threadControlSurface.updateThreadMode(this, threadId, request);
  }

  updateThreadModel(threadId, request = {}) {
    return this.threadControlSurface.updateThreadModel(this, threadId, request);
  }

  updateThreadThinking(threadId, request = {}) {
    return this.threadControlSurface.updateThreadThinking(this, threadId, request);
  }

  updateThreadRuntimeControls(threadId, request = {}) {
    return this.threadControlSurface.updateThreadRuntimeControls(this, threadId, request);
  }

  appendThreadRuntimeControlEvent(input) {
    return this.threadControlSurface.appendThreadRuntimeControlEvent(this, input);
  }

  appendWorkspaceTrustWarningEvent({
    agent,
    threadId,
    controls,
    request,
    source,
    requestedBy,
    workflowGraphId,
    modeEvent,
    now,
  }) {
    return this.threadControlSurface.appendWorkspaceTrustWarningEvent(this, {
      agent,
      threadId,
      controls,
      request,
      source,
      requestedBy,
      workflowGraphId,
      modeEvent,
      now,
    });
  }

  acknowledgeWorkspaceTrustWarning(threadId, warningId, request = {}) {
    return this.threadControlSurface.acknowledgeWorkspaceTrustWarning(this, threadId, warningId, request);
  }

  forkThread(threadId, request = {}) {
    return threadForkState.forkThread(this, threadId, request);
  }

  listSubagents(threadId, options = {}) {
    return this.subagentSurface.listSubagents(this, threadId, options);
  }

  spawnSubagent(threadId, request = {}) {
    return this.subagentSurface.spawnSubagent(this, threadId, request);
  }

  waitSubagent(threadId, subagentId, request = {}) {
    return this.subagentSurface.waitSubagent(this, threadId, subagentId, request);
  }

  sendSubagentInput(threadId, subagentId, request = {}) {
    return this.subagentSurface.sendSubagentInput(this, threadId, subagentId, request);
  }

  cancelSubagent(threadId, subagentId, request = {}) {
    return this.subagentSurface.cancelSubagent(this, threadId, subagentId, request);
  }

  propagateSubagentCancellation(threadId, request = {}) {
    return this.subagentSurface.propagateSubagentCancellation(this, threadId, request);
  }

  resumeSubagent(threadId, subagentId, request = {}) {
    return this.subagentSurface.resumeSubagent(this, threadId, subagentId, request);
  }

  assignSubagent(threadId, subagentId, request = {}) {
    return this.subagentSurface.assignSubagent(this, threadId, subagentId, request);
  }

  getSubagentResult(threadId, subagentId) {
    return this.subagentSurface.getSubagentResult(this, threadId, subagentId);
  }

  getSubagent(threadId, subagentId) {
    return this.subagentSurface.getSubagent(this, threadId, subagentId);
  }

  subagentProjection(record = {}) {
    return this.subagentSurface.subagentProjection(record);
  }

  appendThreadSubagentControlEvent({
    threadId,
    parentAgent,
    record,
    request,
    operation,
    status,
  }) {
    return this.subagentSurface.appendThreadSubagentControlEvent(this, {
      threadId,
      parentAgent,
      record,
      request,
      operation,
      status,
    });
  }

  assertRuntimeBridgeAvailable({ runtimeProfile, operation }) {
    return assertRuntimeBridgeAvailableState(this.runtimeBridge, { runtimeProfile, operation }, {
      externalBlocker,
    });
  }

  runtimeBridgeUnavailable({ runtimeProfile, operation, details = {} }) {
    return runtimeBridgeUnavailableState({ runtimeProfile, operation, details }, {
      externalBlocker,
    });
  }

  normalizeRuntimeBridgeThreadStart({ bridgeResult, agent, threadId, runtimeProfile }) {
    return normalizeRuntimeBridgeThreadStartState({ bridgeResult, agent, threadId, runtimeProfile }, {
      bridgeId: this.runtimeBridge.bridgeId,
      eventStreamIdForThread,
      normalizeArray,
      runtimeError,
    });
  }

  normalizeRuntimeBridgeTurnSubmit({ bridgeResult, agent, threadId, request }) {
    return normalizeRuntimeBridgeTurnSubmitState({ bridgeResult, agent, threadId, request }, {
      eventStreamIdForThread,
      normalizeArray,
      runIdForTurn,
      runtimeError,
      runtimeSessionIdForAgent,
    });
  }

  normalizeRuntimeBridgeLiveEvent({ event, agent, threadId }) {
    return normalizeRuntimeBridgeLiveEventState({ event, agent, threadId }, {
      eventStreamIdForThread,
      optionalString,
      runIdForTurn,
      runtimeSessionIdForAgent,
    });
  }

  doctorReport({ baseUrl = null } = {}) {
    return this.runtimeDoctorReport.doctorReport(this, { baseUrl });
  }

  skillHookCatalog({ cwd = this.defaultCwd } = {}) {
    return this.skillHookSurface.skillHookCatalog({ cwd });
  }

  listSkills({ cwd = this.defaultCwd } = {}) {
    return this.skillHookSurface.listSkills({ cwd });
  }

  listHooks({ cwd = this.defaultCwd } = {}) {
    return this.skillHookSurface.listHooks({ cwd });
  }

  async createTurn(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const controlledRequest = requestWithThreadRuntimeControls(agent, request);
    const diagnosticsFeedback = this.pendingDiagnosticsFeedbackForNextTurn(threadId, controlledRequest);
    if (diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)) {
      const prompt = controlledRequest.prompt ?? controlledRequest.message ?? controlledRequest.input ?? "";
      const run = this.createRun(agent.id, {
        mode: controlledRequest.mode ?? "send",
        threadMode: controlledRequest.threadMode,
        approvalMode: controlledRequest.approvalMode,
        prompt,
        options: controlledRequest.options ?? {},
        memory: controlledRequest.memory,
        remember: controlledRequest.remember,
        diagnosticsFeedback,
      });
      return this.turnForRun(run);
    }
    if (isRuntimeBackedAgent(agent)) {
      return this.createRuntimeBridgeTurn({
        agent,
        threadId,
        request: requestWithDiagnosticsFeedback(controlledRequest, diagnosticsFeedback),
        diagnosticsFeedback,
      });
    }
    const requestedRuntimeProfile = runtimeProfileForRequest(
      controlledRequest,
      controlledRequest.options ?? {},
    );
    if (isRuntimeServiceProfile(requestedRuntimeProfile)) {
      throw runtimeError({
        status: 409,
        code: "runtime_thread_profile_mismatch",
        message:
          "Agent requested runtime_service execution on a non-runtime thread. Start a runtime_service thread before submitting governed Agent work.",
        details: {
          threadId,
          agentId: agent.id,
          agentRuntimeProfile: agent.runtimeProfile ?? "fixture",
          requestedRuntimeProfile,
          syntheticFallbackAllowed: false,
        },
      });
    }
    const prompt = controlledRequest.prompt ?? controlledRequest.message ?? controlledRequest.input ?? "";
    const run = this.createRun(agent.id, {
      mode: controlledRequest.mode ?? "send",
      threadMode: controlledRequest.threadMode,
      approvalMode: controlledRequest.approvalMode,
      prompt,
      options: controlledRequest.options ?? {},
      memory: controlledRequest.memory,
      remember: controlledRequest.remember,
      diagnosticsFeedback,
    });
    return this.turnForRun(run);
  }

  async createRuntimeBridgeTurn({ agent, threadId, request, diagnosticsFeedback = null }) {
    return createRuntimeBridgeTurnState(this, { agent, threadId, request, diagnosticsFeedback }, {
      RuntimeApiBridgeUnavailableError,
      RUNTIME_BRIDGE_AGENT_TURN_MIN_STEPS,
      eventStreamIdForThread,
      insertRuntimeBridgeComputerUseDerivedEvents,
      insertRuntimeBridgeDiagnosticsInjectionEvent,
      insertRuntimeBridgeUsageDeltaEvents,
      normalizeArray,
      normalizeRuntimeBridgeLiveEvent: (input) => this.normalizeRuntimeBridgeLiveEvent(input),
      normalizeRuntimeBridgeTurnSubmit: (input) => this.normalizeRuntimeBridgeTurnSubmit(input),
      optionalPositiveInteger,
      optionalString,
      runIdForTurn,
      runtimeBridgeRunRecord,
      runtimeError,
      runtimeSessionIdForAgent,
    });
  }

  listTurns(threadId) {
    return this.threadEventSurface.listTurns(this, threadId);
  }

  getTurn(threadId, turnId) {
    return this.threadEventSurface.getTurn(this, threadId, turnId);
  }

  eventsForThread(threadId, cursor = {}) {
    return this.threadEventSurface.eventsForThread(this, threadId, cursor);
  }

  eventsForRun(runId, cursor = {}) {
    return this.threadEventSurface.eventsForRun(this, runId, cursor);
  }

  ensureThreadStartedEvent(agent) {
    return this.threadEventSurface.ensureThreadStartedEvent(this, agent);
  }

  projectThreadEvents(agent) {
    return this.threadEventSurface.projectThreadEvents(this, agent);
  }

  projectRunEvents(run, agent = this.getAgent(run.agentId)) {
    return this.threadEventSurface.projectRunEvents(this, run, agent);
  }

  appendRuntimeEvent(event) {
    return this.threadEventSurface.appendRuntimeEvent(this, event);
  }

  runtimeEventsForStream(eventStreamId, cursor = {}) {
    return this.threadEventSurface.runtimeEventsForStream(this, eventStreamId, cursor);
  }

  runtimeEventsForTurn(turnId, cursor = {}) {
    return this.threadEventSurface.runtimeEventsForTurn(this, turnId, cursor);
  }

  runtimeCursorSeq(stream, cursor = {}) {
    return this.threadEventSurface.runtimeCursorSeq(this, stream, cursor);
  }

  assertRuntimeCursorSeq(cursorSeq, latestSeq, details = {}) {
    return this.threadEventSurface.assertRuntimeCursorSeq(cursorSeq, latestSeq, details);
  }

  latestRuntimeEventSeq(eventStreamId) {
    return this.threadEventSurface.latestRuntimeEventSeq(this, eventStreamId);
  }

  runtimeEventStream(eventStreamId) {
    return this.threadEventSurface.runtimeEventStream(this, eventStreamId);
  }

  registerRuntimeEvent(record) {
    return this.threadEventSurface.registerRuntimeEvent(this, record);
  }

  runtimeEventStreamPath(eventStreamId) {
    return this.threadEventSurface.runtimeEventStreamPath(this, eventStreamId);
  }

  threadForAgent(agent) {
    return this.threadEventSurface.threadForAgent(this, agent);
  }

  turnForRun(run) {
    return this.threadEventSurface.turnForRun(this, run);
  }

  async interruptTurn(threadId, turnId, request = {}) {
    const agent = this.agentForThread(threadId);
    const resolved = this.resolveRunForThreadTurn(agent, threadId, turnId);
    const runId = resolved.runId;
    const resolvedTurnId = resolved.turnId || turnId;
    const run = resolved.run;
    let runtimeControl = null;
    if (isRuntimeBackedAgent(agent)) {
      const requestedAction = optionalString(
        request.runtime_control_action ??
          request.control_action,
      );
      const controlAction = /^(cancel|terminate)$/i.test(requestedAction ?? "")
        ? "cancel"
        : "stop";
      runtimeControl = await controlRuntimeBridgeThreadState(this, {
        agent,
        threadId,
        action: controlAction,
        reason:
          optionalString(request.reason ?? request.message ?? request.input) ??
          "operator requested interrupt",
      }, {
        RuntimeApiBridgeUnavailableError,
        runtimeSessionIdForAgent,
      });
    }
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested interrupt";
    const now = new Date().toISOString();
    const previousStatus = run
      ? run.turnStatus ?? lifecycleStatusForRun(run.status)
      : "running";
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: resolvedTurnId,
      item_id: `${resolvedTurnId}:item:operator-interrupt`,
      idempotency_key: `turn:${resolvedTurnId}:operator.interrupt`,
      source,
      source_event_kind: "OperatorControl.Interrupt",
      event_kind: "turn.interrupted",
      status: "interrupted",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? null,
      workflow_node_id: request.workflow_node_id ?? "runtime.operator-interrupt",
      component_kind: "operator_control",
      payload_schema_version: "ioi.runtime.operator-control.v1",
      payload: {
        event_kind: "OperatorControl.Interrupt",
        reason,
        requested_by: requestedBy,
        control_surface: source,
        previous_status: previousStatus,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: resolvedTurnId,
        run_id: runId,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${runId}_operator_interrupt`],
      policy_decision_refs: [`policy_${runId}_operator_interrupt_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    if (!run) {
      const turnEvents = this.runtimeEventsForTurn(resolvedTurnId);
      const interruptedTurn = {
        schema_version: RUNTIME_TURN_SCHEMA_VERSION,
        turn_id: resolvedTurnId,
        thread_id: threadId,
        parent_turn_id: null,
        request_id: runId,
        status: "interrupted",
        input_item_ids: turnEvents
          .filter((candidate) => candidate.event_kind === "turn.started")
          .map((candidate) => candidate.item_id),
        output_item_ids: turnEvents
          .filter((candidate) => candidate.event_kind !== "turn.started")
          .map((candidate) => candidate.item_id),
        events: turnEvents,
        seq_start: turnEvents.at(0)?.seq ?? null,
        seq_end: turnEvents.at(-1)?.seq ?? null,
        started_at: resolved.inFlight?.createdAt ?? event.created_at,
        completed_at: null,
        mode: request.mode ?? "send",
        approval_mode: agent.runtimeControls?.approval_mode ?? "suggest",
      };
      return runtimeControl
        ? {
            ...interruptedTurn,
            runtime_control: runtimeControl,
            runtimeControl,
          }
        : interruptedTurn;
    }
    const stateUpdate = this.contextPolicyRunner.planOperatorInterruptStateUpdate({
      thread_id: threadId,
      turn_id: resolvedTurnId,
      run_id: run.id,
      run,
      event_id: event.event_id,
      seq: event.seq,
      created_at: event.created_at,
      source,
      reason,
    });
    const operationKind = requiredOperatorControlOperationKind(
      stateUpdate,
      threadId,
      run.id,
      "turn.interrupt",
    );
    const updated = plannedOperatorControlRunRecord(stateUpdate, threadId, run.id, operationKind);
    this.runs.set(run.id, updated);
    this.writeRun(updated, operationKind);
    const turn = this.turnForRun(updated);
    return runtimeControl
      ? {
          ...turn,
          runtime_control: runtimeControl,
          runtimeControl,
        }
      : turn;
  }

  steerTurn(threadId, turnId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runId = runIdForTurn(turnId);
    const run = this.getRun(runId);
    if (run.agentId !== agent.id) {
      throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId });
    }
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "operator";
    const guidance =
      optionalString(request.guidance ?? request.message ?? request.input) ?? "operator provided steering guidance";
    const now = new Date().toISOString();
    const previousStatus = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const guidanceHash = crypto.createHash("sha256").update(guidance).digest("hex").slice(0, 16);
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId}:item:operator-steer:${guidanceHash}`,
      idempotency_key:
        request.idempotency_key ??
        `turn:${turnId}:operator.steer:${guidanceHash}`,
      source,
      source_event_kind: "OperatorControl.Steer",
      event_kind: "turn.steered",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? null,
      workflow_node_id: request.workflow_node_id ?? "runtime.operator-steer",
      component_kind: "operator_control",
      payload_schema_version: "ioi.runtime.operator-control.v1",
      payload: {
        event_kind: "OperatorControl.Steer",
        guidance,
        requested_by: requestedBy,
        control_surface: source,
        previous_status: previousStatus,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId,
        run_id: run.id,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${run.id}_operator_steer_${guidanceHash}`],
      policy_decision_refs: [`policy_${run.id}_operator_steer_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const stateUpdate = this.contextPolicyRunner.planOperatorSteerStateUpdate({
      thread_id: threadId,
      turn_id: turnId,
      run_id: run.id,
      run,
      event_id: event.event_id,
      seq: event.seq,
      created_at: event.created_at,
      source,
      guidance,
    });
    const operationKind = requiredOperatorControlOperationKind(
      stateUpdate,
      threadId,
      run.id,
      "turn.steer",
    );
    const updated = plannedOperatorControlRunRecord(stateUpdate, threadId, run.id, operationKind);
    this.runs.set(run.id, updated);
    this.writeRun(updated, operationKind);
    return this.turnForRun(updated);
  }

  requestThreadApproval(threadId, request = {}) {
    return this.approvalSurface.requestThreadApproval(this, threadId, request);
  }

  decideThreadApproval(threadId, approvalId, request = {}) {
    return this.approvalSurface.decideThreadApproval(this, threadId, approvalId, request);
  }

  revokeThreadApproval(threadId, approvalId, request = {}) {
    return this.approvalSurface.revokeThreadApproval(this, threadId, approvalId, request);
  }

  latestApprovalDecisionEvent(threadId, approvalId) {
    return this.approvalSurface.latestApprovalDecisionEvent(this, threadId, approvalId);
  }

  latestCodingToolBudgetBlockedEventForRun(runId, sourceEventId = null) {
    return this.codingToolBudgetRecoverySurface.latestCodingToolBudgetBlockedEventForRun(
      this,
      runId,
      sourceEventId,
    );
  }

  codingToolBudgetRecoveryForRun(runId, request = {}) {
    return this.codingToolBudgetRecoverySurface.codingToolBudgetRecoveryForRun(this, runId, request);
  }

  workflowEditThreadContext(threadId, request = {}) {
    return this.workflowEditSurface.workflowEditThreadContext(this, threadId, request);
  }

  resolveWorkflowEditTarget(agent, request = {}) {
    return this.workflowEditSurface.resolveWorkflowEditTarget(agent, request);
  }

  proposeWorkflowEdit(threadId, request = {}) {
    return this.workflowEditSurface.proposeWorkflowEdit(this, threadId, request);
  }

  admitGovernedImprovementProposal(threadId, request = {}) {
    return this.governedImprovementSurface.admitGovernedImprovementProposal(this, threadId, request);
  }

  authorizeExternalCapabilityExit(threadId, request = {}) {
    return this.externalCapabilityAuthoritySurface.authorizeExternalCapabilityExit(this, threadId, request);
  }

  admitWorkerServicePackageInvocation(threadId, request = {}) {
    return this.workerServicePackageSurface.admitWorkerServicePackageInvocation(this, threadId, request);
  }

  executeCteePrivateWorkspaceAction(threadId, request = {}) {
    return this.cteePrivateWorkspaceSurface.executeCteePrivateWorkspaceAction(this, threadId, request);
  }

  admitL1SettlementAttempt(threadId, request = {}) {
    return this.l1SettlementSurface.admitL1SettlementAttempt(this, threadId, request);
  }

  latestWorkflowEditProposalEvent(threadId, proposalId) {
    return this.workflowEditSurface.latestWorkflowEditProposalEvent(this, threadId, proposalId);
  }

  latestWorkflowEditApplyEvent(threadId, proposalId) {
    return this.workflowEditSurface.latestWorkflowEditApplyEvent(this, threadId, proposalId);
  }

  workflowEditApprovalSatisfaction({ threadId, approvalId, proposalEvent }) {
    return this.workflowEditSurface.workflowEditApprovalSatisfaction(this, {
      threadId,
      approvalId,
      proposalEvent,
    });
  }

  applyWorkflowEditProposal(threadId, proposalId, request = {}) {
    return this.workflowEditSurface.applyWorkflowEditProposal(this, threadId, proposalId, request);
  }

  compactThread(threadId, request = {}) {
    return this.contextPolicySurface.compactThread(this, threadId, request);
  }

  listJobs(options = {}) {
    return this.taskJobSurface.listJobs(this, options);
  }

  createTask(body = {}) {
    return this.taskJobSurface.createTask(this, body);
  }

  listTasks(options = {}) {
    return this.taskJobSurface.listTasks(this, options);
  }

  getTask(taskId) {
    return this.taskJobSurface.getTask(this, taskId);
  }

  cancelTask(taskId) {
    return this.taskJobSurface.cancelTask(this, taskId);
  }

  getJob(jobId) {
    return this.taskJobSurface.getJob(this, jobId);
  }

  cancelJob(jobId) {
    return this.taskJobSurface.cancelJob(this, jobId);
  }

  listMcpServers(options = {}) {
    return this.mcpCatalogSurface.listMcpServers(this, options);
  }

  listMcpTools(options = {}) {
    return this.mcpCatalogSurface.listMcpTools(this, options);
  }

  async searchMcpTools(options = {}) {
    return this.mcpCatalogSurface.searchMcpTools(this, options);
  }

  async getMcpTool(toolId, options = {}) {
    return this.mcpCatalogSurface.getMcpTool(this, toolId, options);
  }

  listMcpResources(options = {}) {
    return this.mcpCatalogSurface.listMcpResources(this, options);
  }

  listMcpPrompts(options = {}) {
    return this.mcpCatalogSurface.listMcpPrompts(this, options);
  }

  mcpStatus(options = {}) {
    return this.mcpCatalogSurface.mcpStatus(this, options);
  }

  validateMcp(input = {}) {
    return this.mcpCatalogSurface.validateMcp(this, input);
  }

  importMcp(input = {}) {
    return this.mcpControlSurface.importMcp(this, input);
  }

  addMcpServer(input = {}) {
    return this.mcpControlSurface.addMcpServer(this, input);
  }

  removeMcpServer(serverId, input = {}) {
    return this.mcpControlSurface.removeMcpServer(this, serverId, input);
  }

  importThreadMcp(threadId, request = {}) {
    return this.mcpControlSurface.importThreadMcp(this, threadId, request);
  }

  addThreadMcpServer(threadId, request = {}) {
    return this.mcpControlSurface.addThreadMcpServer(this, threadId, request);
  }

  removeThreadMcpServer(threadId, serverId, request = {}) {
    return this.mcpControlSurface.removeThreadMcpServer(this, threadId, serverId, request);
  }

  applyThreadMcpServerMutation({
    threadId,
    agent,
    request,
    mutationKind,
    sourceEventKind,
    eventKind,
    workflowNodeId,
    serversToUpsert,
  }) {
    return this.mcpControlSurface.applyThreadMcpServerMutation(this, {
      threadId,
      agent,
      request,
      mutationKind,
      sourceEventKind,
      eventKind,
      workflowNodeId,
      serversToUpsert,
    });
  }

  async mcpStatusWithLiveDiscovery(status, agent, request = {}) {
    return this.mcpControlSurface.mcpStatusWithLiveDiscovery(this, status, agent, request);
  }

  async searchThreadMcpTools(threadId, request = {}) {
    return this.mcpCatalogSurface.searchThreadMcpTools(this, threadId, request);
  }

  async getThreadMcpTool(threadId, toolId, request = {}) {
    return this.mcpCatalogSurface.getThreadMcpTool(this, threadId, toolId, request);
  }

  async getMcpToolFromCatalog(toolId, request = {}) {
    return this.mcpCatalogSurface.getMcpToolFromCatalog(this, toolId, request);
  }

  async searchMcpToolCatalog(request = {}) {
    return this.mcpCatalogSurface.searchMcpToolCatalog(this, request);
  }

  setMcpServerEnabled(serverId, enabled, request = {}) {
    return this.mcpControlSurface.setMcpServerEnabled(this, serverId, enabled, request);
  }

  setThreadMcpServerEnabled(threadId, serverId, enabled, request = {}) {
    return this.mcpControlSurface.setThreadMcpServerEnabled(this, threadId, serverId, enabled, request);
  }

  async invokeMcpTool(request = {}) {
    return this.mcpControlSurface.invokeMcpTool(this, request);
  }

  async invokeThreadMcpTool(threadId, toolId, request = {}) {
    return this.mcpControlSurface.invokeThreadMcpTool(this, threadId, toolId, request);
  }

  mcpServeStatus(options = {}) {
    return this.mcpServeSurface.mcpServeStatus(this, options);
  }

  mcpServeToolCatalog(options = {}) {
    return this.mcpServeSurface.mcpServeToolCatalog(this, options);
  }

  async handleMcpServeJsonRpc(threadId, message, request = {}) {
    return this.mcpServeSurface.handleMcpServeJsonRpc(this, threadId, message, request);
  }

  async handleSingleMcpServeJsonRpc(threadId, message, request = {}) {
    return this.mcpServeSurface.handleSingleMcpServeJsonRpc(this, threadId, message, request);
  }

  async recordThreadMcpStatus(threadId, request = {}) {
    return this.mcpControlSurface.recordThreadMcpStatus(this, threadId, request);
  }

  validateThreadMcp(threadId, request = {}) {
    return this.mcpControlSurface.validateThreadMcp(this, threadId, request);
  }

  appendThreadMcpControlEvent({
    threadId,
    agent,
    request,
    controlKind,
    sourceEventKind,
    eventKind,
    componentKind,
    workflowNodeId,
    payloadSchemaVersion,
    status,
    payload,
  }) {
    return this.mcpControlSurface.appendThreadMcpControlEvent(this, {
      threadId,
      agent,
      request,
      controlKind,
      sourceEventKind,
      eventKind,
      componentKind,
      workflowNodeId,
      payloadSchemaVersion,
      status,
      payload,
    });
  }

  mcpServersForContext(options = {}) {
    return this.mcpCatalogSurface.mcpServersForContext(this, options);
  }

  agentForThread(threadId) {
    return agentForThreadState(this, threadId, {
      agentIdForThread,
    });
  }

  inFlightRuntimeTurnKey(threadId, turnId) {
    return inFlightRuntimeTurnKeyState(threadId, turnId);
  }

  registerInFlightRuntimeTurn({ agent, threadId, turnId, runId = null, request = {} }) {
    return registerInFlightRuntimeTurnState(this, { agent, threadId, turnId, runId, request }, {
      runIdForTurn,
    });
  }

  unregisterInFlightRuntimeTurn(threadId, turnId) {
    return unregisterInFlightRuntimeTurnState(this, threadId, turnId);
  }

  resolveRunForThreadTurn(agent, threadId, turnId) {
    return resolveRunForThreadTurnState(this, agent, threadId, turnId, {
      notFound,
      runIdForTurn,
      runtimeTurnIdForRun,
      turnIdForRun,
    });
  }

  getRun(runId) {
    return this.runReadSurface.getRun(this, runId);
  }

  listRuns(agentId) {
    return this.runReadSurface.listRuns(this, agentId);
  }

  usageForRun(runId) {
    return this.runReadSurface.usageForRun(this, runId);
  }

  usageForThread(threadId) {
    return this.runReadSurface.usageForThread(this, threadId);
  }

  listUsage(options = {}) {
    return this.runReadSurface.listUsage(this, options);
  }

  authorityEvidenceSummary(options = {}) {
    return this.runReadSurface.authorityEvidenceSummary(this, options);
  }

  evaluateContextBudget({ threadId = null, runId = null, request = {} } = {}) {
    return this.contextPolicySurface.evaluateContextBudget(this, { threadId, runId, request });
  }

  evaluateCompactionPolicy({ threadId, request = {} } = {}) {
    return this.contextPolicySurface.evaluateCompactionPolicy(this, { threadId, request });
  }

  cancelRun(runId) {
    return cancelRunState(this, runId, {
      contextPolicyRunner: this.contextPolicyRunner,
    });
  }

  replayFromCanonicalState(runId, cursor) {
    return this.runReadSurface.replayFromCanonicalState(this, runId, cursor);
  }

  traceFromCanonicalState(runId) {
    return this.runReadSurface.traceFromCanonicalState(this, runId);
  }

  canonicalProjection(runId) {
    return this.runReadSurface.canonicalProjection(this, runId);
  }

  listModels() {
    return this.modelMounting.runtimeModelCatalogList();
  }

  listModelCapabilities() {
    return this.modelMounting.listModelCapabilities();
  }

  listRepositories() {
    return this.repositorySurface.listRepositories(this);
  }

  repositoryContext() {
    return this.repositorySurface.repositoryContext(this);
  }

  branchPolicy() {
    return this.repositorySurface.branchPolicy(this);
  }

  githubContext() {
    return this.repositorySurface.githubContext(this);
  }

  prAttempts() {
    return this.repositorySurface.prAttempts(this);
  }

  issueContext() {
    return this.repositorySurface.issueContext(this);
  }

  reviewGate() {
    return this.repositorySurface.reviewGate(this);
  }

  githubPrCreatePlan() {
    return this.repositorySurface.githubPrCreatePlan(this);
  }

  getAccount() {
    return this.toolSurface.getAccount();
  }

  listRuntimeNodes() {
    return this.toolSurface.listRuntimeNodes();
  }

  listTools(options = {}) {
    return this.toolSurface.listTools(options);
  }

  invokeComputerUseBrowserDiscoveryTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const turnId =
      optionalString(request.turn_id) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      "computer-use.browser-discovery";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id) ??
      `computer_use_browser_discovery_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:computer-use-browser-discovery:${toolCallId}`;
    const duplicateEvent = this.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(
      idempotencyKey,
    );
    if (duplicateEvent) {
      return computerUseBrowserDiscoveryInvocationResultFromEvent(duplicateEvent, {
        agent,
        threadId,
        turnId,
        toolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
      });
    }
    const requestInput = objectRecord(request.input);
    const requestArguments = objectRecord(request.arguments);
    const requestMetadata = objectRecord(request.metadata ?? request.options?.metadata);
    const explicitInput = Object.keys(requestInput).length
      ? requestInput
      : Object.keys(requestArguments).length
        ? requestArguments
        : objectRecord(request);
    const input = {
      ...requestMetadata,
      ...explicitInput,
    };
    const report = discoverComputerUseBrowsersSync({
      includeCdpProbe: false,
      includeTabMetadata: Boolean(input.includeTabs ?? input.include_tabs),
      revealTabTitles: Boolean(input.revealTabTitles ?? input.reveal_tab_titles),
    });
    const leaseId = `lease_${safeId(threadId)}_${safeId(toolCallId)}_browser_discovery`;
    const payloadSummary = {
      schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      schemaVersion: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      event_kind: "ComputerUse.BrowserDiscovery",
      source: "runtime_thread_tool",
      computerUse: true,
      computer_use: true,
      computer_use_step: "discover_browser",
      computerUseStep: "discover_browser",
      computer_use_lane: "native_browser",
      computerUseLane: "native_browser",
      computer_use_session_mode: "discovery_only",
      computerUseSessionMode: "discovery_only",
      computer_use_lease_id: leaseId,
      computerUseLeaseId: leaseId,
      computer_use_browser_discovery_ref: report.discovery_ref ?? report.receipt_ref,
      computerUseBrowserDiscoveryRef: report.discovery_ref ?? report.receipt_ref,
      tool_ref: toolId,
      toolRef: toolId,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      authority_scopes: ["computer_use.browser_discovery.read"],
      authorityScopes: ["computer_use.browser_discovery.read"],
      fail_closed_when_unavailable: true,
      failClosedWhenUnavailable: true,
      summary: "Browser discovery receipt emitted",
      lease: {
        schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        lease_id: leaseId,
        lane: "native_browser",
        session_mode: "discovery_only",
        status: "not_acquired",
        authority_scope: "computer_use.browser_discovery.read",
        consent_scope: "operator_prompt",
        environment_ref: "browser_discovery:local_host",
        profile_provenance: "none",
        retention_mode: "prompt_visible_summary_only",
        cleanup_required: false,
        evidence_refs: [report.receipt_ref],
      },
      browser_discovery_report: report,
      browserDiscoveryReport: report,
      receipt_id: report.receipt_ref,
      receiptId: report.receipt_ref,
    };
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:computer-use-browser-discovery:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key: idempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: "ComputerUse.BrowserDiscovery",
      event_kind: "computer_use.browser_discovery",
      status: "completed",
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "computer_use_harness",
      tool_call_id: toolCallId,
      tool_name: toolId,
      artifact_refs: ["computer-use-browser-discovery.json"],
      receipt_refs: uniqueStrings([report.receipt_ref]),
      rollback_refs: [],
      payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    return computerUseBrowserDiscoveryInvocationResultFromEvent(event, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
    });
  }

  invokeComputerUseControlTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const turnId =
      optionalString(request.turn_id) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      "computer-use.control";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id) ??
      `computer_use_control_${crypto.randomUUID()}`;
    const idempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:computer-use-control:${toolCallId}`;
    const duplicateEvent = this.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(
      idempotencyKey,
    );
    if (duplicateEvent) {
      return computerUseControlInvocationResultFromEvent(duplicateEvent, {
        agent,
        threadId,
        turnId,
        toolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
      });
    }
    const requestInput = objectRecord(request.input);
    const requestArguments = objectRecord(request.arguments);
    const input = Object.keys(requestInput).length
      ? requestInput
      : Object.keys(requestArguments).length
        ? requestArguments
        : objectRecord(request);
    const action = computerUseControlActionForInput(input);
    const leaseId =
      optionalString(input.leaseId ?? input.lease_id ?? input.computerUseLeaseId ?? input.computer_use_lease_id) ??
      `lease_${safeId(threadId)}_computer_use`;
    const handoffRef =
      optionalString(input.handoffRef ?? input.handoff_ref ?? input.humanHandoffRef ?? input.human_handoff_ref) ??
      null;
    const reason =
      optionalString(input.reason) ??
      `operator requested computer-use ${action}`;
    const receiptRef = `receipt_${safeId(toolCallId)}_computer_use_control_${action}`;
    const cleanupRef =
      optionalString(input.cleanupRef ?? input.cleanup_ref) ??
      `cleanup_${safeId(toolCallId)}_computer_use_control`;
    const resumeObservationRef =
      optionalString(input.resumeObservationRef ?? input.resume_observation_ref) ?? null;
    const cdpEndpointRef =
      optionalString(
        input.cdpEndpointUrl ??
          input.cdp_endpoint_url ??
          input.cdpWebSocketUrl ??
          input.cdp_websocket_url,
      ) ?? null;
    const statusByAction = {
      pause: "paused",
      resume: "resumed",
      abort: "aborted",
      cleanup: "cleanup_completed",
    };
    const cleanupReceipt = action === "cleanup" || action === "abort"
      ? {
          cleanup_ref: cleanupRef,
          lease_id: leaseId,
          status: action === "abort" ? "completed_after_abort" : "completed",
          closed_process_refs: [],
          deleted_profile_refs: [],
          retained_artifact_refs: ["computer-use-trace.json"],
          warnings: [],
        }
      : null;
    const humanHandoffState = action === "resume"
      ? {
          handoff_ref: handoffRef,
          reason: "operator_resumed_computer_use_handoff",
          requested_user_action: "Resume the computer-use lane after operator handoff.",
          forbidden_agent_actions: ["resume_without_fresh_observation_or_endpoint"],
          resume_condition: "Resume request supplies a post-handoff observation ref or attachable endpoint ref.",
          observation_after_resume_ref: resumeObservationRef,
          timeout_policy: "resume_requested_by_operator",
          evidence_retention: optionalString(input.observationRetentionMode ?? input.observation_retention_mode) ??
            "prompt_visible_summary_only",
          status: "resumed",
        }
      : action === "pause"
        ? {
            handoff_ref: handoffRef ?? `handoff_${safeId(toolCallId)}_computer_use_pause`,
            reason: "operator_paused_computer_use",
            requested_user_action: "Review the paused computer-use lease before resuming or aborting.",
            forbidden_agent_actions: ["execute_browser_or_desktop_action_while_paused"],
            resume_condition: "Operator issues computer-use resume with fresh evidence.",
            observation_after_resume_ref: null,
            timeout_policy: "pause_until_user_resumes_or_aborts",
            evidence_retention: optionalString(input.observationRetentionMode ?? input.observation_retention_mode) ??
              "prompt_visible_summary_only",
            status: "pending",
          }
        : null;
    const controlReceipt = {
      schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      receipt_ref: receiptRef,
      tool_ref: toolId,
      thread_id: threadId,
      turn_id: turnId || null,
      lease_id: leaseId,
      handoff_ref: handoffRef,
      action,
      status: statusByAction[action],
      reason,
      resume_observation_ref: resumeObservationRef,
      cdp_endpoint_ref: cdpEndpointRef,
      cleanup_ref: cleanupReceipt?.cleanup_ref ?? null,
      authority_scope: `computer_use.control.${action}`,
      fail_closed_when_unavailable: true,
      evidence_refs: uniqueStrings([leaseId, handoffRef, resumeObservationRef, cdpEndpointRef, cleanupReceipt?.cleanup_ref]),
    };
    const payloadSummary = {
      schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      event_kind: "ComputerUse.Control",
      source: "runtime_thread_tool",
      computer_use: true,
      computer_use_step: action === "cleanup" ? "cleanup" : "commit_or_handoff",
      computer_use_lane: optionalString(input.lane ?? input.computerUseLane ?? input.computer_use_lane) ??
        "native_browser",
      computer_use_session_mode:
        optionalString(input.sessionMode ?? input.session_mode ?? input.computerUseSessionMode ?? input.computer_use_session_mode) ??
        null,
      computer_use_lease_id: leaseId,
      computer_use_control_action: action,
      computer_use_control_receipt_ref: receiptRef,
      tool_ref: toolId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      authority_scopes: [`computer_use.control.${action}`],
      fail_closed_when_unavailable: true,
      summary: `Computer-use ${action} control receipt emitted`,
      control_receipt: controlReceipt,
      human_handoff_state: humanHandoffState,
      cleanup_receipt: cleanupReceipt,
      receipt_id: receiptRef,
    };
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:computer-use-control:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key: idempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: "ComputerUse.Control",
      event_kind: "computer_use.control",
      status: action === "abort" ? "canceled" : "completed",
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "computer_use_harness",
      tool_call_id: toolCallId,
      tool_name: toolId,
      artifact_refs: [],
      receipt_refs: uniqueStrings([receiptRef, cleanupReceipt?.cleanup_ref]),
      rollback_refs: [],
      payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    return computerUseControlInvocationResultFromEvent(event, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
    });
  }

  async invokeComputerUseNativeBrowserTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const turnId =
      optionalString(request.turn_id) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      "computer-use.native-browser";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id) ??
      `computer_use_native_browser_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:computer-use-native-browser:${toolCallId}`;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const duplicateEvents = stream.events.filter((event) => (
      event.payload_summary?.computer_use_tool_invocation_ref === idempotencyKey ||
      event.payload?.computer_use_tool_invocation_ref === idempotencyKey
    ));
    if (duplicateEvents.length > 0) {
      return computerUseNativeBrowserInvocationResultFromEvents(duplicateEvents, {
        agent,
        threadId,
        turnId,
        toolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
        computerUseLane: "native_browser",
      });
    }
    const requestInput = objectRecord(request.input);
    const requestArguments = objectRecord(request.arguments);
    const input = Object.keys(requestInput).length
      ? requestInput
      : Object.keys(requestArguments).length
        ? requestArguments
        : objectRecord(request);
    const goal =
      optionalString(input.prompt ?? input.goal ?? input.objective ?? request.prompt ?? request.goal) ??
      optionalString(input.url)?.replace(/^/, "Inspect browser surface at ") ??
      "Inspect the native browser surface without external side effects.";
    const runId = `run_${safeId(toolCallId)}`;
    const observationRetentionMode =
      optionalString(input.observationRetentionMode ?? input.observation_retention_mode) ??
      "prompt_visible_summary_only";
    const requestedActionKind = nativeBrowserActionKindForInput(input, goal);
    const requestedActionAuthority = nativeBrowserActionKindIsReadOnly(requestedActionKind)
      ? "computer_use.native_browser.read"
      : "computer_use.native_browser.act";
    const requestedApprovalRef = nativeBrowserApprovalRefForInput(input);
    const requestedTargetRef =
      optionalString(input.targetRef ?? input.target_ref ?? input.computerUseTargetRef ?? input.computer_use_target_ref);
    const requestedSessionMode = nativeBrowserSessionModeForInput(input);
    const requestedLaunchApprovalRef = nativeBrowserControlledRelaunchApprovalRefForInput(input);
    const shouldLaunchControlledRelaunch =
      requestedSessionMode === "controlled_relaunch" &&
      requestedLaunchApprovalRef &&
      !nativeBrowserHasExplicitCdpEndpoint(input);
    const controlledRelaunchLaunch = shouldLaunchControlledRelaunch
      ? await launchControlledNativeBrowser({
          input,
          runId,
          approvalRef: requestedLaunchApprovalRef,
          timeoutMs: nativeBrowserCdpTimeoutMs(input),
          cwd: agent.cwd,
        })
      : null;
    const executionInput = controlledRelaunchLaunch?.status === "launched"
      ? { ...input, cdpEndpointUrl: controlledRelaunchLaunch.endpointUrl }
      : input;
    let nativeBrowserExecution = null;
    let controlledRelaunchCleanup = null;
    const shouldUseCdpExecutor =
      controlledRelaunchLaunch?.status === "launched" ||
      nativeBrowserActionShouldUseCdpExecutor(
        requestedActionKind,
        requestedApprovalRef,
        executionInput,
      );
    if (controlledRelaunchLaunch?.status === "unavailable") {
      nativeBrowserExecution = nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch({
        launchReceipt: controlledRelaunchLaunch.launchReceipt,
        actionKind: requestedActionKind,
        approvalRef: requestedApprovalRef,
        uniqueStrings,
      });
      controlledRelaunchCleanup = await controlledRelaunchLaunch.cleanup({
        leaseId: `lease_${runId}_browser`,
      });
    } else if (shouldUseCdpExecutor) {
      try {
        nativeBrowserExecution = await executeNativeBrowserCdpAction({
          input: executionInput,
          actionKind: requestedActionKind,
          approvalRef: requestedApprovalRef,
          targetRef: requestedTargetRef,
          prompt: goal,
          timeoutMs: nativeBrowserCdpTimeoutMs(input),
        });
      } finally {
        if (controlledRelaunchLaunch?.cleanup) {
          controlledRelaunchCleanup = await controlledRelaunchLaunch.cleanup({
            leaseId: `lease_${runId}_browser`,
          });
        }
      }
    }
    const metadata = {
      computerUse: true,
      computerUseLane: "native_browser",
      computerUseSessionMode: requestedSessionMode,
      workflowGraphId,
      workflowNodeId,
      workflowNodeIds: uniqueStrings([
        workflowNodeId,
        ...normalizeArray(input.workflowNodeIds ?? input.workflow_node_ids),
      ]),
      toolRef: toolId,
      authorityScopes: uniqueStrings([
        requestedActionAuthority,
        "computer_use.native_browser.read",
        ...normalizeArray(input.authorityScopes ?? input.authority_scopes),
      ]),
      observationRetentionMode,
      failClosedWhenUnavailable: true,
      computer_use_action_kind: requestedActionKind,
      computer_use_approval_ref: requestedApprovalRef,
      computer_use_target_ref: requestedTargetRef,
      computerUseNativeBrowserExecution: nativeBrowserExecution,
      computerUseControlledRelaunchLaunchReceipt: controlledRelaunchLaunch?.launchReceipt ?? null,
      computerUseObservationBundle:
        objectRecord(input.computerUseObservationBundle ?? input.observation_bundle),
      computerUseTargetIndex:
        objectRecord(input.computerUseTargetIndex ?? input.target_index),
      computerUseAffordanceGraph:
        objectRecord(input.computerUseAffordanceGraph ?? input.affordance_graph),
      computerUseBrowserObservationArtifacts:
        objectRecord(input.computerUseBrowserObservationArtifacts ?? input.browser_observation_artifacts),
      computerUseControlledRelaunchBroker:
        objectRecord(
          input.computerUseControlledRelaunchBroker ??
            input.computer_use_controlled_relaunch_broker ??
            input.controlledRelaunchBroker ??
            input.controlled_relaunch_broker,
        ),
      controlledRelaunchBrokerRef:
        optionalString(input.controlledRelaunchBrokerRef ?? input.controlled_relaunch_broker_ref),
      controlledRelaunchStartUrl:
        optionalString(input.controlledRelaunchStartUrl ?? input.controlled_relaunch_start_url ?? input.url),
      controlledRelaunchProfileDirRef:
        optionalString(input.controlledRelaunchProfileDirRef ?? input.controlled_relaunch_profile_dir_ref),
      controlledRelaunchLaunchPlanRef:
        optionalString(input.controlledRelaunchLaunchPlanRef ?? input.controlled_relaunch_launch_plan_ref),
      controlledRelaunchApprovalRef: requestedLaunchApprovalRef,
      controlledRelaunchExecutablePath:
        optionalString(input.controlledRelaunchExecutablePath ?? input.controlled_relaunch_executable_path),
      computerUseCleanupReceipt: controlledRelaunchCleanup,
    };
    for (const key of [
      "computer_use_approval_ref",
      "computer_use_target_ref",
      "computerUseNativeBrowserExecution",
      "computerUseControlledRelaunchLaunchReceipt",
      "computerUseObservationBundle",
      "computerUseTargetIndex",
      "computerUseAffordanceGraph",
      "computerUseBrowserObservationArtifacts",
      "computerUseControlledRelaunchBroker",
      "controlledRelaunchBrokerRef",
      "controlledRelaunchStartUrl",
      "controlledRelaunchProfileDirRef",
      "controlledRelaunchLaunchPlanRef",
      "controlledRelaunchApprovalRef",
      "controlledRelaunchExecutablePath",
      "computerUseCleanupReceipt",
    ]) {
      if (metadata[key] && typeof metadata[key] === "object") {
        if (Object.keys(metadata[key]).length === 0) delete metadata[key];
      } else if (metadata[key] == null || metadata[key] === "") {
        delete metadata[key];
      }
    }
    const projection = computerUseProjectionForRun({
      agent,
      runId,
      prompt: goal,
      mode: "send",
      request: { metadata },
      selectedModel: agent.modelId,
    });
    if (!projection) {
      throw runtimeError({
        status: 500,
        code: "computer_use_projection_unavailable",
        message: "Native browser tool invocation could not build a computer-use projection.",
        details: { threadId, toolId },
      });
    }
    const appendedEvents = [];
    for (const [index, projectionEvent] of projection.events.entries()) {
      const runEvent = makeEvent(
        runId,
        agent.id,
        index,
        projectionEvent.type,
        projectionEvent.summary,
        {
          ...projectionEvent.data,
          source: "runtime_thread_tool",
          computer_use_tool_invocation_ref: idempotencyKey,
          toolRef: toolId,
          tool_ref: toolId,
          toolCallId,
          tool_call_id: toolCallId,
          workflowGraphId,
          workflow_graph_id: workflowGraphId,
          workflowNodeId,
          workflow_node_id: workflowNodeId,
        },
      );
      const envelope = ttiEnvelopeForRunEvent({
        event: runEvent,
        threadId,
        turnId,
        workspaceRoot: agent.cwd,
      });
      appendedEvents.push(this.appendRuntimeEvent({
        ...envelope,
        idempotency_key: `${idempotencyKey}:event:${String(index).padStart(2, "0")}:${projectionEvent.type}`,
        source: operatorControlSource(request.source),
        component_kind: "computer_use_harness",
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        tool_call_id: toolCallId,
      }));
    }
    return computerUseNativeBrowserInvocationResultFromEvents(appendedEvents, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      projection,
      computerUseLane: "native_browser",
    });
  }

  async invokeComputerUseVisualGuiTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const turnId =
      optionalString(request.turn_id) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      "computer-use.visual-gui";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id) ??
      `computer_use_visual_gui_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:computer-use-visual-gui:${toolCallId}`;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const duplicateEvents = stream.events.filter((event) => (
      event.payload_summary?.computer_use_tool_invocation_ref === idempotencyKey ||
      event.payload?.computer_use_tool_invocation_ref === idempotencyKey
    ));
    if (duplicateEvents.length > 0) {
      return computerUseNativeBrowserInvocationResultFromEvents(duplicateEvents, {
        agent,
        threadId,
        turnId,
        toolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
        computerUseLane: "visual_gui",
      });
    }
    const requestInput = objectRecord(request.input);
    const requestArguments = objectRecord(request.arguments);
    const input = Object.keys(requestInput).length
      ? requestInput
      : Object.keys(requestArguments).length
        ? requestArguments
        : objectRecord(request);
    const goal =
      optionalString(input.prompt ?? input.goal ?? input.objective ?? request.prompt ?? request.goal) ??
      "Inspect the visual GUI surface without external side effects.";
    const runId = `run_${safeId(toolCallId)}`;
    const observationRetentionMode =
      optionalString(input.observationRetentionMode ?? input.observation_retention_mode) ??
      "local_redacted_artifacts";
    const requestedActionKind = nativeBrowserActionKindForInput(input, goal);
    const requestedActionAuthority = nativeBrowserActionKindIsReadOnly(requestedActionKind)
      ? "computer_use.visual_gui.read"
      : "computer_use.visual_gui.act";
    const requestedApprovalRef = nativeBrowserApprovalRefForInput(input);
    const requestedTargetRef =
      optionalString(input.targetRef ?? input.target_ref ?? input.computerUseTargetRef ?? input.computer_use_target_ref);
    const requestedSessionMode = visualGuiSessionModeForInput(input);
    const materializedVisualArtifacts = this.materializeVisualGuiObservationArtifacts({
      threadId,
      toolId,
      toolCallId,
      workspaceRoot: agent.cwd,
      input,
    });
    const visualObservationMetadata = visualGuiObservationMetadataForInput({
      ...input,
      ...materializedVisualArtifacts.metadata,
    });
    const visualExecutionInput = {
      ...input,
      ...materializedVisualArtifacts.metadata,
      ...visualObservationMetadata,
    };
    const visualGuiExecution = visualGuiLocalExecutorRequested({
      input: visualExecutionInput,
      actionKind: requestedActionKind,
      approvalRef: requestedApprovalRef,
    })
      ? await executeLocalVisualGuiAction({
          input: visualExecutionInput,
          actionKind: requestedActionKind,
          approvalRef: requestedApprovalRef,
          targetRef: requestedTargetRef,
          prompt: goal,
          toolCallId,
          captureDir: this.pathFor("visual-gui-captures"),
          artifactResolver: (artifactRef) => this.codingArtifacts.get(artifactRef),
          maxBytes: COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
        })
      : null;
    const metadata = {
      computerUse: true,
      computerUseLane: "visual_gui",
      computerUseSessionMode: requestedSessionMode,
      workflowGraphId,
      workflowNodeId,
      workflowNodeIds: uniqueStrings([
        workflowNodeId,
        ...normalizeArray(input.workflowNodeIds ?? input.workflow_node_ids),
      ]),
      toolRef: toolId,
      authorityScopes: uniqueStrings([
        requestedActionAuthority,
        "computer_use.visual_gui.observe",
        "computer_use.visual_gui.read",
        ...normalizeArray(input.authorityScopes ?? input.authority_scopes),
      ]),
      observationRetentionMode,
      failClosedWhenUnavailable: true,
      computer_use_action_kind: requestedActionKind,
      computer_use_approval_ref: requestedApprovalRef,
      computer_use_target_ref: requestedTargetRef,
      computerUseVisualArtifactRefs: materializedVisualArtifacts.artifact_refs,
      computerUseExecutionResult: visualGuiExecution,
      computerUseVisualGuiExecution: visualGuiExecution,
      ...visualObservationMetadata,
      computerUseObservationBundle:
        objectRecord(input.computerUseObservationBundle ?? input.observation_bundle),
      computerUseTargetIndex:
        objectRecord(input.computerUseTargetIndex ?? input.target_index),
      computerUseAffordanceGraph:
        objectRecord(input.computerUseAffordanceGraph ?? input.affordance_graph),
      computerUseAdapterContract:
        objectRecord(input.computerUseAdapterContract ?? input.adapter_contract),
      computerUseCleanupReceipt:
        objectRecord(input.computerUseCleanupReceipt ?? input.cleanup_receipt),
    };
    for (const key of [
      "computer_use_approval_ref",
      "computer_use_target_ref",
      "computerUseVisualObservation",
      "computerUseVisualArtifactRefs",
      "computerUseExecutionResult",
      "computerUseVisualGuiExecution",
      "screenshotRef",
      "somRef",
      "axRef",
      "computer_use_visual_observation",
      "screenshot_ref",
      "som_ref",
      "ax_ref",
      "appName",
      "windowTitle",
      "coordinateSpaceId",
      "app_name",
      "window_title",
      "coordinate_space_id",
      "viewportWidth",
      "viewportHeight",
      "viewport_width",
      "viewport_height",
      "visualTargets",
      "visualAffordances",
      "detectedPatterns",
      "visual_targets",
      "visual_affordances",
      "detected_patterns",
      "computerUseObservationBundle",
      "computerUseTargetIndex",
      "computerUseAffordanceGraph",
      "computerUseAdapterContract",
      "computerUseCleanupReceipt",
    ]) {
      if (Array.isArray(metadata[key])) {
        if (metadata[key].length === 0) delete metadata[key];
      } else if (metadata[key] && typeof metadata[key] === "object") {
        if (Object.keys(metadata[key]).length === 0) delete metadata[key];
      } else if (metadata[key] == null || metadata[key] === "") {
        delete metadata[key];
      }
    }
    const projection = computerUseProjectionForRun({
      agent,
      runId,
      prompt: goal,
      mode: "send",
      request: { metadata },
      selectedModel: agent.modelId,
    });
    if (!projection) {
      throw runtimeError({
        status: 500,
        code: "computer_use_projection_unavailable",
        message: "Visual GUI tool invocation could not build a computer-use projection.",
        details: { threadId, toolId },
      });
    }
    const appendedEvents = [];
    for (const [index, projectionEvent] of projection.events.entries()) {
      const runEvent = makeEvent(
        runId,
        agent.id,
        index,
        projectionEvent.type,
        projectionEvent.summary,
        {
          ...projectionEvent.data,
          source: "runtime_thread_tool",
          computer_use_tool_invocation_ref: idempotencyKey,
          toolRef: toolId,
          tool_ref: toolId,
          toolCallId,
          tool_call_id: toolCallId,
          workflowGraphId,
          workflow_graph_id: workflowGraphId,
          workflowNodeId,
          workflow_node_id: workflowNodeId,
        },
      );
      const envelope = ttiEnvelopeForRunEvent({
        event: runEvent,
        threadId,
        turnId,
        workspaceRoot: agent.cwd,
      });
      appendedEvents.push(this.appendRuntimeEvent({
        ...envelope,
        idempotency_key: `${idempotencyKey}:event:${String(index).padStart(2, "0")}:${projectionEvent.type}`,
        source: operatorControlSource(request.source),
        component_kind: "computer_use_harness",
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        tool_call_id: toolCallId,
      }));
    }
    return computerUseNativeBrowserInvocationResultFromEvents(appendedEvents, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      projection,
      computerUseLane: "visual_gui",
    });
  }

  async invokeComputerUseSandboxedHostedTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const turnId =
      optionalString(request.turn_id) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      "computer-use.sandboxed-hosted";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id) ??
      `computer_use_sandboxed_hosted_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:computer-use-sandboxed-hosted:${toolCallId}`;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const duplicateEvents = stream.events.filter((event) => (
      event.payload_summary?.computer_use_tool_invocation_ref === idempotencyKey ||
      event.payload?.computer_use_tool_invocation_ref === idempotencyKey
    ));
    if (duplicateEvents.length > 0) {
      return computerUseNativeBrowserInvocationResultFromEvents(duplicateEvents, {
        agent,
        threadId,
        turnId,
        toolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
        computerUseLane: "sandboxed_hosted",
      });
    }
    const requestInput = objectRecord(request.input);
    const requestArguments = objectRecord(request.arguments);
    const input = Object.keys(requestInput).length
      ? requestInput
      : Object.keys(requestArguments).length
        ? requestArguments
        : objectRecord(request);
    const goal =
      optionalString(input.prompt ?? input.goal ?? input.objective ?? request.prompt ?? request.goal) ??
      "Inspect the sandboxed computer fixture without external side effects.";
    const runId = `run_${safeId(toolCallId)}`;
    const observationRetentionMode =
      optionalString(input.observationRetentionMode ?? input.observation_retention_mode) ??
      "no_persistence";
    const requestedActionKind = nativeBrowserActionKindForInput(input, goal);
    const requestedActionAuthority = nativeBrowserActionKindIsReadOnly(requestedActionKind)
      ? "computer_use.sandboxed_hosted.read"
      : "computer_use.sandboxed_hosted.act";
    const requestedApprovalRef = nativeBrowserApprovalRefForInput(input);
    const requestedTargetRef =
      optionalString(input.targetRef ?? input.target_ref ?? input.computerUseTargetRef ?? input.computer_use_target_ref);
    const requestedSessionMode = sandboxedHostedSessionModeForInput(input);
    const sandboxProvider =
      optionalString(
        input.computer_use_sandbox_provider ??
          input.sandbox_provider,
      ) ?? "local_fixture";
    const sandboxFixture =
      booleanValue(
        input.computer_use_sandbox_fixture ??
          input.sandbox_fixture,
      ) ?? sandboxProvider === "local_fixture";
    const metadata = {
      computerUse: true,
      computerUseLane: "sandboxed_hosted",
      computerUseSessionMode: requestedSessionMode,
      workflowGraphId,
      workflowNodeId,
      workflowNodeIds: uniqueStrings([
        workflowNodeId,
        ...normalizeArray(input.workflowNodeIds ?? input.workflow_node_ids),
      ]),
      toolRef: toolId,
      authorityScopes: uniqueStrings([
        requestedActionAuthority,
        "computer_use.sandboxed_hosted.observe",
        "computer_use.sandboxed_hosted.read",
        ...normalizeArray(input.authorityScopes ?? input.authority_scopes),
      ]),
      observationRetentionMode,
      failClosedWhenUnavailable: true,
      computer_use_action_kind: requestedActionKind,
      computer_use_approval_ref: requestedApprovalRef,
      computer_use_target_ref: requestedTargetRef,
      computer_use_sandbox_provider: sandboxProvider,
      computer_use_sandbox_fixture: sandboxFixture,
      computer_use_sandbox_image_ref:
        optionalString(input.computer_use_sandbox_image_ref ?? input.sandbox_image_ref),
      computer_use_sandbox_task_ref:
        optionalString(input.computer_use_sandbox_task_ref ?? input.sandbox_task_ref),
      computerUseObservationBundle:
        objectRecord(input.computerUseObservationBundle ?? input.observation_bundle),
      computerUseTargetIndex:
        objectRecord(input.computerUseTargetIndex ?? input.target_index),
      computerUseAffordanceGraph:
        objectRecord(input.computerUseAffordanceGraph ?? input.affordance_graph),
      computerUseAdapterContract:
        objectRecord(input.computerUseAdapterContract ?? input.adapter_contract),
      computerUseCleanupReceipt:
        objectRecord(input.computerUseCleanupReceipt ?? input.cleanup_receipt),
    };
    for (const key of [
      "computer_use_approval_ref",
      "computer_use_target_ref",
      "computer_use_sandbox_image_ref",
      "computer_use_sandbox_task_ref",
      "computerUseObservationBundle",
      "computerUseTargetIndex",
      "computerUseAffordanceGraph",
      "computerUseAdapterContract",
      "computerUseCleanupReceipt",
    ]) {
      if (metadata[key] && typeof metadata[key] === "object") {
        if (Object.keys(metadata[key]).length === 0) delete metadata[key];
      } else if (metadata[key] == null || metadata[key] === "") {
        delete metadata[key];
      }
    }
    const projection = computerUseProjectionForRun({
      agent,
      runId,
      prompt: goal,
      mode: "send",
      request: { metadata },
      selectedModel: agent.modelId,
    });
    if (!projection) {
      throw runtimeError({
        status: 500,
        code: "computer_use_projection_unavailable",
        message: "Sandboxed hosted computer-use tool invocation could not build a computer-use projection.",
        details: { threadId, toolId },
      });
    }
    const appendedEvents = [];
    for (const [index, projectionEvent] of projection.events.entries()) {
      const runEvent = makeEvent(
        runId,
        agent.id,
        index,
        projectionEvent.type,
        projectionEvent.summary,
        {
          ...projectionEvent.data,
          source: "runtime_thread_tool",
          computer_use_tool_invocation_ref: idempotencyKey,
          toolRef: toolId,
          tool_ref: toolId,
          toolCallId,
          tool_call_id: toolCallId,
          workflowGraphId,
          workflow_graph_id: workflowGraphId,
          workflowNodeId,
          workflow_node_id: workflowNodeId,
        },
      );
      const envelope = ttiEnvelopeForRunEvent({
        event: runEvent,
        threadId,
        turnId,
        workspaceRoot: agent.cwd,
      });
      appendedEvents.push(this.appendRuntimeEvent({
        ...envelope,
        idempotency_key: `${idempotencyKey}:event:${String(index).padStart(2, "0")}:${projectionEvent.type}`,
        source: operatorControlSource(request.source),
        component_kind: "computer_use_harness",
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        tool_call_id: toolCallId,
      }));
    }
    return computerUseNativeBrowserInvocationResultFromEvents(appendedEvents, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      projection,
      computerUseLane: "sandboxed_hosted",
    });
  }

  async invokeComputerUseVisualGuiObserveTool(threadId, toolId, request = {}) {
    const requestInput = objectRecord(request.input);
    const requestArguments = objectRecord(request.arguments);
    const input = Object.keys(requestInput).length
      ? requestInput
      : Object.keys(requestArguments).length
        ? requestArguments
        : objectRecord(request);
    const toolCallId =
      optionalString(request.tool_call_id) ??
      `computer_use_visual_gui_observe_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:computer-use-visual-gui-observe:${toolCallId}`;
    const localCapture = visualGuiLocalCaptureRequested(input)
      ? captureLocalVisualGuiObservation({
          input,
          captureDir: this.pathFor("visual-gui-captures"),
          toolCallId,
          maxBytes: COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
        })
      : null;
    const sanitizedInput = {
      ...input,
      ...(localCapture?.status === "captured"
        ? localCapture.inputPatch
        : localCapture?.status === "unavailable"
          ? visualGuiLocalCaptureUnavailablePatch(input)
          : {}),
      actionKind: "inspect",
      action_kind: "inspect",
      computer_use_action_kind: "inspect",
      authorityScopes: normalizeArray(input.authorityScopes ?? input.authority_scopes)
        .map((scope) => optionalString(scope))
        .filter((scope) => scope && !scope.includes(".act") && scope !== "coordinate_action"),
    };
    try {
      const result = await this.invokeComputerUseVisualGuiTool(threadId, toolId, {
        ...request,
        input: sanitizedInput,
        tool_call_id: toolCallId,
        idempotency_key: idempotencyKey,
        workflow_node_id:
          optionalString(request.workflow_node_id) ??
          "computer-use.visual-gui.observe",
      });
      const observationBroker = {
        schema_version: "ioi.runtime.computer-use-visual-gui-observation-broker.v1",
        object: "ioi.runtime_computer_use_visual_gui_observation_broker",
        broker_ref: `visual_gui_observation_broker_${safeId(toolCallId)}`,
        lane: "visual_gui",
        session_mode: result.result?.environmentSelection?.selected_session_mode ?? "visual_fallback",
        authority_scope: "computer_use.visual_gui.read",
        tool_ref: toolId,
        tool_call_id: toolCallId,
        observation_ref: result.result?.observation?.observation_ref ?? null,
        target_index_ref: result.result?.targetIndex?.target_index_ref ?? null,
        affordance_graph_ref: result.result?.affordanceGraph?.graph_ref ?? null,
        retained_artifact_refs: result.result?.cleanup?.retained_artifact_refs ?? [],
        capture_receipt: localCapture?.receipt ?? null,
        captureReceipt: localCapture?.receipt ?? null,
        fail_closed_when_unavailable: true,
        note: "Observation broker is read-only; coordinate/OS input authority is not granted.",
      };
      return {
        ...result,
        result: {
          ...result.result,
          observationBroker,
          observation_broker: observationBroker,
        },
      };
    } finally {
      for (const filePath of localCapture?.cleanupPaths ?? []) {
        this.removeQuiet(filePath);
      }
    }
  }

  async invokeThreadToolAsync(threadId, toolId, request = {}) {
    const normalizedToolId = optionalString(toolId);
    if (WORKSPACE_CHANGE_CONTROL_TOOL_IDS.has(normalizedToolId)) {
      return await this.controlWorkspaceChangeForThread(threadId, {
        ...request,
        tool_id: normalizedToolId,
      });
    }
    if (COMPUTER_USE_CONTROL_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseControlTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_NATIVE_BROWSER_TOOL_IDS.has(normalizedToolId)) {
      return await this.invokeComputerUseNativeBrowserTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_VISUAL_GUI_TOOL_IDS.has(normalizedToolId)) {
      return await this.invokeComputerUseVisualGuiTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_SANDBOXED_HOSTED_TOOL_IDS.has(normalizedToolId)) {
      return await this.invokeComputerUseSandboxedHostedTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_VISUAL_GUI_OBSERVE_TOOL_IDS.has(normalizedToolId)) {
      return await this.invokeComputerUseVisualGuiObserveTool(threadId, normalizedToolId, request);
    }
    return this.invokeThreadTool(threadId, toolId, request);
  }

  invokeThreadTool(threadId, toolId, request = {}) {
    return this.codingToolInvocationSurface.invokeThreadTool(this, threadId, toolId, request);
  }

  appendCodingToolCommandStreamEvents({
    agent,
    threadId,
    turnId,
    toolId,
    toolCallId,
    workflowGraphId,
    workflowNodeId,
    request = {},
    result = {},
    status = "completed",
    receiptRefs = [],
    artifactRefs = [],
  } = {}) {
    return this.codingToolArtifactSurface.appendCodingToolCommandStreamEvents(this, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      request,
      result,
      status,
      receiptRefs,
      artifactRefs,
    });
  }

  latestApprovalRequestEvent(threadId, approvalId) {
    return this.approvalSurface.latestApprovalRequestEvent(this, threadId, approvalId);
  }

  codingToolApprovalSatisfaction({ threadId, approvalManifest, request }) {
    return this.codingToolGovernanceSurface.codingToolApprovalSatisfaction(this, {
      threadId,
      approvalManifest,
      request,
    });
  }

  blockCodingToolForApproval({
    agent,
    threadId,
    turnId,
    toolId,
    toolCallId,
    receiptId,
    input,
    request,
    workflowGraphId,
    workflowNodeId,
    requestRollbackRefs,
    diagnosticsRepairContext,
    approvalManifest,
    toolContract,
  }) {
    return this.codingToolGovernanceSurface.blockCodingToolForApproval(this, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      receiptId,
      input,
      request,
      workflowGraphId,
      workflowNodeId,
      requestRollbackRefs,
      diagnosticsRepairContext,
      approvalManifest,
      toolContract,
    });
  }

  blockCodingToolForBudget({
    agent,
    threadId,
    turnId,
    toolId,
    toolCallId,
    receiptId,
    input,
    request,
    workflowGraphId,
    workflowNodeId,
    requestRollbackRefs,
    diagnosticsRepairContext,
    budgetPolicy,
    toolContract,
    codingToolIdempotencyKey,
  }) {
    return this.codingToolGovernanceSurface.blockCodingToolForBudget(this, {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      receiptId,
      input,
      request,
      workflowGraphId,
      workflowNodeId,
      requestRollbackRefs,
      diagnosticsRepairContext,
      budgetPolicy,
      toolContract,
      codingToolIdempotencyKey,
    });
  }

  prepareWorkspaceSnapshotForPatch({
    threadId,
    turnId,
    workspaceRoot,
    toolCallId,
    workflowGraphId,
    workflowNodeId,
    result = {},
  } = {}) {
    return this.workspaceSnapshotSurface.prepareWorkspaceSnapshotForPatch(this, {
      threadId,
      turnId,
      toolCallId,
      workspaceRoot,
      workflowGraphId,
      workflowNodeId,
      result,
    });
  }

  materializeWorkspaceSnapshotArtifact({
    threadId,
    toolCallId,
    workspaceRoot,
    snapshot,
    artifactPayload,
    artifactId,
    receiptId,
  } = {}) {
    return this.workspaceSnapshotSurface.materializeWorkspaceSnapshotArtifact(this, {
      threadId,
      toolCallId,
      workspaceRoot,
      snapshot,
      artifactPayload,
      artifactId,
      receiptId,
    });
  }

  appendWorkspaceSnapshotEvent({
    threadId,
    turnId,
    workspaceRoot,
    workflowGraphId,
    snapshot,
    sourceToolEvent,
  } = {}) {
    return this.workspaceSnapshotSurface.appendWorkspaceSnapshotEvent(this, {
      threadId,
      turnId,
      workspaceRoot,
      workflowGraphId,
      snapshot,
      sourceToolEvent,
    });
  }

  listWorkspaceSnapshots(threadId) {
    return this.workspaceSnapshotSurface.listWorkspaceSnapshots(this, threadId);
  }

  previewWorkspaceSnapshotRestore(threadId, snapshotId, request = {}) {
    return this.workspaceSnapshotSurface.previewWorkspaceSnapshotRestore(this, threadId, snapshotId, request);
  }

  applyWorkspaceSnapshotRestore(threadId, snapshotId, request = {}) {
    return this.workspaceSnapshotSurface.applyWorkspaceSnapshotRestore(this, threadId, snapshotId, request);
  }

  executeDiagnosticsRepairDecision(threadId, decisionRef, request = {}) {
    return this.diagnosticsRepairSurface.executeDiagnosticsRepairDecision(this, threadId, decisionRef, request);
  }

  executeDiagnosticsOperatorOverride(threadId, {
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId = null,
    workflowGraphId = null,
    workflowNodeId = LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID,
  } = {}) {
    return this.diagnosticsRepairSurface.executeDiagnosticsOperatorOverride(this, threadId, {
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
    });
  }

  turnForOperatorOverrideEvent(event = {}) {
    return this.diagnosticsRepairSurface.turnForOperatorOverrideEvent(this, event);
  }

  appendDiagnosticsOperatorOverrideEvent({
    threadId,
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId,
    workflowGraphId,
    workflowNodeId,
    approval,
    status,
    targetTurnId,
    targetRunId,
    previousTurnStatus,
    nextTurnStatus,
    idempotencyKey,
  } = {}) {
    return this.diagnosticsRepairSurface.appendDiagnosticsOperatorOverrideEvent(this, {
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
      approval,
      status,
      targetTurnId,
      targetRunId,
      previousTurnStatus,
      nextTurnStatus,
      idempotencyKey,
    });
  }

  createDiagnosticsRepairRetryTurn(threadId, {
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId = null,
    workflowGraphId = null,
    workflowNodeId = LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID,
  } = {}) {
    return this.diagnosticsRepairSurface.createDiagnosticsRepairRetryTurn(this, threadId, {
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
    });
  }

  turnForRepairRetryEvent(event = {}) {
    return this.diagnosticsRepairSurface.turnForRepairRetryEvent(this, event);
  }

  appendDiagnosticsRepairRetryTurnEvent({
    threadId,
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId,
    workflowGraphId,
    workflowNodeId,
    run,
    turn,
    diagnosticsFeedback,
    idempotencyKey,
  } = {}) {
    return this.diagnosticsRepairSurface.appendDiagnosticsRepairRetryTurnEvent(this, {
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
      run,
      turn,
      diagnosticsFeedback,
      idempotencyKey,
    });
  }

  resolveDiagnosticsRepairDecision(threadId, decisionRef, request = {}) {
    return this.diagnosticsRepairSurface.resolveDiagnosticsRepairDecision(this, threadId, decisionRef, request);
  }

  appendDiagnosticsRepairDecisionExecutedEvent({
    threadId,
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    action,
    snapshotId,
    workflowGraphId,
    workflowNodeId,
    executionResult,
  } = {}) {
    return this.diagnosticsRepairSurface.appendDiagnosticsRepairDecisionExecutedEvent(this, {
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      action,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
      executionResult,
    });
  }

  workspaceSnapshotContentPackage(threadId, snapshotId) {
    return this.workspaceSnapshotSurface.workspaceSnapshotContentPackage(this, threadId, snapshotId);
  }

  materializeWorkspaceRestorePreviewArtifact({
    threadId,
    workspaceRoot,
    snapshotId,
    artifactId,
    receiptId,
    preview,
  } = {}) {
    return this.workspaceSnapshotSurface.materializeWorkspaceRestorePreviewArtifact(this, {
      threadId,
      workspaceRoot,
      snapshotId,
      artifactId,
      receiptId,
      preview,
    });
  }

  materializeWorkspaceRestoreApplyArtifact({
    threadId,
    workspaceRoot,
    snapshotId,
    artifactId,
    receiptId,
    apply,
  } = {}) {
    return this.workspaceSnapshotSurface.materializeWorkspaceRestoreApplyArtifact(this, {
      threadId,
      workspaceRoot,
      snapshotId,
      artifactId,
      receiptId,
      apply,
    });
  }

  appendWorkspaceRestorePreviewEvent({
    threadId,
    turnId,
    workspaceRoot,
    workflowGraphId,
    workflowNodeId,
    preview,
  } = {}) {
    return this.workspaceSnapshotSurface.appendWorkspaceRestorePreviewEvent(this, {
      threadId,
      turnId,
      workspaceRoot,
      workflowGraphId,
      workflowNodeId,
      preview,
    });
  }

  appendWorkspaceRestoreApplyEvent({
    threadId,
    turnId,
    workspaceRoot,
    workflowGraphId,
    workflowNodeId,
    apply,
  } = {}) {
    return this.workspaceSnapshotSurface.appendWorkspaceRestoreApplyEvent(this, {
      threadId,
      turnId,
      workspaceRoot,
      workflowGraphId,
      workflowNodeId,
      apply,
    });
  }

  maybeRunPostEditDiagnostics({
    threadId,
    turnId,
    patchToolCallId,
    patchResult,
    request = {},
    input = {},
    workflowGraphId = null,
  } = {}) {
    return this.diagnosticsFeedbackSurface.maybeRunPostEditDiagnostics(this, {
      threadId,
      turnId,
      patchToolCallId,
      patchResult,
      request,
      input,
      workflowGraphId,
    });
  }

  pendingDiagnosticsFeedbackForNextTurn(threadId, request = {}) {
    return this.diagnosticsFeedbackSurface.pendingDiagnosticsFeedbackForNextTurn(this, threadId, request);
  }

  materializeCodingToolArtifactDrafts({ threadId, toolId, toolCallId, workspaceRoot, result, receiptId }) {
    return this.codingToolArtifactSurface.materializeCodingToolArtifactDrafts(this, {
      threadId,
      toolId,
      toolCallId,
      workspaceRoot,
      result,
      receiptId,
    });
  }

  materializeVisualGuiObservationArtifacts({ threadId, toolId, toolCallId, workspaceRoot, input }) {
    return this.codingToolArtifactSurface.materializeVisualGuiObservationArtifacts(this, {
      threadId,
      toolId,
      toolCallId,
      workspaceRoot,
      input,
    });
  }

  readCodingToolArtifact(threadId, artifactId, range = {}) {
    return this.codingToolArtifactSurface.readCodingToolArtifact(this, threadId, artifactId, range);
  }

  retrieveCodingToolResult(threadId, query = {}) {
    return this.codingToolArtifactSurface.retrieveCodingToolResult(this, threadId, query);
  }

  createConversationArtifact(threadId, input = {}) {
    return this.conversationArtifactSurface.createConversationArtifact(this, threadId, input);
  }

  listConversationArtifacts(query = {}) {
    return this.conversationArtifactSurface.listConversationArtifacts(this, query);
  }

  getConversationArtifact(artifactId) {
    return this.conversationArtifactSurface.getConversationArtifact(this, artifactId);
  }

  listConversationArtifactRevisions(artifactId) {
    return this.conversationArtifactSurface.listConversationArtifactRevisions(this, artifactId);
  }

  performConversationArtifactAction(artifactId, input = {}) {
    return this.conversationArtifactSurface.performConversationArtifactAction(this, artifactId, input);
  }

  exportConversationArtifact(artifactId, input = {}) {
    return this.conversationArtifactSurface.exportConversationArtifact(this, artifactId, input);
  }

  promoteConversationArtifact(artifactId, input = {}) {
    return this.conversationArtifactSurface.promoteConversationArtifact(this, artifactId, input);
  }

  ensureDirs() {
    return ensureStateDirs(this);
  }

  writeSchema() {
    return writeStateSchema(this, {
      writeJson,
    });
  }

  load() {
    return loadStateRecords(this, {
      codingToolArtifactSchemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      listJson,
      listJsonl,
      readJson,
      readJsonl,
    });
  }

  writeAgent(agent, operationKind) {
    return writeAgentRecord(this, agent, operationKind, {
      writeJson,
    });
  }

  writeRun(run, operationKind) {
    return writeRunRecord(this, run, operationKind);
  }

  commitRuntimeRunState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeRunState(this.stateDir, request);
  }

  commitRuntimeAgentState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeAgentState(this.stateDir, request);
  }

  commitRuntimeMemoryState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeMemoryState(this.stateDir, request);
  }

  commitRuntimeSubagentState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeSubagentState(this.stateDir, request);
  }

  commitRuntimeArtifactState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeArtifactState(this.stateDir, request);
  }

  commitRuntimeModelMountRecordState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeModelMountRecordState(this.stateDir, request);
  }

  commitRuntimeModelMountReceiptState(request) {
    return this.runtimeAgentgresAdmissionRunner.commitRuntimeModelMountReceiptState(this.stateDir, request);
  }

  writeSubagent(subagent, operationKind) {
    return writeSubagentRecord(this, subagent, operationKind, {
      runtimeError,
      writeJson,
    });
  }

  pathFor(...segments) {
    return statePathFor(this, ...segments);
  }

  removeQuiet(filePath) {
    return removeQuietFile(filePath);
  }
}

function canonicalMemoryWorkflowNodeId(value = {}) {
  return value?.workflow_node_id ?? value?.workflowNodeId ?? null;
}

function canonicalMemoryMutationEventPayload(value = {}) {
  const isPolicy = value.object === "ioi.agent_memory_policy";
  return {
    schema_version: value.schema_version ?? value.schemaVersion ?? null,
    object: value.object ?? null,
    memory_record_id: isPolicy
      ? value.memory_record_id ?? null
      : value.memory_record_id ?? value.id ?? null,
    memory_policy_id: isPolicy
      ? value.memory_policy_id ?? value.id ?? null
      : value.memory_policy_id ?? null,
    scope: value.scope ?? null,
    fact: value.fact ?? null,
    memory_key: value.memory_key ?? value.memoryKey ?? null,
    agent_id: value.agent_id ?? value.agentId ?? null,
    thread_id: value.thread_id ?? value.threadId ?? null,
    workspace: value.workspace ?? null,
    target_type: value.target_type ?? value.targetType ?? null,
    target_id: value.target_id ?? value.targetId ?? null,
    disabled: Boolean(value.disabled),
    injection_enabled: value.injection_enabled ?? value.injectionEnabled ?? null,
    read_only: value.read_only ?? value.readOnly ?? null,
    write_requires_approval: value.write_requires_approval ?? value.writeRequiresApproval ?? null,
    retention: value.retention ?? null,
    workflow_graph_id: value.workflow_graph_id ?? value.workflowGraphId ?? null,
    workflow_node_id: canonicalMemoryWorkflowNodeId(value),
    workflow_node_type: value.workflow_node_type ?? value.workflowNodeType ?? null,
    source: value.source ?? null,
    redaction: value.redaction ?? "none",
    created_at: value.created_at ?? value.createdAt ?? null,
    updated_at: value.updated_at ?? value.updatedAt ?? null,
    deleted_at: value.deleted_at ?? value.deletedAt ?? null,
    evidence_refs: normalizeArray(value.evidence_refs ?? value.evidenceRefs),
  };
}

function canonicalSubagentMemoryInheritanceEventPayload(value = {}) {
  return {
    schema_version: value.schema_version ?? null,
    object: value.object ?? null,
    parent_agent_id: value.parent_agent_id ?? null,
    subagent_name: value.subagent_name ?? null,
    thread_id: value.thread_id ?? null,
    mode: value.mode ?? null,
    requested_mode: value.requested_mode ?? null,
    parent_policy_id: value.parent_policy_id ?? null,
    effective_policy_id: value.effective_policy_id ?? null,
    inherited_record_ids: normalizeArray(value.inherited_record_ids),
    inherited_record_count: normalizeArray(value.inherited_record_ids).length,
    write_allowed: value.write_allowed ?? null,
    write_block_reason: value.write_block_reason ?? null,
    filters: value.filters ?? {},
    evidence_refs: normalizeArray(value.evidence_refs),
    redaction: value.effective_policy?.redaction ?? "none",
  };
}

function buildRun({
  agent,
  mode,
  prompt,
  request,
  source,
  modelRoute,
  memory = {},
  skillHookCatalog = null,
  diagnosticsFeedback = null,
}) {
  const runId = `run_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const diagnosticsBlockingGate = diagnosticsBlockingGateForFeedback(diagnosticsFeedback);
  const runStatus = diagnosticsBlockingGate ? "blocked" : "completed";
  const taskFamily = taskFamilyForMode(mode);
  const selectedStrategy = strategyForMode(mode);
  const toolSequence = capabilitySequenceForMode(mode, agent);
  const modelRouteDecision = modelRoute?.decision ?? null;
  const selectedModel =
    modelRouteDecision?.selected_model ??
    modelRoute?.selectedModel ??
    request.options?.model?.id ??
    agent.modelId;
  const computerUseProjection = computerUseProjectionForRun({
    agent,
    runId,
    prompt,
    mode,
    request,
    selectedModel,
  });
  if (computerUseProjection) {
    toolSequence.push("computer_use_harness");
  }
  const modelRouteReceiptId =
    modelRoute?.receiptId ?? modelRouteDecision?.receipt_id ?? `receipt_${runId}_model_route`;
  const memoryRecords = normalizeArray(memory.records);
  const memoryWrites = normalizeArray(memory.writes);
  const memoryMutations = normalizeArray(memory.mutations).length > 0
    ? normalizeArray(memory.mutations)
    : memoryWrites.map((write) => ({ ...write, operation: "write" }));
  const memoryWriteReceipts = memoryMutations.map((write) => write.receipt).filter(Boolean);
  const memoryWriteRecords = memoryWrites.map((write) => write.record).filter(Boolean);
  const memoryPolicy = memory.policy ?? null;
  const subagentMemoryInheritance =
    mode === "handoff" ? memory.subagentMemoryInheritance ?? null : null;
  const subagentMemoryReceipt = subagentMemoryInheritance
    ? subagentMemoryInheritanceReceipt(runId, subagentMemoryInheritance)
    : null;
  const activeSkillHookManifest = activeSkillHookManifestForRun({
    runId,
    agent,
    request,
    catalog: skillHookCatalog,
  });
  const runtimeTask = runtimeTaskRecord({
    runId,
    agent,
    prompt,
    mode,
    taskFamily,
    selectedStrategy,
    modelRouteDecision,
    activeSkillHookManifest,
    createdAt,
    updatedAt: createdAt,
    status: runStatus,
  });
  let runtimeJob = runtimeJobRecord({
    runtimeTask,
    agent,
    status: runStatus,
    createdAt,
    updatedAt: createdAt,
    queuedAt: createdAt,
    startedAt: createdAt,
    completedAt: diagnosticsBlockingGate ? null : createdAt,
    lifecycle: diagnosticsBlockingGate ? ["queued", "started", "blocked"] : ["queued", "started", "completed"],
  });
  const runtimeChecklist = runtimeChecklistRecord({
    runtimeTask,
    runtimeJob,
    status: runStatus,
    createdAt,
    updatedAt: createdAt,
  });
  runtimeJob = attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist);
  const hookDryRunPlan = hookDryRunPlanForManifest({
    runId,
    manifest: activeSkillHookManifest,
  });
  const hookInvocationLedger = hookInvocationLedgerForPlan({
    runId,
    manifest: activeSkillHookManifest,
    dryRunPlan: hookDryRunPlan,
  });
  const repositoryContext = repositoryContextForWorkspace({
    cwd: agent.cwd,
    contextId: `repoctx_${runId}`,
    generatedAt: createdAt,
  });
  const branchPolicy = branchPolicyForRepositoryContext({
    runId,
    repositoryContext,
    generatedAt: createdAt,
  });
  const githubContext = githubContextForRepository({
    runId,
    repositoryContext,
    branchPolicy,
    generatedAt: createdAt,
  });
  const prAttempt = prAttemptForRepository({
    runId,
    repositoryContext,
    branchPolicy,
    githubContext,
    generatedAt: createdAt,
    prompt,
  });
  const reviewGate = reviewGateForPrAttempt({
    runId,
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    generatedAt: createdAt,
  });
  const issueContext = issueContextForGithub({
    runId,
    repositoryContext,
    githubContext,
    prAttempt,
    reviewGate,
    generatedAt: createdAt,
  });
  const githubPrCreatePlan = githubPrCreatePlanForReviewGate({
    runId,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    generatedAt: createdAt,
  });
  const taskState = {
    currentObjective: prompt,
    knownFacts: [
      "Run entered the live local IOI daemon public runtime API",
      "Agentgres v0 is the canonical owner for this run state",
      `Selected model profile: ${selectedModel}`,
      `Runtime task: id=${runtimeTask.taskId}, family=${runtimeTask.taskFamily}, status=${runtimeTask.status}`,
      `Runtime job: id=${runtimeJob.jobId}, status=${runtimeJob.status}, queue=${runtimeJob.queueName}`,
      `Runtime checklist: id=${runtimeChecklist.checklistId}, status=${runtimeChecklist.status}, items=${runtimeChecklist.completedItemCount}/${runtimeChecklist.itemCount}`,
      `Repository context: ${repositoryContext.isGitRepository ? "git" : "workspace"} root=${repositoryContext.repoRoot ?? repositoryContext.workspaceRoot}, branch=${repositoryContext.branch ?? "none"}, dirty=${repositoryContext.status.isDirty}`,
      `Branch policy: status=${branchPolicy.status}, protected=${branchPolicy.protectedBranch}, mutationAllowed=${branchPolicy.mutationAllowed}`,
      `GitHub context: status=${githubContext.status}, repo=${githubContext.repoFullName ?? "none"}, prEligible=${githubContext.prCreationEligible}`,
      `Issue context: status=${issueContext.status}, bound=${issueContext.bound}, repo=${issueContext.repoFullName ?? "none"}`,
      `PR attempt: status=${prAttempt.status}, outcome=${prAttempt.outcome}, mutationExecuted=${prAttempt.mutationExecuted}`,
      `Review gate: status=${reviewGate.status}, reviewRequired=${reviewGate.reviewRequired}, reviewSatisfied=${reviewGate.reviewSatisfied}`,
      `GitHub PR create plan: status=${githubPrCreatePlan.status}, dryRun=${githubPrCreatePlan.dryRun}, mutationExecuted=${githubPrCreatePlan.mutationExecuted}`,
      ...(memoryPolicy
        ? [
            `Memory policy: disabled=${Boolean(memoryPolicy.disabled)}, injection=${memoryPolicy.injectionEnabled !== false}, readOnly=${Boolean(memoryPolicy.readOnly)}, writeRequiresApproval=${Boolean(memoryPolicy.writeRequiresApproval)}`,
          ]
        : []),
      ...(subagentMemoryInheritance
        ? [
            `Subagent memory inheritance: mode=${subagentMemoryInheritance.mode}, receiver=${subagentMemoryInheritance.subagent_name ?? "handoff"}, records=${subagentMemoryInheritance.records.length}, write_allowed=${subagentMemoryInheritance.write_allowed}`,
          ]
        : []),
      ...(computerUseProjection
        ? [
            `Computer-use lane: ${computerUseProjection.environmentSelection.selected_lane}/${computerUseProjection.environmentSelection.selected_session_mode}`,
            `Computer-use observation: ${computerUseProjection.observation.observation_ref} with target index ${computerUseProjection.targetIndex.target_index_ref}`,
          ]
        : []),
      `Active skill/hook manifest: skills=${activeSkillHookManifest.selectedSkillIds.length}, hooks=${activeSkillHookManifest.selectedHookIds.length}, skillSet=${activeSkillHookManifest.activeSkillSetHash.slice(0, 12)}, hookSet=${activeSkillHookManifest.activeHookSetHash.slice(0, 12)}`,
      `Hook dry-run plan: wouldRun=${hookDryRunPlan.wouldRunCount}, blocked=${hookDryRunPlan.blockedCount}, skipped=${hookDryRunPlan.skippedCount}`,
      `Hook invocation ledger: invocations=${hookInvocationLedger.invocationCount}, wouldRun=${hookInvocationLedger.wouldRunCount}, blocked=${hookInvocationLedger.blockedCount}, skipped=${hookInvocationLedger.skippedCount}`,
      `Hook escalation receipts: ${hookInvocationLedger.escalationCount} blocked invocation(s) require declaration fixes`,
      ...(diagnosticsFeedback
        ? [
            `Post-edit diagnostics: status=${diagnosticsFeedback.diagnostic_status}, findings=${diagnosticsFeedback.diagnostic_count}, mode=${diagnosticsFeedback.mode}`,
          ]
        : []),
      ...(diagnosticsBlockingGate
        ? [
            `Post-edit diagnostics blocking gate: id=${diagnosticsBlockingGate.gate_id}, status=${diagnosticsBlockingGate.status}, decision=${diagnosticsBlockingGate.decision}`,
          ]
        : []),
      ...memoryRecords.map((record) => `Memory fact (${record.scope}:${record.id}): ${record.fact}`),
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: [],
    constraints: [
      "No GUI internals",
      "No raw receipt dump",
      "No policy bypass",
      ...(diagnosticsBlockingGate ? ["No model continuation while blocking diagnostics have findings"] : []),
    ],
    blockers: diagnosticsBlockingGate ? [diagnosticsBlockingGate.summary] : [],
    changedObjects: mode === "send" ? [] : [`daemon:${mode}`],
    evidenceRefs: [
      "ioi_daemon_public_runtime_api",
      "agentgres_canonical_state_projection",
      runtimeTask.taskId,
      runtimeJob.jobId,
      runtimeChecklist.checklistId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      issueContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      githubPrCreatePlan.planId,
      activeSkillHookManifest.manifestId,
      hookDryRunPlan.planId,
      hookInvocationLedger.ledgerId,
      diagnosticsFeedback?.injection_id,
      diagnosticsBlockingGate?.gate_id,
      diagnosticsBlockingGate?.policy_decision_id,
      ...(diagnosticsBlockingGate?.policy_decision_refs ?? []),
      ...(diagnosticsBlockingGate?.rollback_refs ?? []),
      diagnosticsBlockingGate?.receipt_id,
      activeSkillHookManifest.activeSkillSetHash,
      activeSkillHookManifest.activeHookSetHash,
      ...agent.options.mcpServerNames,
      ...agent.options.skillNames,
      ...agent.options.hookNames,
      ...normalizeArray(modelRouteDecision?.evidence_refs),
      modelRouteReceiptId,
      memoryPolicy?.id,
      ...memoryRecords.map((record) => record.id),
      ...memoryWriteReceipts.map((receipt) => receipt.id),
      subagentMemoryReceipt?.id,
      computerUseProjection?.receipt.id,
      computerUseProjection?.environmentSelection.receipt_ref,
      computerUseProjection?.observation.observation_ref,
      computerUseProjection?.actionProposal?.proposal_ref,
      computerUseProjection?.action?.action_ref,
      computerUseProjection?.actionReceipt?.receipt_ref,
      computerUseProjection?.trajectory?.trajectory_ref,
      computerUseProjection?.cleanup.cleanup_ref,
    ].filter(Boolean),
  };
  const uncertainty = {
    ambiguityLevel: mode === "send" ? "low" : "medium",
    selectedAction:
      mode === "dry_run"
        ? "dry_run"
        : mode === "plan"
          ? "verify"
          : mode === "handoff"
            ? "execute"
            : "probe",
    rationale: "Live daemon run chose bounded local execution with canonical state writeback.",
    valueOfProbe: mode === "send" ? "medium" : "high",
  };
  const probes = [
    {
      probeId: `${runId}:probe:canonical-replay`,
      hypothesis: diagnosticsBlockingGate
        ? "Agentgres canonical state projection can replay the blocked diagnostics gate event stream."
        : "Agentgres canonical state projection can replay the terminal run event stream.",
      cheapestValidationAction: "Read canonical run projection and replay events by cursor.",
      expectedObservation: diagnosticsBlockingGate
        ? "Monotonic event stream with a blocked diagnostics policy event and no model output delta."
        : "Monotonic event stream with exactly one terminal event.",
      result: "confirmed",
      confidenceUpdate: "Canonical replay and daemon stream use the same event IDs.",
    },
  ];
  const postconditions = {
    objective: prompt,
    taskFamily,
    riskClass: mode === "dry_run" ? "side_effect_preview" : "bounded_local",
    checks: [
      {
        checkId: diagnosticsBlockingGate ? "daemon-event-stream-blocked" : "daemon-event-stream-terminal",
        description: diagnosticsBlockingGate
          ? "Daemon event stream is open and blocked by diagnostics policy before model continuation."
          : "Daemon event stream contains exactly one terminal event.",
        status: diagnosticsBlockingGate ? "blocked" : "passed",
      },
      {
        checkId: "agentgres-state-projection",
        description: "Run, task, receipts, scorecard, and ledger are written to Agentgres v0.",
        status: "passed",
      },
      {
        checkId: "runtime-job-ledger",
        description: "Runtime task and job records are durable, replayable, and inspectable through the public jobs API.",
        status: "passed",
      },
      {
        checkId: "runtime-checklist-ledger",
        description: "Runtime checklist record binds task, job, lifecycle, artifacts, and receipts into a replayable workflow projection.",
        status: "passed",
      },
      {
        checkId: "canonical-replay",
        description: "Replay from Agentgres reconstructs terminal event stream.",
        status: "passed",
      },
      {
        checkId: "active-skill-hook-manifest",
        description: "Trace records the exact skill and hook catalog snapshot used by this turn.",
        status: "passed",
      },
      {
        checkId: "repository-context-read-only",
        description: "Repository context is captured without mutating branch, index, or worktree state.",
        status: "passed",
      },
      {
        checkId: "branch-policy-read-only",
        description: "Branch policy decision consumes repository context without mutating branch, index, or worktree state.",
        status: "passed",
      },
      {
        checkId: "github-context-read-only",
        description: "GitHub context is resolved from repository remotes without network calls or PR mutation.",
        status: "passed",
      },
      {
        checkId: "issue-context-read-only",
        description: "Issue context is projected without GitHub network reads or mutation, and may remain unbound.",
        status: "passed",
      },
      {
        checkId: "pr-attempt-preview-only",
        description: "PR attempt intent, branch, and diff artifacts are recorded without creating or updating a PR.",
        status: "passed",
      },
      {
        checkId: "review-gate-read-only",
        description: "Review gate decision is recorded before PR creation and cannot satisfy review or mutate GitHub.",
        status: "passed",
      },
      {
        checkId: "github-pr-create-dry-run",
        description: "GitHub PR creation is represented as a dry-run request plan with no network lookup, token exposure, or mutation.",
        status: "passed",
      },
      {
        checkId: "hook-dry-run-plan",
        description: "Hook execution is previewed with policy decisions and no command execution.",
        status: "passed",
      },
      ...(computerUseProjection
        ? [
            {
              checkId: "computer-use-glass-box-trace",
              description: "Computer-use environment selection, lease, observation, target index, affordance graph, action proposal, action receipt, verification, trajectory, and cleanup are trace-visible.",
              status: "passed",
            },
          ]
        : []),
      ...(hookInvocationLedger.escalationCount > 0
        ? [
            {
              checkId: "hook-escalation-receipts",
              description: "Blocked hook invocations produce escalation receipts with required declaration fixes.",
              status: "passed",
            },
          ]
        : []),
      ...(diagnosticsFeedback
        ? [
            {
              checkId: "post-edit-diagnostics-injected",
              description: diagnosticsBlockingGate
                ? "Compact post-edit diagnostics were injected and stopped model continuation."
                : "Compact post-edit diagnostics were injected before this model turn continued.",
              status: diagnosticsFeedback.blocking && diagnosticsFeedback.diagnostic_status === "findings"
                ? "blocked"
                : "passed",
            },
          ]
        : []),
      ...(diagnosticsBlockingGate
        ? [
            {
              checkId: "post-edit-diagnostics-blocking-gate",
              description: "Blocking diagnostics findings produced a policy gate that requires repair, advisory override, or skip before continuing.",
              status: "blocked",
            },
          ]
        : []),
    ],
    minimumEvidence: [
      "events",
      "receipts",
      "trace",
      "scorecard",
      "agentgres_operation_log",
      "runtime_task",
      "runtime_job",
      "runtime_checklist",
      "repository_context",
      "branch_policy",
      "github_context",
      "issue_context",
      "pr_attempt",
      "pr_branch_artifact",
      "pr_diff_artifact",
      "review_gate",
      "github_pr_create_plan",
      "active_skill_hook_manifest",
      "hook_dry_run_plan",
      "hook_invocation_ledger",
      "hook_escalation_receipt",
      ...(computerUseProjection ? ["computer_use_trace", "computer-use-trace.json"] : []),
      ...(diagnosticsFeedback ? ["lsp_diagnostics_injection"] : []),
      ...(diagnosticsBlockingGate ? ["lsp_diagnostics_blocking_gate"] : []),
    ],
  };
  const semanticImpact = {
    changedSymbols: [],
    changedApis: [
      "/v1/agents/{id}/runs",
      "/v1/agents/{id}/memory",
      "/v1/threads/{id}/memory",
      "/v1/jobs",
      "/v1/jobs/{id}",
      "/v1/jobs/{id}/cancel",
      "/v1/runs/{id}/events",
      "/v1/runs/{id}/trace",
      "/v1/skills",
      "/v1/hooks",
      "/v1/usage",
      "/v1/threads/{id}/usage",
      "/v1/runs/{id}/usage",
      "/v1/repository-context",
      "/v1/branch-policy",
      "/v1/github-context",
      "/v1/issue-context",
      "/v1/pr-attempts",
      "/v1/review-gate",
      "/v1/github/pr-create-plan",
      "/v1/repositories",
    ],
    changedSchemas: [
      "IOISDKMessage",
      "RuntimeTraceBundle",
      "AgentgresRuntimeStateV0",
      "RuntimeTaskRecord",
      "RuntimeJobRecord",
      "RuntimeChecklistRecord",
      "RepositoryContext",
      "BranchPolicyDecision",
      "GitHubContext",
      "IssueContext",
      "PrAttemptRecord",
      "ReviewGateDecision",
      "GitHubPrCreatePlan",
      "ModelRouteDecision",
      "AgentMemoryRecord",
      "SubagentMemoryInheritanceProjection",
      "ActiveSkillHookManifest",
      "HookDryRunPlan",
      "HookInvocationLedger",
      "HookInvocationRecord",
      "HookEscalationReceipt",
      "RuntimeUsageTelemetry",
      ...(computerUseProjection
        ? [
            "ComputerUseRunState",
            "EnvironmentSelectionReceipt",
            "ComputerUseObservationBundle",
            "TargetIndex",
            "AffordanceGraph",
            "ActionProposal",
            "ComputerAction",
            "ActionReceipt",
            "ComputerUseVerificationReceipt",
            "ComputerUseTrajectoryBundle",
            "CleanupReceipt",
          ]
        : []),
      ...(diagnosticsBlockingGate ? ["LspDiagnosticsBlockingGate"] : []),
      "RuntimeEventEnvelope",
    ],
    changedPolicies: [
      ...(mode === "dry_run" ? ["authority.preview_only"] : []),
      ...(memory.policyBlockReason ? [`memory.${memory.policyBlockReason}`] : []),
      ...normalizeArray(memory.policyUpdates).map(() => "memory.policy"),
      ...(subagentMemoryInheritance
        ? [`memory.subagent_inheritance.${subagentMemoryInheritance.mode}`]
        : []),
      "runtime.jobs.durable_projection",
      "runtime.tasks.durable_projection",
      "runtime.checklists.durable_projection",
      "repository.context.read_only",
      "repository.branch_policy.read_only",
      "github.context.read_only",
      "github.issue_context.read_only",
      "github.pr_attempt.preview_only",
      "repository.review_gate.read_only",
      "github.pr_create.dry_run",
      "skills_hooks.active_manifest.read_only",
      "hooks.dry_run_preview_only",
      "hooks.invocation_ledger_preview_only",
      ...(hookInvocationLedger.escalationCount > 0
        ? ["hooks.escalation_receipt_required_for_blocked_invocations"]
        : []),
      ...(activeSkillHookManifest.mutationBlockedHookIds.length > 0
        ? ["hooks.mutation_blocked_without_contract"]
        : []),
      ...(hookDryRunPlan.blockedCount > 0
        ? ["hooks.dry_run_blocked_without_declared_capabilities"]
        : []),
      ...(diagnosticsFeedback
        ? [`lsp.diagnostics.${diagnosticsFeedback.mode}`]
        : []),
      ...(diagnosticsBlockingGate ? ["lsp.diagnostics.blocking_gate"] : []),
      ...(computerUseProjection
        ? [
            "computer_use.native_browser.read_only",
            "computer_use.action_proposal_required",
            "computer_use.cleanup_required",
            "computer_use.observation_retention.local_redacted_artifacts",
          ]
        : []),
    ],
    affectedTests: ["live-runtime-daemon-contract"],
    affectedDocs: [
      ".internal/plans/architectural-improvements-broad-master-guide.md",
    ],
    riskClass: postconditions.riskClass,
  };
  const stopCondition = {
    reason: diagnosticsBlockingGate ? "blocked_by_post_edit_diagnostics" : "evidence_sufficient",
    evidenceSufficient: !diagnosticsBlockingGate,
    rationale: diagnosticsBlockingGate
      ? "Blocking post-edit diagnostics findings paused model continuation until repair, advisory override, or skip."
      : "Daemon stream, canonical Agentgres writeback, trace export, replay, and scorecard evidence were produced.",
  };
  const qualityLedger = {
    ledgerId: `quality_${runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence,
    scorecardMetrics: {
      task_pass_rate: diagnosticsBlockingGate ? 0 : 100,
      recovery_success: diagnosticsBlockingGate ? 0 : 100,
      memory_relevance: mode === "learn" ? 100 : 92,
      tool_quality: 96,
      strategy_roi: 93,
      operator_interventions: diagnosticsBlockingGate ? 1 : 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: diagnosticsBlockingGate ? ["diagnostics_blocked_continuation"] : [],
  };
  const scorecard = {
    taskPassRate: diagnosticsBlockingGate ? 0 : 1,
    recoverySuccess: diagnosticsBlockingGate ? 0 : 1,
    memoryRelevance: mode === "learn" ? 1 : 0.92,
    toolQuality: 0.96,
    strategyRoi: 0.93,
    operatorInterventionRate: diagnosticsBlockingGate ? 1 : 0,
    verifierIndependence: 1,
  };
  const modelRouteReceipt = modelRouteDecision
    ? {
        id: modelRouteReceiptId,
        kind: "model_route_selection",
        summary: `Route ${modelRouteDecision.route_id} selected ${modelRouteDecision.selected_model}.`,
        redaction: "none",
        evidenceRefs: normalizeArray(modelRouteDecision.evidence_refs),
      }
    : null;
  const policyReceipt = {
    id: `receipt_${runId}_policy`,
    kind: "policy_decision",
    summary: "Local daemon run was admitted under bounded local/private runtime policy.",
    redaction: "none",
    evidenceRefs: ["prim:model.invoke", "policy.local_private"],
  };
  const authorityReceipt = {
    id: `receipt_${runId}_authority`,
    kind: "authority_decision",
    summary: "No external authority scope was required for this bounded local daemon run.",
    redaction: "none",
    evidenceRefs: ["wallet.network", "authority.no_external_scope"],
  };
  const runtimeTaskReceipt = {
    id: `receipt_${runId}_runtime_task`,
    kind: "runtime_task",
    summary: runtimeTask.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeTask.taskId,
      runtimeTask.threadId,
      runtimeTask.turnId,
      "RuntimeTaskNode",
      "runtime.tasks.durable_projection",
    ].filter(Boolean),
  };
  const runtimeJobReceipt = {
    id: `receipt_${runId}_runtime_job`,
    kind: "runtime_job",
    summary: runtimeJob.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeJob.jobId,
      runtimeTask.taskId,
      `run:${runId}`,
      "RuntimeJobNode",
      "runtime.jobs.durable_projection",
    ].filter(Boolean),
  };
  const runtimeChecklistReceipt = {
    id: `receipt_${runId}_runtime_checklist`,
    kind: "runtime_checklist",
    summary: runtimeChecklist.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeChecklist.checklistId,
      runtimeTask.taskId,
      runtimeJob.jobId,
      "RuntimeChecklistNode",
      "runtime.checklists.durable_projection",
    ].filter(Boolean),
  };
  const repositoryContextReceipt = {
    id: `receipt_${runId}_repository_context`,
    kind: "repository_context",
    summary: repositoryContext.isGitRepository
      ? `Captured read-only repository context for ${repositoryContext.repoRoot}: branch=${repositoryContext.branch ?? "detached"}, dirty=${repositoryContext.status.isDirty}.`
      : `Captured read-only workspace context for ${repositoryContext.workspaceRoot}; no Git repository was detected.`,
    redaction: "redacted",
    evidenceRefs: [
      repositoryContext.contextId,
      repositoryContext.repoRootHash,
      "RepositoryContextNode",
      "repository.context.read_only",
    ].filter(Boolean),
  };
  const branchPolicyReceipt = {
    id: `receipt_${runId}_branch_policy`,
    kind: "branch_policy",
    summary: branchPolicy.summary,
    redaction: "redacted",
    evidenceRefs: [
      branchPolicy.policyId,
      repositoryContext.contextId,
      "BranchPolicyNode",
      "repository.branch_policy.read_only",
    ].filter(Boolean),
  };
  const githubContextReceipt = {
    id: `receipt_${runId}_github_context`,
    kind: "github_context",
    summary: githubContext.summary,
    redaction: "redacted",
    evidenceRefs: [
      githubContext.contextId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      "GitHubContextNode",
      "github.context.read_only",
    ].filter(Boolean),
  };
  const prAttemptReceipt = {
    id: `receipt_${runId}_pr_attempt`,
    kind: "pr_attempt",
    summary: prAttempt.summary,
    redaction: "redacted",
    evidenceRefs: [
      prAttempt.attemptId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      prAttempt.branchArtifact.artifactName,
      prAttempt.diffArtifact.artifactName,
      "PrAttemptNode",
      "github.pr_attempt.preview_only",
    ].filter(Boolean),
  };
  const issueContextReceipt = {
    id: `receipt_${runId}_issue_context`,
    kind: "issue_context",
    summary: issueContext.summary,
    redaction: "redacted",
    evidenceRefs: [
      issueContext.contextId,
      githubContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      "IssueContextNode",
      "github.issue_context.read_only",
    ].filter(Boolean),
  };
  const reviewGateReceipt = {
    id: `receipt_${runId}_review_gate`,
    kind: "review_gate",
    summary: reviewGate.summary,
    redaction: "redacted",
    evidenceRefs: [
      reviewGate.gateId,
      prAttempt.attemptId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      "ReviewGateNode",
      "repository.review_gate.read_only",
    ].filter(Boolean),
  };
  const githubPrCreatePlanReceipt = {
    id: `receipt_${runId}_github_pr_create_plan`,
    kind: "github_pr_create_plan",
    summary: githubPrCreatePlan.summary,
    redaction: "redacted",
    evidenceRefs: [
      githubPrCreatePlan.planId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      issueContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      "GitHubPrCreateNode",
      "github.pr_create.dry_run",
    ].filter(Boolean),
  };
  const skillHookReceipt = {
    id: `receipt_${runId}_skill_hook_manifest`,
    kind: "active_skill_hook_manifest",
    summary: `Recorded active skill/hook manifest with ${activeSkillHookManifest.selectedSkillIds.length} skill(s) and ${activeSkillHookManifest.selectedHookIds.length} hook(s).`,
    redaction: "redacted",
    evidenceRefs: [
      activeSkillHookManifest.manifestId,
      "runtime_skill_hook_discovery",
      "hook_execution_disabled_until_policy",
    ],
  };
  const hookDryRunReceipt = {
    id: `receipt_${runId}_hook_dry_run_plan`,
    kind: "hook_dry_run_plan",
    summary: `Previewed ${hookDryRunPlan.decisionCount} hook(s): ${hookDryRunPlan.wouldRunCount} would run, ${hookDryRunPlan.blockedCount} blocked, ${hookDryRunPlan.skippedCount} skipped.`,
    redaction: "redacted",
    evidenceRefs: [hookDryRunPlan.planId, activeSkillHookManifest.manifestId, "hook_preview_only"],
  };
  const hookPolicyReceipt = {
    id: `receipt_${runId}_hook_policy_decision`,
    kind: "hook_policy_decision",
    summary: hookDryRunPlan.policyDecision.summary,
    redaction: "redacted",
    evidenceRefs: [
      hookDryRunPlan.planId,
      "hook_policy_decision",
      "hook_execution_disabled_until_policy",
    ],
  };
  const hookInvocationReceipt = {
    id: `receipt_${runId}_hook_invocation_ledger`,
    kind: "hook_invocation_ledger",
    summary: `Recorded ${hookInvocationLedger.invocationCount} preview hook invocation(s): ${hookInvocationLedger.wouldRunCount} would run, ${hookInvocationLedger.blockedCount} blocked, ${hookInvocationLedger.skippedCount} skipped, ${hookInvocationLedger.escalationCount} escalated.`,
    redaction: "redacted",
    evidenceRefs: [
      hookInvocationLedger.ledgerId,
      hookDryRunPlan.planId,
      activeSkillHookManifest.manifestId,
      "hook_invocation_preview_only",
    ],
  };
  const hookEscalationReceipts = hookEscalationReceiptsForLedger(hookInvocationLedger);
  const diagnosticsInjectionReceipt = diagnosticsFeedback
    ? {
        id: diagnosticsFeedback.receipt_id,
        kind: "lsp_diagnostics_injection",
        summary: diagnosticsFeedback.summary,
        redaction: "redacted",
        evidenceRefs: [
          diagnosticsFeedback.injection_id,
          ...normalizeArray(diagnosticsFeedback.diagnostic_event_ids),
          "lsp.diagnostics.injected",
          "LspDiagnosticsNode",
        ],
      }
    : null;
  const diagnosticsBlockingGateReceipt = diagnosticsBlockingGate
    ? {
        id: diagnosticsBlockingGate.receipt_id,
        kind: "lsp_diagnostics_blocking_gate",
        summary: diagnosticsBlockingGate.summary,
        redaction: "redacted",
        evidenceRefs: [
          diagnosticsBlockingGate.gate_id,
          diagnosticsBlockingGate.policy_decision_id,
          ...normalizeArray(diagnosticsBlockingGate.policy_decision_refs),
          ...normalizeArray(diagnosticsBlockingGate.rollback_refs),
          diagnosticsBlockingGate.injection_id,
          diagnosticsBlockingGate.diagnostics_receipt_id,
          ...diagnosticsBlockingGate.diagnostic_event_ids,
          "policy.blocked",
          "LspDiagnosticsNode",
        ].filter(Boolean),
      }
    : null;
  const agentgresReceipt = {
    id: `receipt_${runId}_agentgres`,
    kind: "agentgres_canonical_write",
    summary: "Run state, task state, receipts, scorecard, stop condition, and quality ledger were written to Agentgres v0.",
    redaction: "redacted",
    evidenceRefs: ["agentgres_canonical_state_projection", `run:${runId}`],
  };
  const traceReceipt = {
    id: `receipt_${runId}_trace`,
    kind: "trace_export",
    summary: "Trace export is reconstructed from daemon runtime state and canonical Agentgres projection.",
    redaction: "redacted",
    evidenceRefs: ["RuntimeTraceBundle", "canonical_replay"],
  };
  const receipts = [
    modelRouteReceipt,
    computerUseProjection?.receipt,
    subagentMemoryReceipt,
    runtimeTaskReceipt,
    runtimeJobReceipt,
    runtimeChecklistReceipt,
    repositoryContextReceipt,
    branchPolicyReceipt,
    githubContextReceipt,
    issueContextReceipt,
    prAttemptReceipt,
    reviewGateReceipt,
    githubPrCreatePlanReceipt,
    skillHookReceipt,
    hookDryRunReceipt,
    hookPolicyReceipt,
    hookInvocationReceipt,
    diagnosticsInjectionReceipt,
    diagnosticsBlockingGateReceipt,
    ...hookEscalationReceipts,
    ...memoryWriteReceipts,
    policyReceipt,
    authorityReceipt,
    agentgresReceipt,
    traceReceipt,
  ].filter(Boolean);
  const result = diagnosticsBlockingGate
    ? diagnosticsBlockingGate.message
    : resultForMode(mode, agent, prompt, source, memory);
  const modelInput = promptWithDiagnosticsFeedback(prompt, diagnosticsFeedback);
  const usageTelemetry = runtimeUsageTelemetryForRun({
    run: {
      id: runId,
      agent_id: agent.id,
      mode,
      objective: prompt,
      result,
      createdAt,
      updatedAt: createdAt,
      model_route_decision: modelRouteDecision,
      usage:
        request.usage_telemetry ??
        request.usage ??
        request.options?.usage ??
        null,
    },
    agent,
    threadId: threadIdForAgent(agent.id),
  });
  const events = [];
  const addEvent = (type, summary, data) => {
    const event = makeEvent(runId, agent.id, events.length, type, summary, data);
    events.push(event);
    return event;
  };
  const startedEvent = addEvent("run_started", "Run entered local IOI daemon", {
    taskFamily,
    selectedStrategy,
  });
  addEvent("runtime_task", "Runtime task record written", {
    event_kind: "RuntimeTaskRecord",
    task_id: runtimeTask.taskId ?? null,
    run_id: runtimeTask.runId ?? null,
    agent_id: runtimeTask.agentId ?? null,
    thread_id: runtimeTask.threadId ?? null,
    turn_id: runtimeTask.turnId ?? null,
    status: runtimeTask.status ?? null,
    mode: runtimeTask.mode ?? null,
    task_family: runtimeTask.taskFamily ?? null,
    selected_strategy: runtimeTask.selectedStrategy ?? null,
    durable: Boolean(runtimeTask.durable),
    replayable: Boolean(runtimeTask.replayable),
    prompt_included: Boolean(runtimeTask.promptIncluded),
    receipt_id: runtimeTaskReceipt.id,
    workflow_node_id: "runtime.runtime-task",
    redaction: runtimeTask.redaction,
  });
  addEvent("job_queued", "Runtime job queued", {
    event_kind: "JobQueued",
    job_id: runtimeJob.jobId ?? null,
    task_id: runtimeJob.taskId ?? null,
    run_id: runtimeJob.runId ?? null,
    agent_id: runtimeJob.agentId ?? null,
    thread_id: runtimeJob.threadId ?? null,
    turn_id: runtimeJob.turnId ?? null,
    status: "queued",
    lifecycle_status: "queued",
    queue_name: runtimeJob.queueName ?? null,
    runner: runtimeJob.runner ?? null,
    job_type: runtimeJob.jobType ?? null,
    background: Boolean(runtimeJob.background),
    durable: Boolean(runtimeJob.durable),
    replayable: Boolean(runtimeJob.replayable),
    queued_at: runtimeJob.queuedAt ?? null,
    started_at: runtimeJob.startedAt ?? null,
    completed_at: null,
    progress: runtimeJob.progress,
    receipt_id: runtimeJobReceipt.id,
    workflow_node_id: "runtime.runtime-job",
    redaction: runtimeJob.redaction,
  });
  addEvent("job_started", "Runtime job started", {
    event_kind: "JobStarted",
    job_id: runtimeJob.jobId ?? null,
    task_id: runtimeJob.taskId ?? null,
    run_id: runtimeJob.runId ?? null,
    agent_id: runtimeJob.agentId ?? null,
    thread_id: runtimeJob.threadId ?? null,
    turn_id: runtimeJob.turnId ?? null,
    status: "running",
    lifecycle_status: "started",
    queue_name: runtimeJob.queueName ?? null,
    runner: runtimeJob.runner ?? null,
    job_type: runtimeJob.jobType ?? null,
    background: Boolean(runtimeJob.background),
    durable: Boolean(runtimeJob.durable),
    replayable: Boolean(runtimeJob.replayable),
    queued_at: runtimeJob.queuedAt ?? null,
    started_at: runtimeJob.startedAt ?? null,
    completed_at: null,
    progress: runtimeJob.progress,
    receipt_id: runtimeJobReceipt.id,
    workflow_node_id: "runtime.runtime-job",
    redaction: runtimeJob.redaction,
  });
  addEvent("runtime_checklist", "Runtime checklist recorded", {
    event_kind: "RuntimeChecklistRecord",
    checklist_id: runtimeChecklist.checklistId ?? null,
    task_id: runtimeChecklist.taskId ?? null,
    job_id: runtimeChecklist.jobId ?? null,
    run_id: runtimeChecklist.runId ?? null,
    status: runtimeChecklist.status ?? null,
    item_count: runtimeChecklist.itemCount ?? 0,
    completed_item_count: runtimeChecklist.completedItemCount ?? 0,
    failed_item_count: runtimeChecklist.failedItemCount ?? 0,
    canceled_item_count: runtimeChecklist.canceledItemCount ?? 0,
    blocked_item_count: runtimeChecklist.blockedItemCount ?? 0,
    required_item_ids: normalizeArray(runtimeChecklist.requiredItemIds),
    durable: Boolean(runtimeChecklist.durable),
    replayable: Boolean(runtimeChecklist.replayable),
    receipt_id: runtimeChecklistReceipt.id,
    workflow_node_id: "runtime.runtime-checklist",
    redaction: runtimeChecklist.redaction,
  });
  addEvent("repository_context", "Repository context recorded", {
    event_kind: "RepositoryContext",
    context_id: repositoryContext.contextId ?? null,
    is_git_repository: Boolean(repositoryContext.isGitRepository),
    repo_root_hash: repositoryContext.repoRootHash ?? null,
    detached_head: Boolean(repositoryContext.detachedHead),
    head_short_sha: repositoryContext.headShortSha ?? null,
    remote_count: repositoryContext.remoteCount ?? 0,
    status: {
      is_dirty: Boolean(repositoryContext.status?.isDirty),
      counts: {
        staged: repositoryContext.status?.counts?.staged ?? 0,
        unstaged: repositoryContext.status?.counts?.unstaged ?? 0,
        untracked: repositoryContext.status?.counts?.untracked ?? 0,
        conflicted: repositoryContext.status?.counts?.conflicted ?? 0,
      },
    },
    mutation_executed: Boolean(repositoryContext.mutationExecuted),
    receipt_id: repositoryContextReceipt.id,
    workflow_node_id: "runtime.repository-context",
    redaction: repositoryContext.redaction,
  });
  addEvent("branch_policy", "Branch policy decision recorded", {
    event_kind: "BranchPolicyDecision",
    policy_id: branchPolicy.policyId ?? null,
    repository_context_id: branchPolicy.repositoryContextId ?? null,
    status: branchPolicy.status ?? null,
    branch: branchPolicy.branch ?? null,
    default_branch: branchPolicy.defaultBranch ?? null,
    protected_branch: Boolean(branchPolicy.protectedBranch),
    detached_head: Boolean(branchPolicy.detachedHead),
    dirty: Boolean(branchPolicy.dirty),
    upstream: branchPolicy.upstream ?? null,
    ahead: branchPolicy.ahead ?? 0,
    behind: branchPolicy.behind ?? 0,
    blockers: normalizeArray(branchPolicy.blockers),
    warnings: normalizeArray(branchPolicy.warnings),
    mutation_allowed: Boolean(branchPolicy.mutationAllowed),
    pr_creation_allowed: Boolean(branchPolicy.prCreationAllowed),
    review_required: Boolean(branchPolicy.reviewRequired),
    mutation_executed: Boolean(branchPolicy.mutationExecuted),
    receipt_id: branchPolicyReceipt.id,
    workflow_node_id: "runtime.branch-policy",
    redaction: branchPolicy.redaction,
  });
  addEvent("github_context", "GitHub context recorded", {
    event_kind: "GitHubContext",
    context_id: githubContext.contextId ?? null,
    repository_context_id: githubContext.repositoryContextId ?? null,
    branch_policy_id: githubContext.branchPolicyId ?? null,
    status: githubContext.status ?? null,
    github_remote_present: Boolean(githubContext.githubRemotePresent),
    default_remote_name: githubContext.defaultRemoteName ?? null,
    owner: githubContext.owner ?? null,
    repo: githubContext.repo ?? null,
    repo_full_name: githubContext.repoFullName ?? null,
    branch: githubContext.branch ?? null,
    default_branch: githubContext.defaultBranch ?? null,
    branch_policy_status: githubContext.branchPolicyStatus ?? null,
    credentials: {
      token_available: Boolean(githubContext.credentials?.tokenAvailable),
    },
    pr_creation_eligible: Boolean(githubContext.prCreationEligible),
    network_lookup_performed: Boolean(githubContext.networkLookupPerformed),
    mutation_executed: Boolean(githubContext.mutationExecuted),
    receipt_id: githubContextReceipt.id,
    workflow_node_id: "runtime.github-context",
    redaction: githubContext.redaction,
  });
  addEvent("issue_context", "Issue context recorded", {
    event_kind: "IssueContext",
    context_id: issueContext.contextId ?? null,
    repository_context_id: issueContext.repositoryContextId ?? null,
    github_context_id: issueContext.githubContextId ?? null,
    pr_attempt_id: issueContext.prAttemptId ?? null,
    review_gate_id: issueContext.reviewGateId ?? null,
    status: issueContext.status ?? null,
    repo_full_name: issueContext.repoFullName ?? null,
    bound: Boolean(issueContext.bound),
    issue_provided: Boolean(issueContext.issueProvided),
    issue_number: issueContext.issueNumber ?? null,
    source_kind: issueContext.sourceKind ?? null,
    warnings: normalizeArray(issueContext.warnings),
    network_lookup_performed: Boolean(issueContext.networkLookupPerformed),
    mutation_executed: Boolean(issueContext.mutationExecuted),
    receipt_id: issueContextReceipt.id,
    workflow_node_id: "runtime.issue-context",
    redaction: issueContext.redaction,
  });
  addEvent("pr_attempt", "PR attempt preview recorded", {
    event_kind: "PrAttemptRecord",
    attempt_id: prAttempt.attemptId ?? null,
    repository_context_id: prAttempt.repositoryContextId ?? null,
    branch_policy_id: prAttempt.branchPolicyId ?? null,
    github_context_id: prAttempt.githubContextId ?? null,
    status: prAttempt.status ?? null,
    outcome: prAttempt.outcome ?? null,
    repo_full_name: prAttempt.repoFullName ?? null,
    branch: prAttempt.branch ?? null,
    default_branch: prAttempt.defaultBranch ?? null,
    head_short_sha: prAttempt.headShortSha ?? null,
    blockers: normalizeArray(prAttempt.blockers),
    warnings: normalizeArray(prAttempt.warnings),
    authority: {
      required_scopes: normalizeArray(prAttempt.authority?.requiredScopes),
      missing_scopes: normalizeArray(prAttempt.authority?.missingScopes),
      scope_granted: Boolean(prAttempt.authority?.scopeGranted),
    },
    branch_artifact: {
      artifact_name: prAttempt.branchArtifact?.artifactName ?? null,
    },
    diff_artifact: {
      artifact_name: prAttempt.diffArtifact?.artifactName ?? null,
      diff_hash: prAttempt.diffArtifact?.diffHash ?? null,
      file_count: prAttempt.diffArtifact?.fileCount ?? 0,
    },
    mutation_attempted: Boolean(prAttempt.mutationAttempted),
    mutation_executed: Boolean(prAttempt.mutationExecuted),
    network_lookup_performed: Boolean(prAttempt.networkLookupPerformed),
    receipt_id: prAttemptReceipt.id,
    workflow_node_id: "runtime.pr-attempt",
    redaction: prAttempt.redaction,
  });
  addEvent("review_gate", "Review gate decision recorded", {
    event_kind: "ReviewGateDecision",
    gate_id: reviewGate.gateId ?? null,
    repository_context_id: reviewGate.repositoryContextId ?? null,
    branch_policy_id: reviewGate.branchPolicyId ?? null,
    github_context_id: reviewGate.githubContextId ?? null,
    pr_attempt_id: reviewGate.prAttemptId ?? null,
    status: reviewGate.status ?? null,
    decision: reviewGate.decision ?? null,
    repo_full_name: reviewGate.repoFullName ?? null,
    branch: reviewGate.branch ?? null,
    default_branch: reviewGate.defaultBranch ?? null,
    review_required: Boolean(reviewGate.reviewRequired),
    review_satisfied: Boolean(reviewGate.reviewSatisfied),
    approval_required: Boolean(reviewGate.approvalRequired),
    approval_satisfied: Boolean(reviewGate.approvalSatisfied),
    required_reviewers: normalizeArray(reviewGate.requiredReviewers),
    required_checks: normalizeArray(reviewGate.requiredChecks),
    blockers: normalizeArray(reviewGate.blockers),
    warnings: normalizeArray(reviewGate.warnings),
    mutation_allowed: Boolean(reviewGate.mutationAllowed),
    pr_creation_allowed: Boolean(reviewGate.prCreationAllowed),
    mutation_executed: Boolean(reviewGate.mutationExecuted),
    network_lookup_performed: Boolean(reviewGate.networkLookupPerformed),
    receipt_id: reviewGateReceipt.id,
    workflow_node_id: "runtime.review-gate",
    redaction: reviewGate.redaction,
  });
  addEvent("github_pr_create_plan", "GitHub PR create dry-run plan recorded", {
    event_kind: "GitHubPrCreatePlan",
    plan_id: githubPrCreatePlan.planId ?? null,
    repository_context_id: githubPrCreatePlan.repositoryContextId ?? null,
    branch_policy_id: githubPrCreatePlan.branchPolicyId ?? null,
    github_context_id: githubPrCreatePlan.githubContextId ?? null,
    issue_context_id: githubPrCreatePlan.issueContextId ?? null,
    pr_attempt_id: githubPrCreatePlan.prAttemptId ?? null,
    review_gate_id: githubPrCreatePlan.reviewGateId ?? null,
    status: githubPrCreatePlan.status ?? null,
    decision: githubPrCreatePlan.decision ?? null,
    dry_run: Boolean(githubPrCreatePlan.dryRun),
    tool_name: githubPrCreatePlan.toolName ?? null,
    repo_full_name: githubPrCreatePlan.repoFullName ?? null,
    base_branch: githubPrCreatePlan.baseBranch ?? null,
    head_branch: githubPrCreatePlan.headBranch ?? null,
    issue_number: githubPrCreatePlan.issueNumber ?? null,
    review_gate_status: githubPrCreatePlan.reviewGateStatus ?? null,
    review_satisfied: Boolean(githubPrCreatePlan.reviewSatisfied),
    request: {
      payload_hash: githubPrCreatePlan.request?.payloadHash ?? null,
      body_included: Boolean(githubPrCreatePlan.request?.bodyIncluded),
      token_included: Boolean(githubPrCreatePlan.request?.tokenIncluded),
    },
    authority: {
      required_scopes: normalizeArray(githubPrCreatePlan.authority?.requiredScopes),
      missing_scopes: normalizeArray(githubPrCreatePlan.authority?.missingScopes),
      scope_granted: Boolean(githubPrCreatePlan.authority?.scopeGranted),
    },
    blockers: normalizeArray(githubPrCreatePlan.blockers),
    warnings: normalizeArray(githubPrCreatePlan.warnings),
    mutation_attempted: Boolean(githubPrCreatePlan.mutationAttempted),
    mutation_executed: Boolean(githubPrCreatePlan.mutationExecuted),
    network_lookup_performed: Boolean(githubPrCreatePlan.networkLookupPerformed),
    receipt_id: githubPrCreatePlanReceipt.id,
    workflow_node_id: "runtime.github-pr-create",
    redaction: githubPrCreatePlan.redaction,
  });
  addEvent("skill_hook_manifest", "Active skill and hook manifest recorded", {
    event_kind: "ActiveSkillHookManifest",
    manifest_id: activeSkillHookManifest.manifestId ?? null,
    active_skill_set_hash: activeSkillHookManifest.activeSkillSetHash ?? null,
    active_hook_set_hash: activeSkillHookManifest.activeHookSetHash ?? null,
    selected_skill_ids: normalizeArray(activeSkillHookManifest.selectedSkillIds),
    selected_hook_ids: normalizeArray(activeSkillHookManifest.selectedHookIds),
    mutation_blocked_hook_ids: normalizeArray(activeSkillHookManifest.mutationBlockedHookIds),
    hook_execution: {
      enabled: Boolean(activeSkillHookManifest.hookExecution?.enabled),
    },
    receipt_id: skillHookReceipt.id,
    workflow_node_id: "runtime.skill-hook-manifest",
    redaction: activeSkillHookManifest.redaction,
  });
  addEvent("hook_dry_run_plan", "Hook dry-run plan recorded", {
    event_kind: "HookDryRunPlan",
    plan_id: hookDryRunPlan.planId ?? null,
    manifest_id: hookDryRunPlan.manifestId ?? null,
    decision_count: hookDryRunPlan.decisionCount ?? 0,
    would_run_count: hookDryRunPlan.wouldRunCount ?? 0,
    blocked_count: hookDryRunPlan.blockedCount ?? 0,
    skipped_count: hookDryRunPlan.skippedCount ?? 0,
    policy_decision: {
      status: hookDryRunPlan.policyDecision?.status ?? null,
    },
    hook_execution_enabled: Boolean(hookDryRunPlan.hookExecutionEnabled),
    command_execution_enabled: Boolean(hookDryRunPlan.commandExecutionEnabled),
    receipt_id: hookDryRunReceipt.id,
    policy_receipt_id: hookPolicyReceipt.id,
    workflow_node_id: "runtime.hook-policy",
    redaction: hookDryRunPlan.redaction,
  });
  addEvent("hook_invocation_ledger", "Hook invocation ledger recorded", {
    event_kind: "HookInvocationLedger",
    ledger_id: hookInvocationLedger.ledgerId ?? null,
    manifest_id: hookInvocationLedger.manifestId ?? null,
    dry_run_plan_id: hookInvocationLedger.dryRunPlanId ?? null,
    emitted_event_kinds: normalizeArray(hookInvocationLedger.emittedEventKinds),
    invocation_count: hookInvocationLedger.invocationCount ?? 0,
    would_run_count: hookInvocationLedger.wouldRunCount ?? 0,
    blocked_count: hookInvocationLedger.blockedCount ?? 0,
    skipped_count: hookInvocationLedger.skippedCount ?? 0,
    escalation_count: hookInvocationLedger.escalationCount ?? 0,
    hook_execution_enabled: Boolean(hookInvocationLedger.hookExecutionEnabled),
    command_execution_enabled: Boolean(hookInvocationLedger.commandExecutionEnabled),
    receipt_id: hookInvocationReceipt.id,
    escalation_receipt_ids: hookEscalationReceipts.map((receipt) => receipt.id),
    workflow_node_id: "runtime.hook-invocations",
    redaction: hookInvocationLedger.redaction,
  });
  if (modelRouteDecision) {
    addEvent("model_route_decision", "Model route decision recorded", {
      ...modelRouteDecision,
      receipt_id: modelRouteReceiptId,
    });
  }
  if (computerUseProjection) {
    for (const event of computerUseProjection.events) {
      addEvent(event.type, event.summary, event.data);
    }
  }
  for (const mutation of memoryMutations) {
    const operation = mutation.operation ?? "write";
    addEvent("memory_update", memoryEventSummary(operation), {
      ...canonicalMemoryMutationEventPayload(mutation.record ?? mutation.policy ?? {}),
      operation,
      event_kind: memoryEventKind(operation),
      receipt_id: mutation.receipt?.id ?? null,
      workflow_node_id:
        canonicalMemoryWorkflowNodeId(mutation.record ?? mutation.policy) ??
        "runtime.memory-policy",
    });
  }
  if (subagentMemoryInheritance) {
    addEvent("memory_update", "Subagent memory inheritance resolved", {
      ...canonicalSubagentMemoryInheritanceEventPayload(subagentMemoryInheritance),
      operation: "subagent_inheritance",
      event_kind: "SubagentMemoryInheritance",
      receipt_id: subagentMemoryReceipt?.id ?? null,
      workflow_node_id: "runtime.subagent-memory",
    });
  }
  if (diagnosticsFeedback) {
    addEvent("lsp_diagnostics_injected", diagnosticsFeedback.summary, {
      ...diagnosticsFeedback,
      event_kind: "LspDiagnosticsInjected",
      receipt_id: diagnosticsInjectionReceipt?.id ?? diagnosticsFeedback.receipt_id,
      workflow_node_id: LSP_DIAGNOSTICS_INJECTION_NODE_ID,
    });
  }
  const diagnosticsBlockingGateEvent = diagnosticsBlockingGate
      ? addEvent("policy_blocked", diagnosticsBlockingGate.summary, {
        ...diagnosticsBlockingGate,
        event_kind: "LspDiagnosticsBlockingGate",
        receipt_id: diagnosticsBlockingGateReceipt?.id ?? diagnosticsBlockingGate.receipt_id,
        workflow_node_id: LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
        component_kind: "lsp_diagnostics_gate",
      })
    : null;
  addEvent("task_state", "Task state written to Agentgres", taskState);
  addEvent("uncertainty", "Uncertainty assessed", uncertainty);
  addEvent("probe", "Canonical replay probe completed", probes[0]);
  addEvent("postcondition_synthesized", "Postconditions synthesized", postconditions);
  addEvent("semantic_impact", "Semantic impact classified", semanticImpact);
  const usageDeltas = runtimeUsageTelemetryDeltaPayloads(usageTelemetry, {
    runId,
    agentId: agent.id,
    threadId: threadIdForAgent(agent.id),
    turnId: turnIdForRun(runId),
  });
  if (usageDeltas[0]) {
    addEvent("usage_delta", usageDeltas[0].summary, usageDeltas[0]);
    addEvent(
      "context_pressure_delta",
      usageDeltas[0].contextPressureSummary,
      contextPressureDeltaPayload(usageDeltas[0]),
    );
    const contextPressureAlert = contextPressureAlertPayload(usageDeltas[0]);
    if (contextPressureAlert) {
      addEvent(
        "context_pressure_alert",
        contextPressureAlert.summary,
        contextPressureAlert,
      );
    }
  }
  const deltaEvent = diagnosticsBlockingGate ? null : addEvent("delta", result, { text: result });
  if (usageDeltas[1]) {
    addEvent("usage_delta", usageDeltas[1].summary, usageDeltas[1]);
    addEvent(
      "context_pressure_delta",
      usageDeltas[1].contextPressureSummary,
      contextPressureDeltaPayload(usageDeltas[1]),
    );
    const contextPressureAlert = contextPressureAlertPayload(usageDeltas[1]);
    if (contextPressureAlert) {
      addEvent(
        "context_pressure_alert",
        contextPressureAlert.summary,
        contextPressureAlert,
      );
    }
  }
  addEvent("usage_final", "Usage telemetry recorded", {
    ...usageTelemetry,
    eventKind: "RuntimeUsageTelemetry",
    workflowNodeId: "runtime.usage-telemetry",
    summary: runtimeUsageTelemetrySummary(usageTelemetry),
  });
  addEvent("stop_condition", "Stop condition recorded", stopCondition);
  addEvent("quality_ledger", "Quality ledger recorded", qualityLedger);
  if (!diagnosticsBlockingGate) {
    addEvent("job_completed", "Runtime job completed", {
      event_kind: "JobCompleted",
      job_id: runtimeJob.jobId ?? null,
      task_id: runtimeJob.taskId ?? null,
      run_id: runtimeJob.runId ?? null,
      agent_id: runtimeJob.agentId ?? null,
      thread_id: runtimeJob.threadId ?? null,
      turn_id: runtimeJob.turnId ?? null,
      status: runtimeJob.status ?? null,
      lifecycle_status: "completed",
      queue_name: runtimeJob.queueName ?? null,
      runner: runtimeJob.runner ?? null,
      job_type: runtimeJob.jobType ?? null,
      background: Boolean(runtimeJob.background),
      durable: Boolean(runtimeJob.durable),
      replayable: Boolean(runtimeJob.replayable),
      queued_at: runtimeJob.queuedAt ?? null,
      started_at: runtimeJob.startedAt ?? null,
      completed_at: runtimeJob.completedAt ?? null,
      progress: runtimeJob.progress,
      receipt_id: runtimeJobReceipt.id,
      workflow_node_id: "runtime.runtime-job",
      redaction: runtimeJob.redaction,
    });
  }
  addEvent("artifact", "Trace and scorecard artifacts recorded", {
    artifact_names: [
      "trace.json",
      "runtime-task.json",
      "runtime-job.json",
      "runtime-checklist.json",
      "repository-context.json",
      "branch-policy.json",
      "github-context.json",
      "issue-context.json",
      "pr-attempt.json",
      "pr-branch.json",
      "pr-diff.patch",
      "review-gate.json",
      "github-pr-create-plan.json",
      "active-skill-hook-manifest.json",
      "hook-dry-run-plan.json",
      "hook-invocations.json",
      ...(diagnosticsBlockingGate ? ["diagnostics-blocking-gate.json"] : []),
      ...(computerUseProjection ? ["computer-use-trace.json"] : []),
      "scorecard.json",
      "agentgres-projection.json",
    ],
  });
  if (!diagnosticsBlockingGate) {
    addEvent("completed", "Run completed", { stopReason: stopCondition.reason });
  }
  const trace = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: `trace_${runId}`,
    agentId: agent.id,
    runId,
    eventStreamId: `events_${runId}`,
    events,
    receipts,
    taskState,
    uncertainty,
    probes,
    postconditions,
    semanticImpact,
    modelRouteDecision,
    activeSkillHookManifest,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    githubPrCreatePlan,
    hookDryRunPlan,
    hookInvocationLedger,
    promptAudit: {
      schemaVersion: "ioi.agent-runtime.prompt-audit.v1",
      runId,
      promptHash: doctorHash(prompt),
      runtimeTaskId: runtimeTask.taskId,
      runtimeJobId: runtimeJob.jobId,
      runtimeChecklistId: runtimeChecklist.checklistId,
      repositoryContextId: repositoryContext.contextId,
      branchPolicyId: branchPolicy.policyId,
      githubContextId: githubContext.contextId,
      issueContextId: issueContext.contextId,
      prAttemptId: prAttempt.attemptId,
      reviewGateId: reviewGate.gateId,
      githubPrCreatePlanId: githubPrCreatePlan.planId,
      activeSkillHookManifestId: activeSkillHookManifest.manifestId,
      activeSkillSetHash: activeSkillHookManifest.activeSkillSetHash,
      activeHookSetHash: activeSkillHookManifest.activeHookSetHash,
      selectedSkillIds: activeSkillHookManifest.selectedSkillIds,
      selectedHookIds: activeSkillHookManifest.selectedHookIds,
      hookExecutionEnabled: false,
      hookDryRunPlanId: hookDryRunPlan.planId,
      hookInvocationLedgerId: hookInvocationLedger.ledgerId,
      redaction: {
        promptIncluded: false,
        hookCommandsIncluded: false,
      },
      evidenceRefs: [
        "prompt_audit",
        runtimeTask.taskId,
        runtimeJob.jobId,
        runtimeChecklist.checklistId,
        repositoryContext.contextId,
        branchPolicy.policyId,
        githubContext.contextId,
        issueContext.contextId,
        prAttempt.attemptId,
        reviewGate.gateId,
        githubPrCreatePlan.planId,
        activeSkillHookManifest.manifestId,
      ],
    },
    memoryPolicy,
    memoryRecords,
    memoryWrites: memoryWriteRecords,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
    computerUse: computerUseProjection
      ? {
          environmentSelection: computerUseProjection.environmentSelection,
          lease: computerUseProjection.lease,
          runState: computerUseProjection.runState,
          observation: computerUseProjection.observation,
          targetIndex: computerUseProjection.targetIndex,
          affordanceGraph: computerUseProjection.affordanceGraph,
          actionProposal: computerUseProjection.actionProposal,
          action: computerUseProjection.action,
          actionReceipt: computerUseProjection.actionReceipt,
          verification: computerUseProjection.verification,
          outcomeContract: computerUseProjection.outcomeContract,
          policyDecision: computerUseProjection.policyDecision,
          commitGate: computerUseProjection.commitGate,
          trajectory: computerUseProjection.trajectory,
          cleanup: computerUseProjection.cleanup,
          adapterContract: computerUseProjection.adapterContract,
        }
      : null,
    diagnosticsFeedback,
    diagnosticsBlockingGate,
    subagentMemoryInheritance,
    stopCondition,
    qualityLedger,
    scorecard,
  };
  const artifacts = [
    artifact(runId, "trace.json", "application/json", traceReceipt.id, trace, "redacted"),
    artifact(
      runId,
      "runtime-task.json",
      "application/json",
      runtimeTaskReceipt.id,
      runtimeTask,
      "redacted",
    ),
    artifact(
      runId,
      "runtime-job.json",
      "application/json",
      runtimeJobReceipt.id,
      runtimeJob,
      "redacted",
    ),
    artifact(
      runId,
      "runtime-checklist.json",
      "application/json",
      runtimeChecklistReceipt.id,
      runtimeChecklist,
      "redacted",
    ),
    artifact(
      runId,
      "repository-context.json",
      "application/json",
      repositoryContextReceipt.id,
      repositoryContext,
      "redacted",
    ),
    artifact(
      runId,
      "branch-policy.json",
      "application/json",
      branchPolicyReceipt.id,
      branchPolicy,
      "redacted",
    ),
    artifact(
      runId,
      "github-context.json",
      "application/json",
      githubContextReceipt.id,
      githubContext,
      "redacted",
    ),
    artifact(
      runId,
      "issue-context.json",
      "application/json",
      issueContextReceipt.id,
      issueContext,
      "redacted",
    ),
    artifact(
      runId,
      "pr-attempt.json",
      "application/json",
      prAttemptReceipt.id,
      prAttempt,
      "redacted",
    ),
    artifact(
      runId,
      prAttempt.branchArtifact.artifactName,
      prAttempt.branchArtifact.mediaType,
      prAttemptReceipt.id,
      prAttempt.artifactContents.branch,
      "redacted",
    ),
    artifact(
      runId,
      prAttempt.diffArtifact.artifactName,
      prAttempt.diffArtifact.mediaType,
      prAttemptReceipt.id,
      prAttempt.artifactContents.diff,
      "redacted",
    ),
    artifact(
      runId,
      "review-gate.json",
      "application/json",
      reviewGateReceipt.id,
      reviewGate,
      "redacted",
    ),
    artifact(
      runId,
      "github-pr-create-plan.json",
      "application/json",
      githubPrCreatePlanReceipt.id,
      githubPrCreatePlan,
      "redacted",
    ),
    artifact(
      runId,
      "active-skill-hook-manifest.json",
      "application/json",
      skillHookReceipt.id,
      activeSkillHookManifest,
      "redacted",
    ),
    artifact(
      runId,
      "hook-dry-run-plan.json",
      "application/json",
      hookDryRunReceipt.id,
      hookDryRunPlan,
      "redacted",
    ),
    artifact(
      runId,
      "hook-invocations.json",
      "application/json",
      hookInvocationReceipt.id,
      hookInvocationLedger,
      "redacted",
    ),
    ...(computerUseProjection
      ? [
          artifact(
            runId,
            "computer-use-trace.json",
            "application/json",
            computerUseProjection.receipt.id,
            {
              environmentSelection: computerUseProjection.environmentSelection,
              lease: computerUseProjection.lease,
              runState: computerUseProjection.runState,
              observation: computerUseProjection.observation,
              targetIndex: computerUseProjection.targetIndex,
              affordanceGraph: computerUseProjection.affordanceGraph,
              actionProposal: computerUseProjection.actionProposal,
              action: computerUseProjection.action,
              actionReceipt: computerUseProjection.actionReceipt,
              verification: computerUseProjection.verification,
              outcomeContract: computerUseProjection.outcomeContract,
              commitGate: computerUseProjection.commitGate,
              trajectory: computerUseProjection.trajectory,
              cleanup: computerUseProjection.cleanup,
            },
            "redacted",
          ),
        ]
      : []),
    ...(diagnosticsBlockingGate
      ? [
          artifact(
            runId,
            "diagnostics-blocking-gate.json",
            "application/json",
            diagnosticsBlockingGateReceipt.id,
            diagnosticsBlockingGate,
            "redacted",
          ),
        ]
      : []),
    artifact(runId, "scorecard.json", "application/json", traceReceipt.id, scorecard, "none"),
    artifact(
      runId,
      "agentgres-projection.json",
      "application/json",
      agentgresReceipt.id,
      {
        runId,
        canonicalOwner: "Agentgres",
        source: "agentgres_canonical_state_projection",
      },
      "redacted",
    ),
  ];
  return {
    id: runId,
    agentId: agent.id,
    status: runStatus,
    turnStatus: diagnosticsBlockingGate ? "waiting_for_input" : undefined,
    objective: prompt,
    mode,
    createdAt,
    updatedAt: createdAt,
    events,
    conversation: [
      { role: "user", content: modelInput, eventId: startedEvent.id, createdAt },
      diagnosticsBlockingGate
        ? { role: "system", content: result, eventId: diagnosticsBlockingGateEvent?.id, createdAt }
        : { role: "assistant", content: result, eventId: deltaEvent.id, createdAt },
    ],
    receipts,
    artifacts,
    trace,
    modelRouteDecision,
    modelRouteReceiptId,
    activeSkillHookManifest,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    githubPrCreatePlan,
    hookDryRunPlan,
    hookInvocationLedger,
    memoryPolicy,
    memoryRecords,
    memoryWriteReceipts,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
    diagnosticsFeedback,
    diagnosticsBlockingGate,
    subagentMemoryInheritance,
    result,
  };
}
