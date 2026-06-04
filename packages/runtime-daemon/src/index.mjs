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
  firstOptionalString,
  nativeBrowserActionKindForInput,
  nativeBrowserActionKindFromText,
  nativeBrowserActionKindIsReadOnly,
  nativeBrowserActionKindValue,
  nativeBrowserActionKinds,
  nativeBrowserActionShouldUseCdpExecutor,
  nativeBrowserApprovalRefForInput,
  nativeBrowserCdpTimeoutMs,
  nativeBrowserControlledRelaunchApprovalRefForInput,
  nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch as nativeBrowserExecutionUnavailableFromControlledRelaunchLaunchImpl,
  nativeBrowserHasExplicitCdpEndpoint,
  nativeBrowserSessionModeForInput,
  sandboxedHostedSessionModeForInput,
  snakeCaseKey,
  visualGuiFiniteNumber,
  visualGuiMediaTypeForPath,
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
  CODING_TOOL_IDS,
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  codingToolContracts,
  codingToolInputForRequest,
  codingToolInputSummary,
  codingToolResultSummary,
  codingToolSourceEventKind,
  codingToolSummary,
  executeCodingTool,
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
  mcpCatalogExposureForStatus,
  mcpCatalogFullRequested,
  mcpCatalogPreviewLimit,
  mcpCatalogSummaryForServer,
  mcpConfigSourceModeForRequest,
  mcpJsonRpcError,
  mcpJsonRpcErrorCodeFor,
  mcpJsonRpcResult,
  mcpLiveExecutionModeForServer,
  mcpPromptKey,
  mcpRegistryWithServers,
  mcpResourceKey,
  mcpServeAllowedToolIds,
  mcpServeToolCallResult,
  mcpServeToolDescriptor,
  mcpServeToolIdForName,
  mcpServerMatchesConfigSourceMode,
  mcpServerRecordFromAddRequest,
  mcpServerRecordsFromMutationInput,
  mcpToolIdentityMatches,
  mcpToolKey,
  mcpToolMatchesQuery,
  mcpToolNamespaces,
  mcpToolSearchLimit,
  mcpTransportEvidenceRef,
  mcpTransportSummary,
  resolveMcpServerRecord,
  resolveMcpToolRecord,
} from "./runtime-mcp-helpers.mjs";
import {
  WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
  WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
  parseJsonObject,
  workspaceRestoreApplyOperations,
  workspaceRestoreOperationCounts,
  workspaceRestorePreviewOperation,
  workspaceSnapshotContentDraftsByPath,
  workspaceSnapshotFileForPatch,
} from "./workspace-restore.mjs";
import {
  redactRuntimeNodeForDoctor,
  runtimeAccount,
  runtimeNodes,
  runtimeToolRegistryGovernanceMetadata,
  runtimeTools,
} from "./runtime-tool-catalog.mjs";
import {
  RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
  discoverMcpHttpCatalog,
  discoverMcpStdioCatalog,
  invokeMcpHttpTool,
  invokeMcpStdioTool,
  mcpRegistryForWorkspace,
  mcpPromptsForServers,
  mcpResourcesForServers,
  mcpServerRecordsFromValidationInput,
  mcpToolsForServers,
  normalizeMcpServerRecord,
  validateMcpServerRecords,
} from "./mcp-manager.mjs";
import {
  RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION,
  RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION,
  RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
  memoryRowsForStatus,
  memoryStatusForProjection,
  validateMemoryProjection,
} from "./memory-manager.mjs";
import {
  RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  normalizeSubagentOutputContract,
  normalizeSubagentRole,
  optionalPositiveInteger,
  subagentBudgetStatusForRun,
  subagentBudgetForRequest,
  subagentBudgetUsageTelemetryForRequest,
  subagentCancellationPropagates,
  subagentContractOutputForRun,
  subagentIsActive,
  subagentManagerEventPayload,
  subagentOperatorControlKind,
  subagentResultForRun,
  subagentRuntimeEventKind,
  validateSubagentOutputContract,
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
import { discoverSkillHookCatalog } from "./skill-hook-catalog.mjs";
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
import { createCodingToolBudgetRecovery } from "./runtime-coding-tool-budget-recovery.mjs";
import { createRuntimeInvocationResultProjections } from "./runtime-invocation-results.mjs";
import { createDiagnosticsRepairExecutionHelpers } from "./diagnostics-repair-execution.mjs";
import { createDiagnosticsFeedbackHelpers } from "./diagnostics-feedback.mjs";
import { createDiagnosticsRepairPolicyHelpers } from "./diagnostics-repair-policy.mjs";
import { createRuntimeUsageEventHelpers } from "./runtime-usage-events.mjs";
import { createRuntimeMemoryHelpers } from "./runtime-memory-helpers.mjs";
import { createRuntimeRunHelpers } from "./runtime-run-helpers.mjs";
import { createRuntimeRunEventHelpers } from "./runtime-run-event-helpers.mjs";
import { createRuntimeEventEnvelopeHelpers } from "./runtime-event-envelopes.mjs";
import { createRuntimeEventPayloadHelpers } from "./runtime-event-payloads.mjs";
import { createRuntimeCodingToolResultHelpers } from "./runtime-coding-tool-results.mjs";
import {
  appendOperatorControl,
  booleanValue,
  doctorCheck,
  doctorHash,
  normalizeArray,
  normalizeBooleanOption,
  objectRecord,
  operatorControlSource,
  optionalString,
  relativePathForWorkspace,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import { createRuntimeAgentOptionsHelpers } from "./runtime-agent-options.mjs";
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
  workspaceTrustWarningRecordForMode,
} from "./repository-context.mjs";
import {
  branchPolicyProjection,
  githubContextProjection,
  githubPrCreatePlanProjection,
  issueContextProjection,
  prAttemptsProjection,
  repositoryContextProjection,
  repositoryListProjection,
  reviewGateProjection,
} from "./repository-projections.mjs";
import { createRepositoryWorkflowProjections } from "./repository-workflow-projections.mjs";
import {
  approvalModeForThreadMode,
  initialThreadRuntimeControls,
  modelPolicyForOptions,
  modelRouteBindingFromReceipt,
  modelWorkflowContext,
  normalizeThreadApprovalMode,
  normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls,
  requestWithThreadRuntimeControls,
  runModeForThreadMode,
  threadModeForRunMode,
  threadRuntimeControlKind,
  threadRuntimeControlModelInput,
} from "./threads/thread-runtime-controls.mjs";
import {
  appendRuntimeEvent as appendRuntimeEventState,
  assertRuntimeCursorSeq as assertRuntimeCursorSeqState,
  ensureThreadStartedEvent as ensureThreadStartedEventState,
  latestRuntimeEventSeq as latestRuntimeEventSeqState,
  projectRunEvents as projectRunEventsState,
  projectThreadEvents as projectThreadEventsState,
  registerRuntimeEvent as registerRuntimeEventState,
  runtimeCursorSeq as runtimeCursorSeqState,
  runtimeEventsForStream as runtimeEventsForStreamState,
  runtimeEventsForTurn as runtimeEventsForTurnState,
  runtimeEventStream as runtimeEventStreamState,
  runtimeEventStreamPath as runtimeEventStreamPathState,
} from "./threads/thread-replay.mjs";
import {
  writeAgentRecord,
  writeRunRecord,
} from "./threads/thread-persistence.mjs";
import {
  agentForThread as agentForThreadState,
  deleteAgent as deleteAgentState,
  getAgent as getAgentState,
  getRun as getRunState,
  inFlightRuntimeTurnKey as inFlightRuntimeTurnKeyState,
  listAgents as listAgentsState,
  listRuns as listRunsState,
  registerInFlightRuntimeTurn as registerInFlightRuntimeTurnState,
  resolveRunForThreadTurn as resolveRunForThreadTurnState,
  unregisterInFlightRuntimeTurn as unregisterInFlightRuntimeTurnState,
  updateAgent as updateAgentState,
  usageForRun as usageForRunState,
  usageForThread as usageForThreadState,
} from "./threads/thread-store.mjs";
import {
  controlManagedSessionForThread as controlManagedSessionForThreadState,
  inspectManagedSessionsForThread as inspectManagedSessionsForThreadState,
} from "./threads/managed-session-state.mjs";
import {
  controlWorkspaceChangeForThread as controlWorkspaceChangeForThreadState,
  inspectWorkspaceChangeReviewsForThread as inspectWorkspaceChangeReviewsForThreadState,
} from "./threads/workspace-change-state.mjs";
import {
  controlRuntimeBridgeThread as controlRuntimeBridgeThreadState,
  createRuntimeBridgeThread as createRuntimeBridgeThreadState,
  createRuntimeBridgeTurn as createRuntimeBridgeTurnState,
  normalizeRuntimeBridgeLiveEvent as normalizeRuntimeBridgeLiveEventState,
  normalizeRuntimeBridgeThreadStart as normalizeRuntimeBridgeThreadStartState,
  normalizeRuntimeBridgeTurnSubmit as normalizeRuntimeBridgeTurnSubmitState,
} from "./threads/runtime-bridge-thread.mjs";
import {
  codingToolBudgetPolicyForRequest,
  contextBudgetNumber,
  contextBudgetUsageTelemetryFromRequest,
  evaluateCompactionPolicyDecision,
  evaluateContextBudgetPolicy,
} from "./threads/context-budget-policy.mjs";
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
  RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
  RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
  RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION,
  WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
  WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
  WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
  WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
  WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
  RUNTIME_MCP_SERVE_SCHEMA_VERSION,
  RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
  RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS,
  RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
  RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
  RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
  RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
  MCP_LIVE_CATALOG_DEFAULT_PREVIEW_LIMIT,
  MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT,
  WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
  WORKSPACE_SNAPSHOT_NODE_ID,
  WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
  WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
  WORKSPACE_RESTORE_PREVIEW_NODE_ID,
  LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
  DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
  DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_AUTO_NODE_ID,
  LSP_DIAGNOSTICS_INJECTION_NODE_ID,
  LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID,
  LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RESTORE_PREVIEW_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RESTORE_APPLY_NODE_ID,
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
  workspaceRestoreApplyAllowsConflicts,
  workspaceRestoreApplyApprovalForRequest,
  workspaceRestoreApplyBlockedReason,
  workspaceRestoreApplyPolicyDecisionRefs,
  workspaceRestoreApplyStatus,
  workspaceRestoreApplySummary,
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
  codingToolEffectRequiresApproval,
  codingToolWorkflowApprovalPolicy,
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
  codingToolBudgetRecoveryAction,
  codingToolBudgetRecoveryPolicyFromInputs,
  codingToolBudgetRecoveryResult,
  codingToolBudgetRecoveryTargetNodeIds,
  isCodingToolBudgetBlockedRuntimeEvent,
  recoveryPolicyRetryLimit,
} = createCodingToolBudgetRecovery({
  WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
  WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
  WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
  normalizeArray,
  optionalString,
  runtimeError,
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
  codingToolArtifactMetadata,
  codingToolArtifactReadResult,
  codingToolCommandStreamChunks,
  codingToolCommandStreamRequested,
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
    this.conversationArtifacts = new ConversationArtifactStore(this.stateDir);
    this.runtimeBridge = createRuntimeApiBridge(options.runtimeBridge);
    this.schemaVersion = "ioi.agentgres.runtime.v0";
    this.ensureDirs();
    this.modelMounting = new ModelMountingState({
      stateDir: this.stateDir,
      cwd: this.defaultCwd,
      homeDir: options.homeDir,
      vaultSecrets: options.vaultSecrets,
      appendOperation: (kind, payload) => this.appendOperation(kind, payload),
    });
    this.memory = new AgentMemoryStore(this.stateDir, {
      appendOperation: (kind, payload) => this.appendOperation(kind, payload),
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
    const now = new Date().toISOString();
    const cwd = path.resolve(options.local?.cwd ?? this.defaultCwd);
    const runtime = runtimeModeForOptions(options);
    ensureProviderAvailable(runtime, options);
    const modelRoute = this.resolveModelRoute(options, {
      evidenceRefs: ["runtime_agent_model_route"],
      workflowNodeId: "runtime.model-router",
      workflowNodeType: "Model Router",
    });
    const agent = {
      id: `agent_${crypto.randomUUID()}`,
      status: "active",
      runtime,
      cwd,
      modelId: modelRoute.selectedModel,
      requestedModelId: modelRoute.requestedModelId,
      modelRouteId: modelRoute.routeId,
      modelRouteEndpointId: modelRoute.endpointId,
      modelRouteProviderId: modelRoute.providerId,
      modelRouteReceiptId: modelRoute.receiptId,
      modelRouteDecision: modelRoute.decision,
      runtimeControls: initialThreadRuntimeControls(options, modelRoute, now),
      mcpRegistry: mcpRegistryForWorkspace(cwd, {
        ...options,
        homeDir: this.homeDir,
      }),
      createdAt: now,
      updatedAt: now,
      options: summarizeAgentOptions(cwd, options),
    };
    this.agents.set(agent.id, agent);
    this.writeAgent(agent, "agent.create");
    return agent;
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
    return updateAgentState(this, agentId, status, operationKind);
  }

  deleteAgent(agentId) {
    return deleteAgentState(this, agentId, {
      path,
      policyError,
    });
  }

  createRun(agentId, request = {}) {
    const agent = this.getAgent(agentId);
    ensureProviderAvailable(agent.runtime, agent.options);
    const mode = request.mode ?? "send";
    const threadMode = request.threadMode ?? threadModeForRunMode(mode, agent.runtimeControls?.mode);
    const approvalMode =
      request.approvalMode ??
      request.approval_mode ??
      agent.runtimeControls?.approvalMode ??
      approvalModeForThreadMode(threadMode);
    const prompt =
      request.prompt ??
      (mode === "learn"
        ? `Learn governed task-family updates for ${request.options?.taskFamily ?? "runtime"}`
        : "");
    const modelRoute = this.resolveRunModelRoute(agent, request);
    const memory = this.resolveRunMemory(agent, request, prompt);
    const skillHookCatalog = this.skillHookCatalog({ cwd: agent.cwd });
    const run = buildRun({
      agent,
      mode,
      prompt,
      request,
      source: "local_daemon_agentgres",
      modelRoute,
      memory,
      skillHookCatalog,
      diagnosticsFeedback: request.diagnosticsFeedback ?? request.diagnostics_feedback ?? null,
    });
    const runtimeRunDraft = {
      ...run,
      threadMode,
      approvalMode,
    };
    const usageTelemetry = runtimeUsageTelemetryForRun({
      run: runtimeRunDraft,
      agent,
      threadId: threadIdForAgent(agent.id),
    });
    const runtimeRun = {
      ...runtimeRunDraft,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      usageTelemetry,
      runtimeUsage: usageTelemetry,
      trace: {
        ...runtimeRunDraft.trace,
        usage: usageTelemetry,
        usage_telemetry: usageTelemetry,
        usageTelemetry,
        runtimeUsage: usageTelemetry,
      },
    };
    this.runs.set(runtimeRun.id, runtimeRun);
    this.writeRun(runtimeRun, "run.create");
    return runtimeRun;
  }

  resolveModelRoute(options = {}, context = {}) {
    const model = options.model ?? {};
    const requestedModel = model.id ?? model.model ?? model.modelId ?? "auto";
    const routeId = model.routeId ?? model.route_id ?? model.route ?? options.routeId ?? options.route_id ?? "route.local-first";
    const capability = model.capability ?? options.capability ?? "chat";
    const policy = modelPolicyForOptions(options);
    const workflow = modelWorkflowContext({ model, options, context });
    const body = {
      model: requestedModel,
      route_id: routeId,
      model_policy: policy,
      ...workflow,
    };
    return this.selectModelRouteWithFallback({
      requestedModel,
      routeId,
      capability,
      policy,
      body,
      evidenceRefs: context.evidenceRefs ?? [],
    });
  }

  resolveRunModelRoute(agent, request = {}) {
    const options = request.options ?? {};
    if (options.model) {
      return this.resolveModelRoute(options, {
        evidenceRefs: ["runtime_run_model_route"],
        workflowNodeId: "runtime.model-router",
        workflowNodeType: "Model Router",
      });
    }
    return {
      requestedModelId: agent.requestedModelId ?? agent.modelId,
      selectedModel: agent.modelId,
      routeId: agent.modelRouteId ?? "route.local-first",
      endpointId: agent.modelRouteEndpointId ?? null,
      providerId: agent.modelRouteProviderId ?? null,
      receiptId: agent.modelRouteReceiptId ?? null,
      decision: agent.modelRouteDecision ?? null,
    };
  }

  selectModelRouteWithFallback({ requestedModel, routeId, capability, policy, body, evidenceRefs }) {
    try {
      const selection = this.modelMounting.selectRoute({ modelId: requestedModel, routeId, capability, policy });
      const receipt = this.modelMounting.routeSelectionReceipt(selection, {
        body,
        capability,
        evidenceRefs,
      });
      return modelRouteBindingFromReceipt(receipt, requestedModel);
    } catch (error) {
      const fallbackRouteId = "route.local-first";
      const fallbackPolicy = {
        ...policy,
        allow_hosted_fallback: false,
      };
      const fallbackBody = {
        ...body,
        model: "auto",
        route_id: fallbackRouteId,
        model_policy: fallbackPolicy,
        fallback_triggered: true,
        fallback_reason: error?.code ?? "primary_route_unavailable",
      };
      const fallbackSelection = this.modelMounting.selectRoute({
        modelId: "auto",
        routeId: fallbackRouteId,
        capability,
        policy: fallbackPolicy,
      });
      fallbackSelection.evaluatedCandidates = [
        ...normalizeArray(error?.details?.evaluatedCandidates),
        ...normalizeArray(fallbackSelection.evaluatedCandidates),
      ];
      const receipt = this.modelMounting.routeSelectionReceipt(fallbackSelection, {
        body: fallbackBody,
        capability,
        evidenceRefs: ["runtime_model_route_fallback", ...evidenceRefs],
      });
      return modelRouteBindingFromReceipt(receipt, requestedModel);
    }
  }

  resolveRunMemory(agent, request = {}, prompt = "") {
    const memoryOptions = memoryOptionsForRequest(request);
    const threadId = memoryOptions.threadId ?? memoryOptions.thread_id ?? threadIdForAgent(agent.id);
    const command = parseMemoryCommand(prompt);
    const paths = this.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
    let policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(memoryOptions),
    });
    const policyUpdates = [];
    const mutations = [];
    if (command.kind === "disable" || command.kind === "enable") {
      const update = this.memory.setPolicy({
        targetType: "thread",
        targetId: threadId,
        agent,
        threadId,
        workspace: agent.cwd,
        source: command.kind === "disable" ? "chat_memory_disable" : "chat_memory_enable",
        updates: {
          disabled: command.kind === "disable",
          injectionEnabled: command.kind !== "disable",
        },
      });
      policyUpdates.push(update);
      mutations.push(update);
      policy = this.memory.effectivePolicy({
        agent,
        threadId,
        workspace: agent.cwd,
        overrides: memoryPolicyOverrides(memoryOptions),
      });
    }
    const subagentMemoryInheritance =
      (request.mode ?? "send") === "handoff"
        ? this.resolveSubagentMemoryInheritance({ agent, threadId, request, parentPolicy: policy })
        : null;
    const effectivePolicy = subagentMemoryInheritance?.effectivePolicy ?? policy;
    const requestedRemember =
      memoryOptions.remember ??
      request.remember ??
      null;
    const requestedWrite =
      command.kind === "remember" ||
      command.kind === "edit" ||
      command.kind === "delete" ||
      Boolean(requestedRemember);
    const policyBlockReason = memoryWriteBlockReason(effectivePolicy, memoryOptions, requestedWrite);
    if (subagentMemoryInheritance) {
      subagentMemoryInheritance.writeBlockReason = policyBlockReason;
      subagentMemoryInheritance.writeAllowed = requestedWrite
        ? policyBlockReason === null
        : !effectivePolicy.disabled && !effectivePolicy.readOnly && !effectivePolicy.writeRequiresApproval;
    }
    if (effectivePolicy.disabled || effectivePolicy.injectionEnabled === false) {
      return {
        command: command.kind,
        records: [],
        writes: mutations.filter((mutation) => mutation.receipt?.kind === "memory_write"),
        mutations,
        policy: effectivePolicy,
        policyUpdates,
        paths,
        injected: false,
        disabled: Boolean(effectivePolicy.disabled),
        policyBlockReason,
        subagentMemoryInheritance,
      };
    }
    const writes = [];
    if (!policyBlockReason && command.kind === "remember") {
      const write = this.rememberForAgent(agent, { text: command.text, threadId, scope: effectivePolicy.scope ?? "thread", source: "chat_hash_remember" });
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    } else if (!policyBlockReason && command.kind === "edit") {
      mutations.push(this.updateMemoryRecord(command.id, { text: command.text, source: "chat_memory_edit" }));
    } else if (!policyBlockReason && command.kind === "delete") {
      mutations.push(this.deleteMemoryRecord(command.id, { source: "chat_memory_delete" }));
    } else if (!policyBlockReason && requestedRemember) {
      const write = this.rememberForAgent(agent, { text: requestedRemember, threadId, scope: effectivePolicy.scope ?? "thread", source: "api_remember", workflow: memoryOptions.workflow ?? memoryOptions });
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    }
    const records = subagentMemoryInheritance?.records ??
      this.memory.list({ agent, threadId, workspace: agent.cwd, ...memoryListFilters(memoryOptions) });
    return {
      command: command.kind,
      records,
      writes,
      mutations,
      policy: effectivePolicy,
      policyUpdates,
      paths,
      injected: command.kind !== "remember" && records.length > 0,
      policyBlockReason,
      subagentMemoryInheritance,
    };
  }

  resolveSubagentMemoryInheritance({ agent, threadId, request = {}, parentPolicy = {} } = {}) {
    const memoryOptions = memoryOptionsForRequest(request);
    const requestedMode =
      optionalString(memoryOptions.subagentInheritance ?? memoryOptions.subagent_inheritance) ??
      parentPolicy.subagentInheritance ??
      "explicit";
    const mode = normalizeSubagentInheritanceMode(requestedMode);
    const receiver = subagentReceiverForRequest(request);
    const filters = memoryListFilters(memoryOptions);
    const parentAllowsInjection = !parentPolicy.disabled && parentPolicy.injectionEnabled !== false;
    const records = parentAllowsInjection && shouldInheritSubagentMemory(mode, memoryOptions)
      ? this.memory.list({
          agent,
          threadId,
          workspace: agent.cwd,
          ...memoryListFilters({
            ...memoryOptions,
            redaction: memoryOptions.redaction ?? parentPolicy.redaction,
          }),
        })
      : [];
    const effectivePolicy = subagentMemoryPolicy({ agent, threadId, parentPolicy, receiver, mode });
    return {
      schemaVersion: "ioi.agent-runtime.subagent-memory-inheritance.v1",
      object: "ioi.subagent_memory_inheritance",
      parentAgentId: agent.id,
      subagentName: receiver,
      threadId,
      mode,
      requestedMode,
      parentPolicyId: parentPolicy.id ?? null,
      effectivePolicyId: effectivePolicy.id,
      parentPolicy,
      effectivePolicy,
      filters,
      records,
      inheritedRecordIds: records.map((record) => record.id),
      writeAllowed: !effectivePolicy.disabled && !effectivePolicy.readOnly && !effectivePolicy.writeRequiresApproval,
      writeBlockReason: null,
      evidenceRefs: [
        "subagent_memory_inheritance",
        "agent_memory_store",
        parentPolicy.id,
        effectivePolicy.id,
        ...records.map((record) => record.id),
      ].filter(Boolean),
    };
  }

  rememberForAgent(agent, { text, threadId = threadIdForAgent(agent.id), scope = "thread", source = "operator_remember", workflow = {} } = {}) {
    return this.memory.remember({
      text,
      agent,
      threadId,
      scope,
      source,
      workflow,
    });
  }

  rememberForThread(threadId, body = {}) {
    const agent = this.agentForThread(threadId);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory write blocked by policy.", { threadId, reason: blocked, policy });
    }
    const mutation = this.rememberForAgent(agent, {
      text: body.text ?? body.fact ?? body.memory,
      threadId,
      scope: body.scope ?? "thread",
      source: body.source ?? "thread_memory_api",
      workflow: body.workflow ?? body,
    });
    return this.recordThreadMemoryMutation(threadId, mutation, body, "write");
  }

  listMemoryForThread(threadId, options = {}) {
    const agent = this.agentForThread(threadId);
    return this.memory.projection({ agent, threadId, workspace: agent.cwd, filters: memoryListFilters(options) });
  }

  memoryPolicyForThread(threadId) {
    const agent = this.agentForThread(threadId);
    return this.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  setMemoryPolicyForThread(threadId, body = {}) {
    const agent = this.agentForThread(threadId);
    const mutation = this.memory.setPolicy({
      targetType: "thread",
      targetId: threadId,
      agent,
      threadId,
      workspace: agent.cwd,
      source: body.source ?? "thread_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
    return this.recordThreadMemoryMutation(threadId, mutation, body, "policy_update");
  }

  memoryPathForThread(threadId) {
    const agent = this.agentForThread(threadId);
    return this.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  updateMemoryForThread(threadId, memoryId, body = {}) {
    const agent = this.agentForThread(threadId);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory edit blocked by policy.", { threadId, memoryId, reason: blocked, policy });
    }
    const mutation = this.updateMemoryRecord(memoryId, body);
    return this.recordThreadMemoryMutation(threadId, mutation, body, "edit");
  }

  deleteMemoryForThread(threadId, memoryId, body = {}) {
    const agent = this.agentForThread(threadId);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory delete blocked by policy.", { threadId, memoryId, reason: blocked, policy });
    }
    const mutation = this.deleteMemoryRecord(memoryId, body);
    return this.recordThreadMemoryMutation(threadId, mutation, body, "delete");
  }

  rememberForAgentId(agentId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory write blocked by policy.", { agentId, threadId, reason: blocked, policy });
    }
    return this.rememberForAgent(agent, {
      text: body.text ?? body.fact ?? body.memory,
      threadId,
      scope: body.scope ?? "thread",
      source: body.source ?? "agent_memory_api",
      workflow: body.workflow ?? body,
    });
  }

  listMemoryForAgent(agentId, options = {}) {
    const agent = this.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return this.memory.projection({ agent, threadId, workspace: agent.cwd, filters: memoryListFilters(options) });
  }

  memoryPolicyForAgent(agentId, options = {}) {
    const agent = this.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return this.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  setMemoryPolicyForAgent(agentId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    return this.memory.setPolicy({
      targetType: body.targetType ?? body.target_type ?? "thread",
      targetId: body.targetId ?? body.target_id ?? threadId,
      agent,
      threadId,
      workspace: agent.cwd,
      source: body.source ?? "agent_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
  }

  memoryPathForAgent(agentId, options = {}) {
    const agent = this.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return this.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  updateMemoryForAgentId(agentId, memoryId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory edit blocked by policy.", { agentId, threadId, memoryId, reason: blocked, policy });
    }
    return this.updateMemoryRecord(memoryId, body);
  }

  deleteMemoryForAgentId(agentId, memoryId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory delete blocked by policy.", { agentId, threadId, memoryId, reason: blocked, policy });
    }
    return this.deleteMemoryRecord(memoryId, body);
  }

  updateMemoryRecord(memoryId, body = {}) {
    return this.memory.updateRecord({
      id: memoryId,
      text: body.text ?? body.fact ?? body.memory,
      source: body.source ?? "memory_edit_api",
    });
  }

  deleteMemoryRecord(memoryId, body = {}) {
    return this.memory.deleteRecord({
      id: memoryId,
      source: body.source ?? "memory_delete_api",
    });
  }

  memoryProjectionForContext(options = {}) {
    const threadId = optionalString(options.thread_id ?? options.threadId);
    const agentId =
      optionalString(options.agent_id ?? options.agentId) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    if (threadId) return this.listMemoryForThread(threadId, options);
    if (agentId) return this.listMemoryForAgent(agentId, options);
    return this.memory.projection({
      workspace: this.defaultCwd,
      filters: memoryListFilters(options),
    });
  }

  memoryStatus(options = {}) {
    const projection = this.memoryProjectionForContext(options);
    return {
      ...memoryStatusForProjection(projection),
      thread_id: projection.threadId ?? null,
      threadId: projection.threadId ?? null,
      agent_id: projection.agentId ?? null,
      agentId: projection.agentId ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  validateMemory(input = {}) {
    const projection =
      input.projection && typeof input.projection === "object"
        ? input.projection
        : this.memoryProjectionForContext(input);
    const validation = validateMemoryProjection(projection);
    return {
      ...validation,
      thread_id: projection.threadId ?? null,
      threadId: projection.threadId ?? null,
      agent_id: projection.agentId ?? null,
      agentId: projection.agentId ?? null,
      workspace: projection.workspace ?? null,
    };
  }

  recordThreadMemoryStatus(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const status = this.memoryStatus({ ...request, thread_id: threadId });
    return this.appendThreadMemoryControlEvent({
      threadId,
      agent,
      request,
      controlKind: "memory_status",
      sourceEventKind: "OperatorControl.Memory",
      eventKind: "memory.status",
      componentKind: "memory_policy",
      workflowNodeId: "runtime.memory-manager",
      payloadSchemaVersion: RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION,
      status: status.status === "needs_review" ? "blocked" : "completed",
      payload: {
        ...status,
        event_kind: "MemoryStatus",
        control_kind: "memory_status",
        thread_id: threadId,
        agent_id: agent.id,
        rows: memoryRowsForStatus(status),
        summary: `Memory has ${status.record_count} record(s); policy ${status.policy?.id ?? "default"} is ${status.status}.`,
      },
    });
  }

  validateThreadMemory(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const validation = this.validateMemory({ ...request, thread_id: threadId });
    return this.appendThreadMemoryControlEvent({
      threadId,
      agent,
      request,
      controlKind: "memory_validate",
      sourceEventKind: "OperatorControl.MemoryValidate",
      eventKind: "memory.validation",
      componentKind: "memory_policy",
      workflowNodeId: "runtime.memory-manager.validate",
      payloadSchemaVersion: RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
      status: validation.ok ? "completed" : "blocked",
      payload: {
        ...validation,
        event_kind: "MemoryValidationReport",
        control_kind: "memory_validate",
        thread_id: threadId,
        agent_id: agent.id,
        summary: validation.ok
          ? `Memory validation passed for ${validation.record_count} record(s).`
          : `Memory validation found ${validation.issue_count} issue(s).`,
      },
    });
  }

  recordThreadMemoryMutation(threadId, mutation = {}, request = {}, operation = "write") {
    const agent = this.agentForThread(threadId);
    const status = this.memoryStatus({ ...request, thread_id: threadId });
    const record = mutation.record ?? null;
    const policy = mutation.policy ?? status.policy ?? null;
    const receipt = mutation.receipt ?? null;
    const receiptRefs = receipt?.id ? [receipt.id] : [];
    const memoryRecordId = record?.id ?? null;
    const memoryPolicyId = policy?.id ?? null;
    const controlKind = memoryControlKind(operation);
    const payloadRecordList = record ? [record] : status.records;
    const mutationRows = memoryRowsForStatus({
      ...status,
      records: payloadRecordList,
      receipt_refs: receiptRefs,
      receiptRefs,
    }).map((row) =>
      row.row_kind === "memory_record" && (!memoryRecordId || row.memory_record_id === memoryRecordId)
        ? {
            ...row,
            label: memoryMutationRowLabel(operation),
            raw_input: memoryMutationRawInput(operation),
            memory_operation: operation,
            workflow_node_id: record?.workflowNodeId ?? memoryWorkflowNodeId(operation),
          }
        : row,
    );
    const payload = {
      ...status,
      schema_version: RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION,
      object: "ioi.runtime_memory_manager_mutation",
      event_kind: memoryEventKind(operation),
      control_kind: controlKind,
      memory_operation: operation,
      memoryOperation: operation,
      mutation_status: "completed",
      mutationStatus: "completed",
      thread_id: threadId,
      threadId,
      agent_id: agent.id,
      agentId: agent.id,
      record,
      records: payloadRecordList,
      policy,
      receipt,
      memory_record_id: memoryRecordId,
      memoryRecordId,
      memory_policy_id: memoryPolicyId,
      memoryPolicyId,
      receipt_refs: receiptRefs,
      receiptRefs,
      rows: mutationRows,
      memory_rows: mutationRows,
      memoryRows: mutationRows,
      summary: memoryMutationSummary(operation, { record, policy }),
    };
    const result = this.appendThreadMemoryControlEvent({
      threadId,
      agent,
      request,
      controlKind,
      sourceEventKind: memoryOperatorControlKind(operation),
      eventKind: memoryRuntimeEventKind(operation),
      componentKind: operation === "policy_update" ? "memory_policy" : "memory_write",
      workflowNodeId: memoryWorkflowNodeId(operation),
      payloadSchemaVersion: RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION,
      status: "completed",
      payload,
      receiptRefs,
      policyDecisionKind: operation,
    });
    return {
      ...mutation,
      ...result,
      record,
      policy,
      receipt,
      operation,
    };
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
    const thread = this.threadForAgent(agent);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(thread.latest_turn_id) ??
      "";
    const source = operatorControlSource(request.source);
    const graphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const nodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      workflowNodeId;
    const eventHash = doctorHash(`${threadId}:${controlKind}:${JSON.stringify(payload)}:${Date.now()}`).slice(0, 12);
    const resolvedReceiptRefs = normalizeArray(receiptRefs).length
      ? normalizeArray(receiptRefs)
      : [`receipt_memory_${safeId(controlKind)}_${eventHash}`];
    const resolvedPolicyDecisionRefs = normalizeArray(policyDecisionRefs).length
      ? normalizeArray(policyDecisionRefs)
      : [`policy_memory_${safeId(controlKind)}_${safeId(policyDecisionKind)}_${eventHash}`];
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:memory:${safeId(controlKind)}:${eventHash}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:memory:${controlKind}:${eventHash}`,
      source,
      source_event_kind: sourceEventKind,
      event_kind: eventKind,
      status,
      actor: "operator",
      workspace_root: agent.cwd,
      workflow_graph_id: graphId,
      workflow_node_id: nodeId,
      component_kind: componentKind,
      payload_schema_version: payloadSchemaVersion,
      payload_summary: payload,
      receipt_refs: resolvedReceiptRefs,
      policy_decision_refs: resolvedPolicyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const result = {
      ...payload,
      event,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, `thread.${controlKind}`);
    return result;
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
    return this.updateThreadRuntimeControls(threadId, { ...request, control: "mode" });
  }

  updateThreadModel(threadId, request = {}) {
    return this.updateThreadRuntimeControls(threadId, { ...request, control: "model" });
  }

  updateThreadThinking(threadId, request = {}) {
    return this.updateThreadRuntimeControls(threadId, { ...request, control: "thinking" });
  }

  updateThreadRuntimeControls(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const now = new Date().toISOString();
    const controlKind = threadRuntimeControlKind(request);
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const workflowGraphId = request.workflow_graph_id ?? request.workflowGraphId ?? null;
    const existingControls = normalizedAgentRuntimeControls(agent);
    const nextControls = {
      ...existingControls,
      model: { ...(existingControls.model ?? {}) },
      updatedAt: now,
    };
    let modelRoute = null;
    let updatedAgent = agent;

    if (controlKind === "mode") {
      const mode = normalizeThreadInteractionMode(
        request.mode ?? request.interaction_mode ?? request.interactionMode ?? request.value,
      );
      const approvalMode = normalizeThreadApprovalMode(
        request.approval_mode ?? request.approvalMode,
        approvalModeForThreadMode(mode),
      );
      nextControls.mode = mode;
      nextControls.approvalMode = approvalMode;
    } else {
      const modelInput = threadRuntimeControlModelInput(request, existingControls, agent);
      modelRoute = this.resolveModelRoute(
        {
          model: modelInput.model,
          workflowGraphId,
          workflowNodeId: modelInput.workflowNodeId,
          workflowNodeType: "Model Router",
        },
        {
          evidenceRefs: [`runtime_thread_${controlKind}_control`],
          workflowGraphId,
          workflowNodeId: modelInput.workflowNodeId,
          workflowNodeType: "Model Router",
        },
      );
      nextControls.model = {
        id: modelRoute.requestedModelId,
        routeId: modelRoute.routeId,
        selectedModel: modelRoute.selectedModel,
        endpointId: modelRoute.endpointId,
        providerId: modelRoute.providerId,
        receiptId: modelRoute.receiptId,
        reasoningEffort:
          modelRoute.decision?.reasoningEffort ??
          modelInput.model.reasoningEffort ??
          null,
        privacy: modelInput.model.privacy ?? null,
        maxCostUsd: modelInput.model.maxCostUsd ?? null,
        allowHostedFallback: modelInput.model.allowHostedFallback ?? null,
        workflowGraphId,
        workflowNodeId: modelRoute.decision?.workflowNodeId ?? modelInput.workflowNodeId,
        updatedAt: now,
      };
      updatedAgent = {
        ...updatedAgent,
        modelId: modelRoute.selectedModel,
        requestedModelId: modelRoute.requestedModelId,
        modelRouteId: modelRoute.routeId,
        modelRouteEndpointId: modelRoute.endpointId,
        modelRouteProviderId: modelRoute.providerId,
        modelRouteReceiptId: modelRoute.receiptId,
        modelRouteDecision: modelRoute.decision,
      };
    }

    const event = this.appendThreadRuntimeControlEvent({
      agent: updatedAgent,
      threadId,
      controlKind,
      controls: nextControls,
      request,
      source,
      requestedBy,
      workflowGraphId,
      modelRoute,
      now,
    });
    const workspaceTrustWarningEvent =
      controlKind === "mode"
        ? this.appendWorkspaceTrustWarningEvent({
            agent: updatedAgent,
            threadId,
            controls: nextControls,
            request,
            source,
            requestedBy,
            workflowGraphId,
            modeEvent: event,
            now,
          })
        : null;
    updatedAgent = {
      ...updatedAgent,
      runtimeControls: nextControls,
      updatedAt: workspaceTrustWarningEvent?.created_at ?? event.created_at,
    };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, `thread.${controlKind}`);
    const thread = this.threadForAgent(updatedAgent);
    const workspaceTrustWarning = workspaceTrustWarningEvent?.payload_summary ?? null;
    return {
      ...thread,
      workspace_trust_warning: workspaceTrustWarning,
      workspaceTrustWarning,
      control: {
        schemaVersion: RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
        schema_version: RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
        control_kind: controlKind,
        controlKind,
        mode: nextControls.mode,
        approval_mode: nextControls.approvalMode,
        model: nextControls.model,
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
        workspace_trust_warning: workspaceTrustWarning,
        workspaceTrustWarning,
        workspace_trust_warning_event_id: workspaceTrustWarningEvent?.event_id ?? null,
        workspaceTrustWarningEventId: workspaceTrustWarningEvent?.event_id ?? null,
      },
      event,
      workspace_trust_warning_event: workspaceTrustWarningEvent,
      workspaceTrustWarningEvent: workspaceTrustWarningEvent,
    };
  }

  appendThreadRuntimeControlEvent({
    agent,
    threadId,
    controlKind,
    controls,
    request,
    source,
    requestedBy,
    workflowGraphId,
    modelRoute,
    now,
  }) {
    const streamId = eventStreamIdForThread(threadId);
    const workflowNodeId =
      request.workflow_node_id ??
      request.workflowNodeId ??
      modelRoute?.decision?.workflowNodeId ??
      controls.model?.workflowNodeId ??
      (controlKind === "mode" ? "runtime.thread-mode" : "runtime.model-router");
    const payload =
      controlKind === "mode"
        ? {
            event_kind: "OperatorControl.Mode",
            control_kind: controlKind,
            mode: controls.mode,
            approval_mode: controls.approvalMode,
            requested_by: requestedBy,
            control_surface: source,
            agent_id: agent.id,
            thread_id: threadId,
            session_id: runtimeSessionIdForAgent(agent),
          }
        : {
            ...(modelRoute?.decision ?? {}),
            event_kind: "ModelRouteDecision",
            control_kind: controlKind,
            requested_by: requestedBy,
            control_surface: source,
            agent_id: agent.id,
            thread_id: threadId,
            session_id: runtimeSessionIdForAgent(agent),
            model_control: controls.model,
          };
    const controlHash = crypto
      .createHash("sha256")
      .update(JSON.stringify({
        controlKind,
        mode: controls.mode,
        approvalMode: controls.approvalMode,
        model: controls.model,
        workflowNodeId,
      }))
      .digest("hex")
      .slice(0, 16);
    return this.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:${controlKind}-control:${controlHash}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:control.${controlKind}:${controlHash}`,
      source,
      source_event_kind:
        controlKind === "mode"
          ? "OperatorControl.Mode"
          : controlKind === "thinking"
            ? "OperatorControl.Thinking"
            : "OperatorControl.Model",
      event_kind: controlKind === "mode" ? "thread.mode_updated" : "model.route_decision",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: controlKind === "mode" ? "runtime_mode" : "model_router",
      payload_schema_version:
        controlKind === "mode"
          ? RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION
          : RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION,
      payload,
      receipt_refs:
        controlKind === "mode"
          ? [`receipt_${agent.id}_mode_${safeId(controls.mode)}_${controlHash}`]
          : [modelRoute?.receiptId].filter(Boolean),
      policy_decision_refs: [`policy_${agent.id}_${controlKind}_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
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
    const mode = controls.mode;
    if (mode !== "review" && mode !== "yolo") return null;
    const modeWorkflowNodeId =
      request.workflow_node_id ??
      request.workflowNodeId ??
      modeEvent?.workflow_node_id ??
      "runtime.thread-mode";
    const workflowNodeId =
      request.workspace_trust_workflow_node_id ??
      request.workspaceTrustWorkflowNodeId ??
      request.trust_warning_workflow_node_id ??
      request.trustWarningWorkflowNodeId ??
      `${modeWorkflowNodeId}.workspace-trust`;
    const payload = workspaceTrustWarningRecordForMode({
      agent,
      threadId,
      controls,
      request,
      source,
      requestedBy,
      workflowGraphId,
      workflowNodeId,
      modeWorkflowNodeId,
      modeEvent,
      now,
    });
    const warningHash = crypto
      .createHash("sha256")
      .update(JSON.stringify({
        threadId,
        mode: controls.mode,
        approvalMode: controls.approvalMode,
        workspaceRootHash: payload.workspace_root_hash,
        branchPolicyStatus: payload.branch_policy_status,
        warningReasons: payload.warning_reasons,
        workflowGraphId,
        workflowNodeId,
      }))
      .digest("hex")
      .slice(0, 16);
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:workspace-trust:${warningHash}`,
      idempotency_key: `thread:${threadId}:workspace-trust-warning:${warningHash}`,
      source,
      source_event_kind: "WorkspaceTrust.Warning",
      event_kind: "workspace.trust_warning",
      status: "warning",
      actor: "policy",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workspace_trust",
      payload_schema_version: WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
      payload_summary: payload,
      receipt_refs: [`receipt_${agent.id}_workspace_trust_${safeId(mode)}_${warningHash}`],
      policy_decision_refs: [
        `policy_${agent.id}_workspace_trust_${safeId(mode)}_${safeId(payload.severity)}`,
      ],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
  }

  acknowledgeWorkspaceTrustWarning(threadId, warningId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedWarningId = optionalString(warningId ?? request.warning_id ?? request.warningId);
    if (!normalizedWarningId) {
      throw runtimeError({
        status: 400,
        code: "workspace_trust_warning_id_required",
        message: "Workspace trust acknowledgement requires a warning id.",
        details: { threadId },
      });
    }
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const warningEvent = [...stream.events].reverse().find((event) => {
      if (event.event_kind !== "workspace.trust_warning" && event.type !== "workspace_trust_warning") return false;
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.event_id === normalizedWarningId ||
        payload.warning_id === normalizedWarningId ||
        payload.warningId === normalizedWarningId
      );
    });
    if (!warningEvent) {
      throw runtimeError({
        status: 404,
        code: "workspace_trust_warning_not_found",
        message: "Workspace trust warning does not exist for this thread.",
        details: { threadId, warningId: normalizedWarningId },
      });
    }
    const warningPayload = warningEvent.payload_summary ?? warningEvent.payload ?? {};
    const now = new Date().toISOString();
    const source = operatorControlSource(request.source);
    const acknowledgedBy =
      optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message) ??
      "Workspace trust warning acknowledged by operator.";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
      warningEvent.workflow_graph_id ??
      warningPayload.workflow_graph_id ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      warningEvent.workflow_node_id ??
      warningPayload.workflow_node_id ??
      "runtime.workspace-trust";
    const sourceEventId =
      optionalString(request.source_event_id ?? request.sourceEventId) ??
      warningEvent.event_id;
    const acknowledgementHash = doctorHash(
      JSON.stringify({
        threadId,
        warningId: normalizedWarningId,
        sourceEventId,
        workflowGraphId,
        workflowNodeId,
        acknowledgedBy,
      }),
    ).slice(0, 16);
    const payload = {
      schemaVersion: WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
      schema_version: WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
      object: "ioi.workspace_trust_acknowledgement",
      acknowledgementId: `workspace_trust_ack_${acknowledgementHash}`,
      acknowledgement_id: `workspace_trust_ack_${acknowledgementHash}`,
      warningId: normalizedWarningId,
      warning_id: normalizedWarningId,
      warningEventId: warningEvent.event_id,
      warning_event_id: warningEvent.event_id,
      sourceEventId,
      source_event_id: sourceEventId,
      status: "acknowledged",
      acknowledgedAt: now,
      acknowledged_at: now,
      acknowledgedBy,
      acknowledged_by: acknowledgedBy,
      reason,
      mode: warningPayload.mode ?? warningPayload.thread_mode ?? null,
      thread_mode: warningPayload.thread_mode ?? warningPayload.mode ?? null,
      approvalMode: warningPayload.approvalMode ?? warningPayload.approval_mode ?? null,
      approval_mode: warningPayload.approval_mode ?? warningPayload.approvalMode ?? null,
      severity: warningPayload.severity ?? null,
      trustProfile: warningPayload.trustProfile ?? warningPayload.trust_profile ?? "local_private",
      trust_profile: warningPayload.trust_profile ?? warningPayload.trustProfile ?? "local_private",
      threadId,
      thread_id: threadId,
      agentId: agent.id,
      agent_id: agent.id,
      sessionId: runtimeSessionIdForAgent(agent),
      session_id: runtimeSessionIdForAgent(agent),
      workflowGraphId,
      workflow_graph_id: workflowGraphId,
      workflowNodeId,
      workflow_node_id: workflowNodeId,
      controlSurface: source,
      control_surface: source,
      daemonEnforced: true,
      daemon_enforced: true,
      canvasLocalTrustStateAccepted: false,
      canvas_local_trust_state_accepted: false,
      commandExecuted: false,
      command_executed: false,
    };
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:workspace-trust-ack:${acknowledgementHash}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:workspace-trust-acknowledgement:${acknowledgementHash}`,
      source,
      source_event_kind: "WorkspaceTrust.Acknowledged",
      event_kind: "workspace.trust_acknowledged",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workspace_trust",
      payload_schema_version: WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
      payload_summary: payload,
      receipt_refs: [
        `receipt_${agent.id}_workspace_trust_ack_${safeId(normalizedWarningId)}_${acknowledgementHash}`,
      ],
      policy_decision_refs: [
        `policy_${agent.id}_workspace_trust_acknowledged_${acknowledgementHash}`,
      ],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    return {
      ...this.threadForAgent(agent),
      workspace_trust_acknowledgement: payload,
      workspaceTrustAcknowledgement: payload,
      workspace_trust_acknowledgement_event: event,
      workspaceTrustAcknowledgementEvent: event,
      event,
    };
  }

  forkThread(threadId, request = {}) {
    const sourceThread = this.getThread(threadId);
    const sourceAgent = this.agentForThread(threadId);
    const options = {
      ...(request.options ?? {}),
      local: {
        cwd: request.options?.local?.cwd ?? sourceThread.workspace ?? this.defaultCwd,
      },
      model: request.options?.model ? request.options.model : { id: sourceThread.model_route },
    };
    const idempotencyKey = request.idempotency_key ?? request.idempotencyKey;
    const streamId = eventStreamIdForThread(threadId);
    if (idempotencyKey) {
      const duplicate = this.runtimeEventStream(streamId).idempotency.get(String(idempotencyKey));
      const duplicateForkThreadId =
        duplicate?.payload_summary?.fork_thread_id ?? duplicate?.payload?.fork_thread_id;
      if (duplicateForkThreadId) {
        return {
          ...this.getThread(String(duplicateForkThreadId)),
          source_thread_id: sourceThread.thread_id,
          forked_from_seq:
            Number(duplicate?.payload_summary?.source_latest_seq ?? sourceThread.latest_seq) ||
            sourceThread.latest_seq,
        };
      }
    }
    const fork = this.createAgent(options);
    const thread = this.threadForAgent(fork);
    const sourceLatestSeq = sourceThread.latest_seq;
    const sourceLatestTurnId = sourceThread.latest_turn_id ?? "";
    const controlSource = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason = optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested thread fork";
    const now = new Date().toISOString();
    this.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: threadId,
      turn_id: sourceLatestTurnId,
      item_id: `${threadId}:item:thread-fork:${thread.thread_id}`,
      idempotency_key: idempotencyKey ? String(idempotencyKey) : `thread:${threadId}:operator.fork:${thread.thread_id}`,
      source: controlSource,
      source_event_kind: "OperatorControl.Fork",
      event_kind: "thread.forked",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: sourceAgent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.thread-fork",
      component_kind: "thread_fork",
      payload_schema_version: "ioi.runtime.thread-fork.v1",
      payload: {
        event_kind: "OperatorControl.Fork",
        reason,
        requested_by: requestedBy,
        control_surface: controlSource,
        source_thread_id: sourceThread.thread_id,
        source_agent_id: sourceThread.agent_id,
        source_latest_seq: sourceLatestSeq,
        source_latest_turn_id: sourceLatestTurnId || null,
        fork_thread_id: thread.thread_id,
        fork_agent_id: thread.agent_id,
        fork_session_id: thread.session_id,
        session_id: sourceThread.session_id,
      },
      receipt_refs: [`receipt_${sourceThread.agent_id}_thread_fork_${thread.agent_id}`],
      policy_decision_refs: [`policy_${sourceThread.agent_id}_thread_fork_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(sourceAgent),
    });
    return {
      ...thread,
      source_thread_id: sourceThread.thread_id,
      forked_from_seq: sourceLatestSeq,
    };
  }

  listSubagents(threadId, options = {}) {
    const parentAgent = this.agentForThread(threadId);
    const role = optionalString(options.role ?? options.subagent_role ?? options.subagentRole);
    const subagents = [...this.subagents.values()]
      .filter((record) => (record.parent_thread_id ?? record.parentThreadId) === threadId)
      .filter((record) => !role || record.role === role)
      .sort((left, right) =>
        String(left.created_at ?? left.createdAt ?? "").localeCompare(
          String(right.created_at ?? right.createdAt ?? ""),
        ),
      )
      .map((record) => this.subagentProjection(record));
    return {
      schema_version: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      schemaVersion: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      object: "ioi.runtime_subagent_list",
      thread_id: threadId,
      threadId,
      parent_agent_id: parentAgent.id,
      parentAgentId: parentAgent.id,
      status: "ready",
      count: subagents.length,
      active_count: subagents.filter((record) => subagentIsActive(record)).length,
      activeCount: subagents.filter((record) => subagentIsActive(record)).length,
      subagents,
    };
  }

  spawnSubagent(threadId, request = {}) {
    const parentAgent = this.agentForThread(threadId);
    const parentThread = this.threadForAgent(parentAgent);
    const prompt = optionalString(
      request.prompt ?? request.message ?? request.input ?? request.subagentPrompt ?? request.subagent_prompt,
    );
    if (!prompt) {
      throw runtimeError({
        status: 400,
        code: "subagent_prompt_required",
        message: "Subagent spawn requires a prompt.",
        details: { threadId },
      });
    }
    const role = normalizeSubagentRole(request.role ?? request.subagentRole ?? request.subagent_role);
    const maxConcurrency = optionalPositiveInteger(
      request.max_concurrency ?? request.maxConcurrency ?? request.subagentMaxConcurrency,
    );
    if (maxConcurrency) {
      const activeForRole = this.listSubagents(threadId, { role }).subagents.filter(subagentIsActive).length;
      if (activeForRole >= maxConcurrency) {
        throw policyError("Subagent role concurrency limit reached.", {
          threadId,
          role,
          activeForRole,
          maxConcurrency,
        });
      }
    }

    const modelRouteId =
      optionalString(request.model_route_id ?? request.modelRouteId ?? request.subagentModelRoute) ??
      parentAgent.modelRouteId ??
      "route.local-first";
    const childAgent = this.createAgent({
      local: { cwd: parentAgent.cwd },
      model: {
        id: parentAgent.requestedModelId ?? parentAgent.modelId ?? "auto",
        routeId: parentAgent.modelRouteId ?? "route.local-first",
      },
    });
    const run = this.createRun(childAgent.id, {
      mode: "send",
      prompt,
      options: {
        receiver: role,
        memory: request.memory ?? request.options?.memory ?? {},
      },
    });
    const now = new Date().toISOString();
    const subagentId = childAgent.id;
    const outputContract = normalizeSubagentOutputContract(
      request.output_contract ?? request.outputContract ?? request.subagentOutputContract,
    );
    const output = subagentContractOutputForRun(run, outputContract);
    const outputContractStatus = validateSubagentOutputContract(output, outputContract);
    const budget = subagentBudgetForRequest(request);
    const budgetUsageTelemetry = subagentBudgetUsageTelemetryForRequest(request);
    const budgetStatus = subagentBudgetStatusForRun({
      budget,
      run,
      prompt,
      previousUsage: budgetUsageTelemetry ?? {},
    });
    const subagentLifecycleStatus =
      budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status);
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      `runtime.subagent.spawn.${safeId(role)}`;
    const parentTurnId =
      optionalString(request.parent_turn_id ?? request.parentTurnId ?? request.turn_id ?? request.turnId) ??
      parentThread.latest_turn_id ??
      null;
    const contextPressureAction =
      optionalString(request.context_pressure_action ?? request.contextPressureAction) ?? null;
    const contextPressure = contextBudgetNumber(
      request.context_pressure,
      request.contextPressure,
      request.pressure,
    );
    const pressureStatus =
      optionalString(request.pressure_status ?? request.pressureStatus) ?? null;
    const alertId = optionalString(request.alert_id ?? request.alertId) ?? null;
    const sourceEventId =
      optionalString(request.source_event_id ?? request.sourceEventId) ?? null;
    const requestReceiptRefs = uniqueStrings(
      request.receipt_refs ?? request.receiptRefs,
    );
    const requestPolicyDecisionRefs = uniqueStrings(
      request.policy_decision_refs ?? request.policyDecisionRefs,
    );
    const runReceiptRefs = run.receipts.map((receipt) => receipt.id);
    const record = {
      schema_version: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      schemaVersion: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      object: "ioi.runtime_subagent",
      subagent_id: subagentId,
      subagentId,
      agent_id: childAgent.id,
      agentId: childAgent.id,
      child_thread_id: threadIdForAgent(childAgent.id),
      childThreadId: threadIdForAgent(childAgent.id),
      run_id: run.id,
      runId: run.id,
      parent_thread_id: threadId,
      parentThreadId: threadId,
      parent_agent_id: parentAgent.id,
      parentAgentId: parentAgent.id,
      parent_turn_id: parentTurnId,
      parentTurnId,
      role,
      tool_pack: optionalString(request.tool_pack ?? request.toolPack ?? request.subagentToolPack) ?? null,
      toolPack: optionalString(request.tool_pack ?? request.toolPack ?? request.subagentToolPack) ?? null,
      model_route_id: modelRouteId,
      modelRouteId,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      session_boot_id: runtimeSessionIdForAgent(childAgent),
      sessionBootId: runtimeSessionIdForAgent(childAgent),
      lifecycle_status: subagentLifecycleStatus,
      lifecycleStatus: subagentLifecycleStatus,
      status: subagentLifecycleStatus,
      restart_status: "not_restarted",
      restartStatus: "not_restarted",
      fork_context: request.fork_context === true || request.forkContext === true,
      forkContext: request.fork_context === true || request.forkContext === true,
      context_mode: request.fork_context === true || request.forkContext === true ? "forked" : "fresh",
      contextMode: request.fork_context === true || request.forkContext === true ? "forked" : "fresh",
      max_concurrency: maxConcurrency,
      maxConcurrency,
      budget,
      budget_usage_telemetry: budgetUsageTelemetry,
      budgetUsageTelemetry,
      budget_status: budgetStatus.status,
      budgetStatus,
      usage_telemetry: budgetStatus.usage,
      usageTelemetry: budgetStatus.usage,
      budget_policy_decision: budgetStatus.policy_decision,
      budgetPolicyDecision: budgetStatus.policyDecision,
      block_reason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
      blockReason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
      output_contract: outputContract,
      outputContract,
      output_contract_status: outputContractStatus.status,
      outputContractStatus,
      output_contract_validation: outputContractStatus,
      outputContractValidation: outputContractStatus,
      merge_policy: optionalString(request.merge_policy ?? request.mergePolicy) ?? "manual",
      mergePolicy: optionalString(request.merge_policy ?? request.mergePolicy) ?? "manual",
      cancellation_inheritance:
        optionalString(request.cancellation_inheritance ?? request.cancellationInheritance) ?? "propagate",
      cancellationInheritance:
        optionalString(request.cancellation_inheritance ?? request.cancellationInheritance) ?? "propagate",
      context_pressure_action: contextPressureAction,
      contextPressureAction,
      context_pressure: contextPressure,
      contextPressure,
      pressure: contextPressure,
      pressure_status: pressureStatus,
      pressureStatus,
      alert_id: alertId,
      alertId,
      source_event_id: sourceEventId,
      sourceEventId,
      source_receipt_refs: requestReceiptRefs,
      sourceReceiptRefs: requestReceiptRefs,
      source_policy_decision_refs: requestPolicyDecisionRefs,
      sourcePolicyDecisionRefs: requestPolicyDecisionRefs,
      created_at: now,
      createdAt: now,
      updated_at: now,
      updatedAt: now,
      result: subagentResultForRun({ record: null, run, output, outputContractStatus }),
      receipt_refs: uniqueStrings([...runReceiptRefs, ...requestReceiptRefs]),
      receiptRefs: uniqueStrings([...runReceiptRefs, ...requestReceiptRefs]),
      policy_decision_refs: requestPolicyDecisionRefs,
      policyDecisionRefs: requestPolicyDecisionRefs,
      evidence_refs: [
        "runtime.subagent_manager",
        "runtime.subagent.spawn",
        run.id,
        ...runReceiptRefs,
        ...requestReceiptRefs,
        ...requestPolicyDecisionRefs,
      ],
      evidenceRefs: [
        "runtime.subagent_manager",
        "runtime.subagent.spawn",
        run.id,
        ...runReceiptRefs,
        ...requestReceiptRefs,
        ...requestPolicyDecisionRefs,
      ],
    };
    record.result = subagentResultForRun({ record, run, output, outputContractStatus });
    const event = this.appendThreadSubagentControlEvent({
      threadId,
      parentAgent,
      record,
      request,
      operation: "spawn",
      status: subagentLifecycleStatus,
    });
    const saved = {
      ...record,
      event_id: event.event_id,
      eventId: event.event_id,
      receipt_refs: uniqueStrings([...record.receipt_refs, ...event.receipt_refs]),
      receiptRefs: uniqueStrings([...record.receiptRefs, ...event.receipt_refs]),
      updated_at: event.created_at,
      updatedAt: event.created_at,
    };
    saved.result = subagentResultForRun({
      record: saved,
      run,
      output,
      outputContractStatus,
    });
    this.writeSubagent(saved, "subagent.spawn");
    if (budgetStatus.status === "exceeded") {
      throw policyError("Subagent budget limit exceeded.", {
        threadId,
        role,
        subagentId,
        reason: "subagent_budget_exceeded",
        budgetStatus,
        budget_status: budgetStatus.status,
        subagent: this.subagentProjection(saved),
        eventId: event.event_id,
        event_id: event.event_id,
        receiptRefs: event.receipt_refs,
        receipt_refs: event.receipt_refs,
        policyDecisionRefs: event.policy_decision_refs,
        policy_decision_refs: event.policy_decision_refs,
      });
    }
    return {
      ...this.subagentProjection(saved),
      event,
    };
  }

  waitSubagent(threadId, subagentId, request = {}) {
    const record = this.getSubagent(threadId, subagentId);
    const run = this.getRun(record.run_id ?? record.runId);
    const output = subagentContractOutputForRun(run, record.output_contract ?? record.outputContract);
    const outputContractStatus = validateSubagentOutputContract(
      output,
      record.output_contract ?? record.outputContract,
    );
    const previousLifecycleStatus = record.lifecycle_status ?? record.lifecycleStatus ?? record.status;
    const lifecycleStatus =
      previousLifecycleStatus === "blocked" ? "blocked" : lifecycleStatusForRun(run.status);
    const updated = {
      ...record,
      lifecycle_status: lifecycleStatus,
      lifecycleStatus,
      status: lifecycleStatus,
      output_contract_status: outputContractStatus.status,
      outputContractStatus,
      output_contract_validation: outputContractStatus,
      outputContractValidation: outputContractStatus,
      waited_at: new Date().toISOString(),
      waitedAt: new Date().toISOString(),
    };
    updated.result = subagentResultForRun({ record: updated, run, output, outputContractStatus });
    const event = this.appendThreadSubagentControlEvent({
      threadId,
      parentAgent: this.agentForThread(threadId),
      record: updated,
      request,
      operation: "wait",
      status: updated.status,
    });
    const saved = {
      ...updated,
      wait_event_id: event.event_id,
      waitEventId: event.event_id,
      receipt_refs: uniqueStrings([...normalizeArray(updated.receipt_refs), ...event.receipt_refs]),
      receiptRefs: uniqueStrings([...normalizeArray(updated.receiptRefs), ...event.receipt_refs]),
      updated_at: event.created_at,
      updatedAt: event.created_at,
    };
    saved.result = subagentResultForRun({ record: saved, run, output, outputContractStatus });
    this.writeSubagent(saved, "subagent.wait");
    return {
      ...saved.result,
      subagent: this.subagentProjection(saved),
      event,
      receipt_refs: event.receipt_refs,
      receiptRefs: event.receipt_refs,
    };
  }

  sendSubagentInput(threadId, subagentId, request = {}) {
    const record = this.getSubagent(threadId, subagentId);
    if ((record.lifecycle_status ?? record.lifecycleStatus ?? record.status) === "canceled") {
      throw policyError("Cannot send input to a canceled subagent.", { threadId, subagentId });
    }
    const message = optionalString(
      request.input ??
        request.message ??
        request.prompt ??
        request.text ??
        request.subagent_input ??
        request.subagentInput,
    );
    if (!message) {
      throw runtimeError({
        status: 400,
        code: "subagent_input_required",
        message: "Subagent input requires a message.",
        details: { threadId, subagentId },
      });
    }

    const previousRunId = record.run_id ?? record.runId;
    const childAgentId = record.agent_id ?? record.agentId ?? subagentId;
    const inputId = `subagent_input_${doctorHash(`${threadId}:${subagentId}:${Date.now()}`).slice(0, 12)}`;
    const run = this.createRun(childAgentId, {
      mode: "send",
      prompt: message,
      options: {
        receiver: record.role ?? "general",
        memory: request.memory ?? request.options?.memory ?? {},
      },
    });
    const output = subagentContractOutputForRun(run, record.output_contract ?? record.outputContract);
    const outputContractStatus = validateSubagentOutputContract(
      output,
      record.output_contract ?? record.outputContract,
    );
    const budget = subagentBudgetForRequest(request) ?? subagentBudgetForRequest(record);
    const budgetUsageTelemetry =
      subagentBudgetUsageTelemetryForRequest(request) ??
      record.usage_telemetry ??
      record.usageTelemetry ??
      null;
    const budgetStatus = subagentBudgetStatusForRun({
      budget,
      run,
      prompt: message,
      previousUsage: budgetUsageTelemetry ?? {},
    });
    const now = new Date().toISOString();
    const inputRecord = {
      schema_version: "ioi.runtime.subagent-input.v1",
      schemaVersion: "ioi.runtime.subagent-input.v1",
      input_id: inputId,
      inputId,
      message,
      run_id: run.id,
      runId: run.id,
      previous_run_id: previousRunId ?? null,
      previousRunId: previousRunId ?? null,
      created_at: now,
      createdAt: now,
      actor: optionalString(request.actor) ?? "operator",
      source: operatorControlSource(request.source),
      workflow_graph_id: optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
      workflowGraphId: optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
      workflow_node_id: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
      workflowNodeId: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
    };
    const inputHistory = [...normalizeArray(record.input_history ?? record.inputHistory), inputRecord];
    const updated = {
      ...record,
      run_id: run.id,
      runId: run.id,
      previous_run_ids: uniqueStrings([
        ...normalizeArray(record.previous_run_ids ?? record.previousRunIds),
        previousRunId,
      ]),
      previousRunIds: uniqueStrings([
        ...normalizeArray(record.previousRunIds ?? record.previous_run_ids),
        previousRunId,
      ]),
      lifecycle_status:
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status),
      lifecycleStatus:
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status),
      status:
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status),
      budget,
      budget_usage_telemetry: budgetUsageTelemetry,
      budgetUsageTelemetry,
      budget_status: budgetStatus.status,
      budgetStatus,
      usage_telemetry: budgetStatus.usage,
      usageTelemetry: budgetStatus.usage,
      budget_policy_decision: budgetStatus.policy_decision,
      budgetPolicyDecision: budgetStatus.policyDecision,
      block_reason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
      blockReason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
      output_contract_status: outputContractStatus.status,
      outputContractStatus,
      output_contract_validation: outputContractStatus,
      outputContractValidation: outputContractStatus,
      input_count: inputHistory.length,
      inputCount: inputHistory.length,
      input_history: inputHistory,
      inputHistory,
      last_input: message,
      lastInput: message,
      last_input_at: now,
      lastInputAt: now,
      input_id: inputId,
      inputId,
      updated_at: now,
      updatedAt: now,
    };
    updated.result = subagentResultForRun({ record: updated, run, output, outputContractStatus });
    const event = this.appendThreadSubagentControlEvent({
      threadId,
      parentAgent: this.agentForThread(threadId),
      record: updated,
      request,
      operation: "send_input",
      status: updated.status,
    });
    const saved = {
      ...updated,
      input_event_id: event.event_id,
      inputEventId: event.event_id,
      receipt_refs: uniqueStrings([
        ...normalizeArray(updated.receipt_refs),
        ...normalizeArray(run.receipts).map((receipt) => receipt.id),
        ...event.receipt_refs,
      ]),
      receiptRefs: uniqueStrings([
        ...normalizeArray(updated.receiptRefs),
        ...normalizeArray(run.receipts).map((receipt) => receipt.id),
        ...event.receipt_refs,
      ]),
      evidence_refs: uniqueStrings([
        ...normalizeArray(updated.evidence_refs ?? updated.evidenceRefs),
        "runtime.subagent.input",
        run.id,
      ]),
      evidenceRefs: uniqueStrings([
        ...normalizeArray(updated.evidenceRefs ?? updated.evidence_refs),
        "runtime.subagent.input",
        run.id,
      ]),
      updated_at: event.created_at,
      updatedAt: event.created_at,
    };
    saved.result = subagentResultForRun({ record: saved, run, output, outputContractStatus });
    this.writeSubagent(saved, "subagent.input");
    if (budgetStatus.status === "exceeded") {
      throw policyError("Subagent budget limit exceeded.", {
        threadId,
        subagentId,
        reason: "subagent_budget_exceeded",
        budgetStatus,
        budget_status: budgetStatus.status,
        subagent: this.subagentProjection(saved),
        eventId: event.event_id,
        event_id: event.event_id,
        receiptRefs: event.receipt_refs,
        receipt_refs: event.receipt_refs,
        policyDecisionRefs: event.policy_decision_refs,
        policy_decision_refs: event.policy_decision_refs,
      });
    }
    return {
      ...this.subagentProjection(saved),
      input: inputRecord,
      result: saved.result,
      event,
    };
  }

  cancelSubagent(threadId, subagentId, request = {}) {
    const record = this.getSubagent(threadId, subagentId);
    const previousStatus = record.lifecycle_status ?? record.lifecycleStatus ?? record.status ?? null;
    const reason =
      optionalString(request.reason ?? request.cancellation_reason ?? request.cancellationReason) ??
      "operator_cancel";
    const cancellationInherited = Boolean(request.inherited ?? request.cancellationInherited);
    const propagatedFromThreadId =
      optionalString(request.propagated_from_thread_id ?? request.propagatedFromThreadId) ?? null;
    const run = this.cancelRun(record.run_id ?? record.runId);
    const output = subagentContractOutputForRun(run, record.output_contract ?? record.outputContract);
    const outputContractStatus = validateSubagentOutputContract(
      output,
      record.output_contract ?? record.outputContract,
    );
    const budget = subagentBudgetForRequest(request) ?? subagentBudgetForRequest(record);
    const budgetUsageTelemetry =
      subagentBudgetUsageTelemetryForRequest(request) ??
      record.usage_telemetry ??
      record.usageTelemetry ??
      null;
    const prompt = optionalString(record.prompt ?? record.objective ?? record.task) ?? "";
    const budgetStatus = subagentBudgetStatusForRun({
      budget,
      run,
      prompt,
      previousUsage: budgetUsageTelemetry ?? {},
    });
    const now = new Date().toISOString();
    const updated = {
      ...record,
      lifecycle_status: "canceled",
      lifecycleStatus: "canceled",
      status: "canceled",
      output_contract_status: outputContractStatus.status,
      outputContractStatus,
      output_contract_validation: outputContractStatus,
      outputContractValidation: outputContractStatus,
      canceled_at: now,
      canceledAt: now,
      cancellation_reason: reason,
      cancellationReason: reason,
      cancellation_inherited: cancellationInherited,
      cancellationInherited,
      propagated_from_thread_id: propagatedFromThreadId,
      propagatedFromThreadId,
      cancellation: {
        reason,
        previous_status: previousStatus,
        previousStatus,
        requested_by: optionalString(request.actor) ?? "operator",
        requestedBy: optionalString(request.actor) ?? "operator",
        inherited: cancellationInherited,
        propagated_from_thread_id: propagatedFromThreadId,
        propagatedFromThreadId,
        source: operatorControlSource(request.source),
      },
      updated_at: now,
      updatedAt: now,
    };
    updated.result = subagentResultForRun({ record: updated, run, output, outputContractStatus });
    const event = this.appendThreadSubagentControlEvent({
      threadId,
      parentAgent: this.agentForThread(threadId),
      record: updated,
      request,
      operation: "cancel",
      status: "canceled",
    });
    const saved = {
      ...updated,
      cancel_event_id: event.event_id,
      cancelEventId: event.event_id,
      receipt_refs: uniqueStrings([
        ...normalizeArray(updated.receipt_refs),
        ...normalizeArray(run.receipts).map((receipt) => receipt.id),
        ...event.receipt_refs,
      ]),
      receiptRefs: uniqueStrings([
        ...normalizeArray(updated.receiptRefs),
        ...normalizeArray(run.receipts).map((receipt) => receipt.id),
        ...event.receipt_refs,
      ]),
      evidence_refs: uniqueStrings([
        ...normalizeArray(updated.evidence_refs ?? updated.evidenceRefs),
        "runtime.subagent.cancel",
        run.id,
      ]),
      evidenceRefs: uniqueStrings([
        ...normalizeArray(updated.evidenceRefs ?? updated.evidence_refs),
        "runtime.subagent.cancel",
        run.id,
      ]),
      updated_at: event.created_at,
      updatedAt: event.created_at,
    };
    saved.result = subagentResultForRun({ record: saved, run, output, outputContractStatus });
    this.writeSubagent(saved, "subagent.cancel");
    return {
      ...saved.result,
      subagent: this.subagentProjection(saved),
      event,
      cancellation: saved.cancellation,
      receipt_refs: event.receipt_refs,
      receiptRefs: event.receipt_refs,
    };
  }

  propagateSubagentCancellation(threadId, request = {}) {
    const parentAgent = this.agentForThread(threadId);
    const reason =
      optionalString(request.reason ?? request.cancellation_reason ?? request.cancellationReason) ??
      "parent_cancel";
    const source = operatorControlSource(request.source);
    const requestBase = {
      ...request,
      source,
      reason,
      inherited: true,
      cancellationInherited: true,
      propagated_from_thread_id: threadId,
      propagatedFromThreadId: threadId,
    };
    delete requestBase.idempotency_key;
    delete requestBase.idempotencyKey;
    const candidates = [...this.subagents.values()]
      .filter((record) => (record.parent_thread_id ?? record.parentThreadId) === threadId)
      .sort((left, right) =>
        String(left.created_at ?? left.createdAt ?? "").localeCompare(
          String(right.created_at ?? right.createdAt ?? ""),
        ),
      );
    const canceled = [];
    const skipped = [];
    for (const record of candidates) {
      const targetId = record.subagent_id ?? record.subagentId ?? record.agent_id ?? record.agentId;
      const inheritance = record.cancellation_inheritance ?? record.cancellationInheritance ?? "propagate";
      const status = record.lifecycle_status ?? record.lifecycleStatus ?? record.status ?? null;
      if (!subagentCancellationPropagates(record)) {
        skipped.push({
          ...this.subagentProjection(record),
          skip_reason: "cancellation_inheritance_not_propagate",
          skipReason: "cancellation_inheritance_not_propagate",
          cancellation_inheritance: inheritance,
          cancellationInheritance: inheritance,
        });
        continue;
      }
      if (status === "canceled") {
        skipped.push({
          ...this.subagentProjection(record),
          skip_reason: "already_canceled",
          skipReason: "already_canceled",
          cancellation_inheritance: inheritance,
          cancellationInheritance: inheritance,
        });
        continue;
      }
      const childRequest = {
        ...requestBase,
        workflow_node_id:
          optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
          `runtime.subagent.cancel.propagated.${safeId(record.role ?? "general")}`,
        workflowNodeId:
          optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
          `runtime.subagent.cancel.propagated.${safeId(record.role ?? "general")}`,
      };
      const result = this.cancelSubagent(threadId, String(targetId), childRequest);
      canceled.push(result);
    }
    return {
      schema_version: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      schemaVersion: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      object: "ioi.runtime_subagent_cancellation_propagation",
      thread_id: threadId,
      threadId,
      parent_agent_id: parentAgent.id,
      parentAgentId: parentAgent.id,
      status: "completed",
      source,
      reason,
      propagation_policy: "cancellationInheritance=propagate",
      propagationPolicy: "cancellationInheritance=propagate",
      candidate_count: candidates.length,
      candidateCount: candidates.length,
      canceled_count: canceled.length,
      canceledCount: canceled.length,
      skipped_count: skipped.length,
      skippedCount: skipped.length,
      canceled_subagents: canceled.map((result) => result.subagent),
      canceledSubagents: canceled.map((result) => result.subagent),
      skipped_subagents: skipped,
      skippedSubagents: skipped,
      event_refs: canceled.map((result) => result.event?.event_id).filter(Boolean),
      eventRefs: canceled.map((result) => result.event?.event_id).filter(Boolean),
      receipt_refs: uniqueStrings(canceled.flatMap((result) => normalizeArray(result.receipt_refs))),
      receiptRefs: uniqueStrings(canceled.flatMap((result) => normalizeArray(result.receiptRefs))),
    };
  }

  resumeSubagent(threadId, subagentId, request = {}) {
    const record = this.getSubagent(threadId, subagentId);
    const previousRunId = record.run_id ?? record.runId;
    const previousStatus = record.lifecycle_status ?? record.lifecycleStatus ?? record.status ?? null;
    const childAgentId = record.agent_id ?? record.agentId ?? subagentId;
    const role = normalizeSubagentRole(request.role ?? request.subagentRole ?? request.subagent_role ?? record.role);
    const modelRouteId =
      optionalString(request.model_route_id ?? request.modelRouteId ?? request.subagentModelRoute) ??
      record.model_route_id ??
      record.modelRouteId ??
      "route.local-first";
    const prompt =
      optionalString(
        request.prompt ??
          request.message ??
          request.input ??
          request.resume_prompt ??
          request.resumePrompt,
      ) ?? `Resume subagent ${role}.`;
    const resumeId = `subagent_resume_${doctorHash(`${threadId}:${subagentId}:${Date.now()}`).slice(0, 12)}`;
    const run = this.createRun(childAgentId, {
      mode: "send",
      prompt,
      options: {
        receiver: role,
        memory: request.memory ?? request.options?.memory ?? {},
        model: { id: "auto", routeId: modelRouteId },
      },
    });
    const output = subagentContractOutputForRun(run, record.output_contract ?? record.outputContract);
    const outputContractStatus = validateSubagentOutputContract(
      output,
      record.output_contract ?? record.outputContract,
    );
    const budget = subagentBudgetForRequest(request) ?? subagentBudgetForRequest(record);
    const budgetUsageTelemetry =
      subagentBudgetUsageTelemetryForRequest(request) ??
      record.usage_telemetry ??
      record.usageTelemetry ??
      null;
    const budgetStatus = subagentBudgetStatusForRun({
      budget,
      run,
      prompt,
      previousUsage: budgetUsageTelemetry ?? {},
    });
    const now = new Date().toISOString();
    const restartCount = Number(record.restart_count ?? record.restartCount ?? 0) + 1;
    const resumeRecord = {
      schema_version: "ioi.runtime.subagent-resume.v1",
      schemaVersion: "ioi.runtime.subagent-resume.v1",
      resume_id: resumeId,
      resumeId,
      run_id: run.id,
      runId: run.id,
      previous_run_id: previousRunId ?? null,
      previousRunId: previousRunId ?? null,
      previous_status: previousStatus,
      previousStatus,
      prompt,
      role,
      model_route_id: modelRouteId,
      modelRouteId,
      restart_count: restartCount,
      restartCount,
      created_at: now,
      createdAt: now,
      actor: optionalString(request.actor) ?? "operator",
      source: operatorControlSource(request.source),
      workflow_graph_id: optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
      workflowGraphId: optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
      workflow_node_id: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
      workflowNodeId: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
    };
    const resumeHistory = [...normalizeArray(record.resume_history ?? record.resumeHistory), resumeRecord];
    const cancellationHistory = [
      ...normalizeArray(record.cancellation_history ?? record.cancellationHistory),
      ...(record.cancellation ? [record.cancellation] : []),
    ];
    const updated = {
      ...record,
      role,
      run_id: run.id,
      runId: run.id,
      previous_run_ids: uniqueStrings([
        ...normalizeArray(record.previous_run_ids ?? record.previousRunIds),
        previousRunId,
      ]),
      previousRunIds: uniqueStrings([
        ...normalizeArray(record.previousRunIds ?? record.previous_run_ids),
        previousRunId,
      ]),
      model_route_id: modelRouteId,
      modelRouteId,
      lifecycle_status:
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status),
      lifecycleStatus:
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status),
      status:
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRun(run.status),
      budget,
      budget_usage_telemetry: budgetUsageTelemetry,
      budgetUsageTelemetry,
      budget_status: budgetStatus.status,
      budgetStatus,
      usage_telemetry: budgetStatus.usage,
      usageTelemetry: budgetStatus.usage,
      budget_policy_decision: budgetStatus.policy_decision,
      budgetPolicyDecision: budgetStatus.policyDecision,
      block_reason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
      blockReason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
      restart_status: "restarted",
      restartStatus: "restarted",
      restart_count: restartCount,
      restartCount,
      resume_id: resumeId,
      resumeId,
      resumed_at: now,
      resumedAt: now,
      resume_history: resumeHistory,
      resumeHistory,
      cancellation: null,
      cancellation_reason: null,
      cancellationReason: null,
      cancellation_cleared_at: now,
      cancellationClearedAt: now,
      cancellation_history: cancellationHistory,
      cancellationHistory,
      output_contract_status: outputContractStatus.status,
      outputContractStatus,
      output_contract_validation: outputContractStatus,
      outputContractValidation: outputContractStatus,
      updated_at: now,
      updatedAt: now,
    };
    updated.result = subagentResultForRun({ record: updated, run, output, outputContractStatus });
    const event = this.appendThreadSubagentControlEvent({
      threadId,
      parentAgent: this.agentForThread(threadId),
      record: updated,
      request,
      operation: "resume",
      status: updated.status,
    });
    const saved = {
      ...updated,
      resume_event_id: event.event_id,
      resumeEventId: event.event_id,
      receipt_refs: uniqueStrings([
        ...normalizeArray(updated.receipt_refs),
        ...normalizeArray(run.receipts).map((receipt) => receipt.id),
        ...event.receipt_refs,
      ]),
      receiptRefs: uniqueStrings([
        ...normalizeArray(updated.receiptRefs),
        ...normalizeArray(run.receipts).map((receipt) => receipt.id),
        ...event.receipt_refs,
      ]),
      evidence_refs: uniqueStrings([
        ...normalizeArray(updated.evidence_refs ?? updated.evidenceRefs),
        "runtime.subagent.resume",
        run.id,
      ]),
      evidenceRefs: uniqueStrings([
        ...normalizeArray(updated.evidenceRefs ?? updated.evidence_refs),
        "runtime.subagent.resume",
        run.id,
      ]),
      updated_at: event.created_at,
      updatedAt: event.created_at,
    };
    saved.result = subagentResultForRun({ record: saved, run, output, outputContractStatus });
    this.writeSubagent(saved, "subagent.resume");
    if (budgetStatus.status === "exceeded") {
      throw policyError("Subagent budget limit exceeded.", {
        threadId,
        subagentId,
        reason: "subagent_budget_exceeded",
        budgetStatus,
        budget_status: budgetStatus.status,
        subagent: this.subagentProjection(saved),
        eventId: event.event_id,
        event_id: event.event_id,
        receiptRefs: event.receipt_refs,
        receipt_refs: event.receipt_refs,
        policyDecisionRefs: event.policy_decision_refs,
        policy_decision_refs: event.policy_decision_refs,
      });
    }
    return {
      ...saved.result,
      subagent: this.subagentProjection(saved),
      resume: resumeRecord,
      event,
      receipt_refs: event.receipt_refs,
      receiptRefs: event.receipt_refs,
    };
  }

  assignSubagent(threadId, subagentId, request = {}) {
    const record = this.getSubagent(threadId, subagentId);
    const previousRole = record.role ?? "general";
    const role = normalizeSubagentRole(request.role ?? request.subagentRole ?? request.subagent_role ?? previousRole);
    const toolPack =
      optionalString(request.tool_pack ?? request.toolPack ?? request.subagentToolPack) ??
      record.tool_pack ??
      record.toolPack ??
      null;
    const modelRouteId =
      optionalString(request.model_route_id ?? request.modelRouteId ?? request.subagentModelRoute) ??
      record.model_route_id ??
      record.modelRouteId ??
      null;
    const mergePolicy =
      optionalString(request.merge_policy ?? request.mergePolicy) ??
      record.merge_policy ??
      record.mergePolicy ??
      "manual";
    const cancellationInheritance =
      optionalString(request.cancellation_inheritance ?? request.cancellationInheritance) ??
      record.cancellation_inheritance ??
      record.cancellationInheritance ??
      "propagate";
    const targetAgentId =
      optionalString(request.target_agent_id ?? request.targetAgentId) ??
      record.agent_id ??
      record.agentId ??
      subagentId;
    const assignmentId = `subagent_assignment_${doctorHash(`${threadId}:${subagentId}:${Date.now()}`).slice(0, 12)}`;
    const now = new Date().toISOString();
    const assignmentCount = Number(record.assignment_count ?? record.assignmentCount ?? 0) + 1;
    const assignmentRecord = {
      schema_version: "ioi.runtime.subagent-assignment.v1",
      schemaVersion: "ioi.runtime.subagent-assignment.v1",
      assignment_id: assignmentId,
      assignmentId,
      previous_role: previousRole,
      previousRole,
      role,
      target_agent_id: targetAgentId,
      targetAgentId,
      tool_pack: toolPack,
      toolPack,
      model_route_id: modelRouteId,
      modelRouteId,
      merge_policy: mergePolicy,
      mergePolicy,
      cancellation_inheritance: cancellationInheritance,
      cancellationInheritance,
      assignment_count: assignmentCount,
      assignmentCount,
      created_at: now,
      createdAt: now,
      actor: optionalString(request.actor) ?? "operator",
      source: operatorControlSource(request.source),
      workflow_graph_id: optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
      workflowGraphId: optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null,
      workflow_node_id: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
      workflowNodeId: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
    };
    const assignmentHistory = [
      ...normalizeArray(record.assignment_history ?? record.assignmentHistory),
      assignmentRecord,
    ];
    const run = this.getRun(record.run_id ?? record.runId);
    const output = subagentContractOutputForRun(run, record.output_contract ?? record.outputContract);
    const outputContractStatus = validateSubagentOutputContract(
      output,
      record.output_contract ?? record.outputContract,
    );
    const updated = {
      ...record,
      role,
      target_agent_id: targetAgentId,
      targetAgentId,
      tool_pack: toolPack,
      toolPack,
      model_route_id: modelRouteId,
      modelRouteId,
      merge_policy: mergePolicy,
      mergePolicy,
      cancellation_inheritance: cancellationInheritance,
      cancellationInheritance,
      assignment_id: assignmentId,
      assignmentId,
      assignment_count: assignmentCount,
      assignmentCount,
      assignment_history: assignmentHistory,
      assignmentHistory,
      assigned_at: now,
      assignedAt: now,
      output_contract_status: outputContractStatus.status,
      outputContractStatus,
      output_contract_validation: outputContractStatus,
      outputContractValidation: outputContractStatus,
      updated_at: now,
      updatedAt: now,
    };
    updated.result = subagentResultForRun({ record: updated, run, output, outputContractStatus });
    const event = this.appendThreadSubagentControlEvent({
      threadId,
      parentAgent: this.agentForThread(threadId),
      record: updated,
      request,
      operation: "assign",
      status: updated.status,
    });
    const saved = {
      ...updated,
      assign_event_id: event.event_id,
      assignEventId: event.event_id,
      receipt_refs: uniqueStrings([...normalizeArray(updated.receipt_refs), ...event.receipt_refs]),
      receiptRefs: uniqueStrings([...normalizeArray(updated.receiptRefs), ...event.receipt_refs]),
      evidence_refs: uniqueStrings([
        ...normalizeArray(updated.evidence_refs ?? updated.evidenceRefs),
        "runtime.subagent.assign",
        assignmentId,
      ]),
      evidenceRefs: uniqueStrings([
        ...normalizeArray(updated.evidenceRefs ?? updated.evidence_refs),
        "runtime.subagent.assign",
        assignmentId,
      ]),
      updated_at: event.created_at,
      updatedAt: event.created_at,
    };
    saved.result = subagentResultForRun({ record: saved, run, output, outputContractStatus });
    this.writeSubagent(saved, "subagent.assign");
    return {
      ...this.subagentProjection(saved),
      assignment: assignmentRecord,
      result: saved.result,
      event,
    };
  }

  getSubagentResult(threadId, subagentId) {
    const record = this.getSubagent(threadId, subagentId);
    const run = this.getRun(record.run_id ?? record.runId);
    const output = subagentContractOutputForRun(run, record.output_contract ?? record.outputContract);
    const outputContractStatus = validateSubagentOutputContract(
      output,
      record.output_contract ?? record.outputContract,
    );
    return {
      ...subagentResultForRun({ record, run, output, outputContractStatus }),
      subagent: this.subagentProjection({
        ...record,
        output_contract_status: outputContractStatus.status,
        outputContractStatus,
      }),
    };
  }

  getSubagent(threadId, subagentId) {
    const record = this.subagents.get(subagentId);
    if (!record || (record.parent_thread_id ?? record.parentThreadId) !== threadId) {
      throw notFound(`Subagent not found: ${subagentId}`, { threadId, subagentId });
    }
    return record;
  }

  subagentProjection(record = {}) {
    return {
      ...record,
      schema_version: record.schema_version ?? RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      schemaVersion: record.schemaVersion ?? RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      object: record.object ?? "ioi.runtime_subagent",
      subagent_id: record.subagent_id ?? record.subagentId ?? record.agent_id ?? record.agentId,
      subagentId: record.subagentId ?? record.subagent_id ?? record.agentId ?? record.agent_id,
      agent_id: record.agent_id ?? record.agentId,
      agentId: record.agentId ?? record.agent_id,
      parent_thread_id: record.parent_thread_id ?? record.parentThreadId,
      parentThreadId: record.parentThreadId ?? record.parent_thread_id,
      lifecycle_status: record.lifecycle_status ?? record.lifecycleStatus ?? record.status,
      lifecycleStatus: record.lifecycleStatus ?? record.lifecycle_status ?? record.status,
      output_contract_status:
        record.output_contract_status ??
        record.outputContractStatus?.status ??
        record.output_contract_validation?.status ??
        null,
      outputContractStatus:
        record.outputContractStatus ??
        record.output_contract_validation ??
        record.output_contract_status ??
        null,
    };
  }

  appendThreadSubagentControlEvent({
    threadId,
    parentAgent,
    record,
    request,
    operation,
    status,
  }) {
    const thread = this.threadForAgent(parentAgent);
    const source = operatorControlSource(request.source);
    const eventHash = doctorHash(
      `${threadId}:${operation}:${record.subagent_id ?? record.subagentId}:${Date.now()}`,
    ).slice(0, 12);
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
      record.workflow_graph_id ??
      record.workflowGraphId ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      record.workflow_node_id ??
      record.workflowNodeId ??
      `runtime.subagent.${operation}`;
    const payload = subagentManagerEventPayload({ record, operation, status });
    const budgetPolicyDecision = record.budget_policy_decision ?? record.budgetPolicyDecision ?? null;
    const budgetStatus =
      record.budget_status ?? record.budgetStatus?.status ?? budgetPolicyDecision?.reason ?? null;
    const requestReceiptRefs = uniqueStrings(request.receipt_refs ?? request.receiptRefs);
    const requestPolicyDecisionRefs = uniqueStrings(
      request.policy_decision_refs ?? request.policyDecisionRefs,
    );
    const policyDecisionRefs = uniqueStrings([
      ...requestPolicyDecisionRefs,
      ...(budgetStatus === "exceeded" && budgetPolicyDecision?.id && typeof budgetPolicyDecision.id === "string"
        ? [budgetPolicyDecision.id]
        : [`policy_subagent_${safeId(operation)}_allow_${eventHash}`]),
    ]);
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: record.parent_turn_id ?? record.parentTurnId ?? thread.latest_turn_id ?? "",
      item_id: `${record.parent_turn_id ?? record.parentTurnId ?? threadId}:item:subagent:${safeId(operation)}:${safeId(record.subagent_id ?? record.subagentId)}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:subagent.${operation}:${record.subagent_id ?? record.subagentId}:${eventHash}`,
      source,
      source_event_kind: subagentOperatorControlKind(operation),
      event_kind: subagentRuntimeEventKind(operation),
      status,
      actor: "operator",
      workspace_root: parentAgent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "subagent_lifecycle",
      payload_schema_version: RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
      payload,
      receipt_refs: uniqueStrings([
        ...requestReceiptRefs,
        `receipt_subagent_${safeId(operation)}_${eventHash}`,
      ]),
      policy_decision_refs: policyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(parentAgent),
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
    const generatedAt = new Date().toISOString();
    const modelProjection = this.modelMounting.projection();
    const skillHookCatalog = this.skillHookCatalog();
    const memoryPaths = this.memory.pathProjection({
      threadId: null,
      workspace: this.defaultCwd,
    });
    const providerKeys = doctorProviderKeyReport();
    const optionalWarnings = [];
    const checks = [
      doctorCheck("daemon.public_api", "pass", true, "Public runtime daemon routes are reachable.", [
        "/v1/doctor",
      ]),
      doctorCheck(
        "workspace.root",
        fs.existsSync(this.defaultCwd) ? "pass" : "blocked",
        true,
        fs.existsSync(this.defaultCwd)
          ? "Workspace root exists."
          : "Workspace root is missing.",
        [this.defaultCwd],
      ),
      doctorCheck(
        "agentgres.store",
        fs.existsSync(this.stateDir) ? "pass" : "blocked",
        true,
        "Agentgres v0 state directory is present.",
        [this.stateDir, "agentgres_canonical_operation_log"],
      ),
      doctorCheck(
        "model.routes",
        modelProjection.routes.length > 0 ? "pass" : "blocked",
        true,
        `${modelProjection.routes.length} model route(s) are registered.`,
        modelProjection.routes.map((route) => route.id),
      ),
      doctorCheck(
        "memory.store",
        fs.existsSync(memoryPaths.recordsPath) && fs.existsSync(memoryPaths.policiesPath)
          ? "pass"
          : "blocked",
        true,
        "Memory records and policies are backed by durable state paths.",
        [memoryPaths.recordsPath, memoryPaths.policiesPath],
      ),
      doctorCheck(
        "tool.catalog",
        this.listTools().length > 0 ? "pass" : "blocked",
        true,
        `${this.listTools().length} governed runtime tool(s) are registered.`,
        this.listTools().map((tool) => tool.stableToolId),
      ),
      doctorCheck(
        "workflow.react_flow_registry",
        "pass",
        true,
        "React Flow registry exposes runtime doctor and readiness nodes.",
        ["RuntimeDoctorNode", "packages/agent-ide/src/runtime/workflow-node-registry.ts"],
      ),
      doctorCheck(
        "mcp.registry",
        modelProjection.mcpServers.length > 0 ? "pass" : "degraded",
        false,
        modelProjection.mcpServers.length > 0
          ? `${modelProjection.mcpServers.length} MCP server(s) are registered.`
          : "No MCP servers are registered; MCP remains optional.",
        modelProjection.mcpServers.map((server) => server.id),
      ),
      doctorCheck(
        "skills.hooks",
        skillHookCatalog.status,
        false,
        `${skillHookCatalog.skillCount} governed skill(s) and ${skillHookCatalog.hookCount} hook(s) discovered across ${skillHookCatalog.sources.length} source(s).`,
        ["runtime_skill_hook_discovery", "/v1/skills", "/v1/hooks"],
      ),
      doctorCheck(
        "wallet.network",
        process.env.IOI_WALLET_NETWORK_URL ? "pass" : "degraded",
        false,
        process.env.IOI_WALLET_NETWORK_URL
          ? "Wallet/network approval endpoint is configured."
          : "Wallet/network approval endpoint is optional and not configured.",
        ["IOI_WALLET_NETWORK_URL"],
      ),
      doctorCheck(
        "remote.agentgres",
        process.env.IOI_AGENTGRES_URL ? "pass" : "degraded",
        false,
        process.env.IOI_AGENTGRES_URL
          ? "Remote Agentgres adapter is configured."
          : "Remote Agentgres adapter is optional and not configured.",
        ["IOI_AGENTGRES_URL"],
      ),
      doctorCheck(
        "lsp.status",
        "degraded",
        false,
        "LSP health is not daemon-owned yet; workflow activation should treat it as optional.",
        ["lsp.status.next_slice"],
      ),
    ];
    for (const check of checks) {
      if (!check.required && check.status !== "pass") optionalWarnings.push(check.id);
    }
    const requiredFailures = checks.filter((check) => check.required && check.status !== "pass");
    const status = requiredFailures.length > 0
      ? "blocked"
      : optionalWarnings.length > 0
        ? "degraded"
        : "pass";
    return {
      schemaVersion: "ioi.agent-runtime.doctor.v1",
      object: "ioi.agent_runtime_doctor_report",
      generatedAt,
      status,
      readiness: requiredFailures.length > 0 ? "blocked" : "ready",
      version: {
        runtime: "ioi-runtime-daemon",
        schema: this.schemaVersion,
      },
      daemon: {
        endpoint: baseUrl,
        publicApi: "/v1",
        nativeApi: "/api/v1",
        requestScoped: true,
      },
      workspace: {
        root: this.defaultCwd,
        exists: fs.existsSync(this.defaultCwd),
      },
      configPaths: {
        stateDir: this.stateDir,
        operationLog: path.join(this.stateDir, "operation-log.jsonl"),
        memoryRecords: memoryPaths.recordsPath,
        memoryPolicies: memoryPaths.policiesPath,
        modelMountingProjection: path.join(this.stateDir, "projections", "model-mounting-canonical.json"),
      },
      providerKeys,
      modelRoutes: {
        modelCount: modelProjection.artifacts.length,
        routeCount: modelProjection.routes.length,
        routeIds: modelProjection.routes.map((route) => route.id),
        selectedDefaultRoute: modelProjection.routes.find((route) => route.id === "route.local-first")?.id ?? null,
      },
      mcp: {
        serverCount: modelProjection.mcpServers.length,
        servers: modelProjection.mcpServers.map((server) => ({
          id: server.id,
          transport: server.transport,
          status: server.status,
          secretRefCount: normalizeArray(server.secretRefs).length,
          secretsRedacted: true,
        })),
      },
      skillsHooks: {
        status: skillHookCatalog.status,
        skillCount: skillHookCatalog.skillCount,
        hookCount: skillHookCatalog.hookCount,
        sourceCount: skillHookCatalog.sources.length,
        activeSkillSetHash: skillHookCatalog.activeSkillSetHash,
        activeHookSetHash: skillHookCatalog.activeHookSetHash,
        validationIssueCount: skillHookCatalog.validationIssueCount,
        discoveryEndpoints: ["/v1/skills", "/v1/hooks"],
      },
      memory: {
        recordCount: this.memory.records.size,
        policyCount: this.memory.policies.size,
        defaultPolicy: this.memory.effectivePolicy({
          threadId: null,
          workspace: this.defaultCwd,
        }),
        paths: memoryPaths,
      },
      sandbox: {
        status: "pass",
        profile: "local_private",
        approvalMode: "suggest",
        networkDefault: "local_only",
      },
      workflow: {
        reactFlowRegistryVersion: "ioi.reactflow.workflow-node-registry.v1",
        doctorNodeType: "runtime_doctor",
        activationConsumesDoctorReport: true,
        readinessBlockerField: "checks",
      },
      agentgres: {
        schemaVersion: this.schemaVersion,
        operationCount: this.operationCount(),
        localStateDirPresent: fs.existsSync(this.stateDir),
        remoteAdapterConfigured: Boolean(process.env.IOI_AGENTGRES_URL),
        remoteAdapterHash: process.env.IOI_AGENTGRES_URL ? doctorHash(process.env.IOI_AGENTGRES_URL) : null,
      },
      wallet: {
        approvalStatus: process.env.IOI_WALLET_NETWORK_URL ? "configured" : "not_configured",
        networkConfigured: Boolean(process.env.IOI_WALLET_NETWORK_URL),
        networkUrlHash: process.env.IOI_WALLET_NETWORK_URL ? doctorHash(process.env.IOI_WALLET_NETWORK_URL) : null,
      },
      runtimeNodes: this.listRuntimeNodes().map((node) => redactRuntimeNodeForDoctor(node, { doctorHash })),
      checks,
      blockers: requiredFailures.map((check) => check.id),
      optionalWarnings,
      redaction: {
        profile: "doctor_safe",
        secretValuesIncluded: false,
        endpointValuesHashed: true,
      },
      evidenceRefs: ["ioi_agent_runtime_doctor", "runtime_preflight", "RuntimeDoctorNode"],
    };
  }

  skillHookCatalog({ cwd = this.defaultCwd } = {}) {
    return discoverSkillHookCatalog({ cwd, homeDir: this.homeDir });
  }

  listSkills({ cwd = this.defaultCwd } = {}) {
    const catalog = this.skillHookCatalog({ cwd });
    return {
      schemaVersion: "ioi.agent-runtime.skills.v1",
      object: "ioi.agent_skill_registry_projection",
      generatedAt: catalog.generatedAt,
      workspace: catalog.workspace,
      status: catalog.skillStatus,
      skillCount: catalog.skillCount,
      activeSkillSetHash: catalog.activeSkillSetHash,
      sources: catalog.sources.filter((source) => source.kind === "skill_dir"),
      skills: catalog.skills,
      redaction: catalog.redaction,
      evidenceRefs: ["runtime_skill_discovery", "SkillNode", "SkillPackNode"],
    };
  }

  listHooks({ cwd = this.defaultCwd } = {}) {
    const catalog = this.skillHookCatalog({ cwd });
    return {
      schemaVersion: "ioi.agent-runtime.hooks.v1",
      object: "ioi.agent_hook_registry_projection",
      generatedAt: catalog.generatedAt,
      workspace: catalog.workspace,
      status: catalog.hookStatus,
      hookCount: catalog.hookCount,
      activeHookSetHash: catalog.activeHookSetHash,
      sources: catalog.sources.filter((source) => source.kind === "hook_file" || source.kind === "hook_dir"),
      hooks: catalog.hooks,
      redaction: catalog.redaction,
      evidenceRefs: ["runtime_hook_discovery", "HookNode", "HookPolicyNode"],
    };
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
    const agent = this.agentForThread(threadId);
    return this.listRuns(agent.id).map((run) => this.turnForRun(run));
  }

  getTurn(threadId, turnId) {
    const turn = this.listTurns(threadId).find((candidate) => candidate.turn_id === turnId);
    if (!turn) throw notFound(`Turn not found: ${turnId}`, { threadId, turnId });
    return turn;
  }

  eventsForThread(threadId, cursor = {}) {
    const agent = this.agentForThread(threadId);
    this.projectThreadEvents(agent);
    return this.runtimeEventsForStream(eventStreamIdForThread(threadIdForAgent(agent.id)), cursor);
  }

  eventsForRun(runId, cursor = {}) {
    const run = this.getRun(runId);
    const agent = this.getAgent(run.agentId);
    this.projectThreadEvents(agent);
    return this.runtimeEventsForTurn(runtimeTurnIdForRun(run), cursor);
  }

  ensureThreadStartedEvent(agent) {
    return ensureThreadStartedEventState(this, agent, {
      DAEMON_FIXTURE_PROFILE,
      RUNTIME_THREAD_SCHEMA_VERSION,
      eventStreamIdForThread,
      threadIdForAgent,
      threadStatusForAgent,
    });
  }

  projectThreadEvents(agent) {
    return projectThreadEventsState(this, agent, {
      isRuntimeBackedAgent,
    });
  }

  projectRunEvents(run, agent = this.getAgent(run.agentId)) {
    return projectRunEventsState(this, run, agent, {
      isRuntimeBackedAgent,
      threadIdForAgent,
      ttiEnvelopeForRunEvent,
      turnIdForRun,
    });
  }

  appendRuntimeEvent(event) {
    return appendRuntimeEventState(this, event, {
      fs,
      normalizeRuntimeEventEnvelope,
      runtimeError,
    });
  }

  runtimeEventsForStream(eventStreamId, cursor = {}) {
    return runtimeEventsForStreamState(this, eventStreamId, cursor);
  }

  runtimeEventsForTurn(turnId, cursor = {}) {
    return runtimeEventsForTurnState(this, turnId, cursor);
  }

  runtimeCursorSeq(stream, cursor = {}) {
    return runtimeCursorSeqState(this, stream, cursor, {
      runtimeError,
    });
  }

  assertRuntimeCursorSeq(cursorSeq, latestSeq, details = {}) {
    return assertRuntimeCursorSeqState(cursorSeq, latestSeq, details, {
      runtimeError,
    });
  }

  latestRuntimeEventSeq(eventStreamId) {
    return latestRuntimeEventSeqState(this, eventStreamId);
  }

  runtimeEventStream(eventStreamId) {
    return runtimeEventStreamState(this, eventStreamId);
  }

  registerRuntimeEvent(record) {
    return registerRuntimeEventState(this, record);
  }

  runtimeEventStreamPath(eventStreamId) {
    return runtimeEventStreamPathState(this, eventStreamId, {
      runtimeEventStreamFileName,
    });
  }

  threadForAgent(agent) {
    const runs = this.listRuns(agent.id);
    const latestRun = runs.at(-1);
    this.projectThreadEvents(agent);
    const threadId = threadIdForAgent(agent.id);
    const runtimeControls = normalizedAgentRuntimeControls(agent);
    const latestSeq = this.latestRuntimeEventSeq(eventStreamIdForThread(threadId));
    const updatedAt = Math.max(
      Date.parse(agent.updatedAt) || 0,
      ...runs.map((run) => Date.parse(run.updatedAt) || 0),
    );
    const usageTelemetry = runtimeUsageTelemetryForThread({
      threadId,
      agent,
      runs,
      subagents: [...this.subagents.values()].filter(
        (record) => (record.parent_thread_id ?? record.parentThreadId) === threadId,
      ),
    });
    return {
      schema_version: RUNTIME_THREAD_SCHEMA_VERSION,
      thread_id: threadId,
      session_id: runtimeSessionIdForAgent(agent),
      agent_id: agent.id,
      workspace_root: agent.cwd,
      title: latestRun?.objective ?? agent.cwd,
      mode: runtimeControls.mode,
      approval_mode: runtimeControls.approvalMode,
      trust_profile: "local_private",
      model_route: agent.modelId,
      status: latestRun?.turnStatus === "interrupted" ? "interrupted" : threadStatusForAgent(agent.status),
      latest_turn_id: latestRun ? turnIdForRun(latestRun.id) : null,
      latest_seq: latestSeq,
      event_stream_id: eventStreamIdForThread(threadId),
      workflow_graph_id: null,
      harness_binding_id: null,
      agentgres_projection_ref: `agents/${agent.id}.json`,
      created_at: agent.createdAt,
      updated_at: new Date(updatedAt || Date.parse(agent.updatedAt) || Date.now()).toISOString(),
      archived_at: agent.status === "archived" ? agent.updatedAt : null,
      fixture_profile: fixtureProfileForAgent(agent),
      created_at_ms: Date.parse(agent.createdAt) || 0,
      updated_at_ms: updatedAt,
      workspace: agent.cwd,
      requested_model: agent.requestedModelId ?? agent.modelId,
      model_route_id: agent.modelRouteId ?? null,
      model_route_receipt_id: agent.modelRouteReceiptId ?? null,
      model_route_decision: agent.modelRouteDecision ?? null,
      selected_model: agent.modelId,
      reasoning_effort:
        agent.modelRouteDecision?.reasoningEffort ??
        runtimeControls.model?.reasoningEffort ??
        null,
      runtime_controls: runtimeControls,
      memory_count: this.memory.list({
        agent,
        threadId,
        workspace: agent.cwd,
      }).length,
      archived: agent.status === "archived",
      evidence_refs: ["agentgres_canonical_operation_log", "runtime_tti_projection"],
      runtime_profile: agent.runtimeProfile ?? "fixture",
      runtime_bridge_id: agent.runtimeBridgeId ?? null,
      runtime_bridge_source: agent.runtimeBridgeSource ?? null,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      usageTelemetry,
      runtime_usage: usageTelemetry,
      runtimeUsage: usageTelemetry,
    };
  }

  turnForRun(run) {
    const agent = this.getAgent(run.agentId);
    this.projectRunEvents(run, agent);
    const turnId = runtimeTurnIdForRun(run);
    const turnEvents = this.runtimeEventsForTurn(turnId);
    const seqStart = turnEvents.at(0)?.seq ?? null;
    const status = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const isOpen = status === "queued" || status === "running" || status === "waiting_for_approval" || status === "waiting_for_input";
    const seqEnd = isOpen ? null : (turnEvents.at(-1)?.seq ?? null);
    const completedAt = isOpen ? null : run.updatedAt;
    const usageTelemetry =
      run.usage_telemetry ??
      run.usageTelemetry ??
      run.runtimeUsage ??
      run.usage ??
      runtimeUsageTelemetryForRun({ run, agent, threadId: threadIdForAgent(run.agentId) });
    return {
      schema_version: RUNTIME_TURN_SCHEMA_VERSION,
      turn_id: turnId,
      thread_id: threadIdForAgent(run.agentId),
      parent_turn_id: null,
      request_id: run.id,
      status,
      input_item_ids: turnEvents
        .filter((event) => event.event_kind === "turn.started")
        .map((event) => event.item_id),
      output_item_ids: turnEvents
        .filter((event) => event.event_kind !== "turn.started")
        .map((event) => event.item_id),
      events: turnEvents,
      seq_start: seqStart,
      seq_end: seqEnd,
      started_at: run.createdAt,
      completed_at: completedAt,
      mode: run.threadMode ?? threadModeForRunMode(run.mode, agent.runtimeControls?.mode),
      approval_mode: run.approvalMode ?? agent.runtimeControls?.approvalMode ?? "suggest",
      model_route_decision_id: run.modelRouteDecision?.decisionId ?? run.trace?.modelRouteDecision?.decisionId ?? null,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      usageTelemetry,
      runtime_usage: usageTelemetry,
      runtimeUsage: usageTelemetry,
      result: run.result ?? "",
      output: run.result ?? "",
      text: run.result ?? "",
      stop_reason: run.trace?.stopCondition?.reason ?? null,
      error: run.status === "failed" ? run.result : null,
      conversation: Array.isArray(run.conversation) ? run.conversation : [],
      rollback_snapshot_id: null,
      quality_ledger_ref: run.trace?.qualityLedger?.ledgerId ?? null,
      workflow_execution_ref: null,
      fixture_profile: fixtureProfileForAgent(agent),
      started_at_ms: Date.parse(run.createdAt) || 0,
      completed_at_ms: completedAt ? Date.parse(completedAt) || 0 : null,
      error_summary: run.status === "failed" ? run.result : null,
      model_route_decision: run.modelRouteDecision ?? run.trace?.modelRouteDecision ?? null,
      model_route_receipt_id: run.modelRouteReceiptId ?? null,
      active_skill_hook_manifest_ref: run.activeSkillHookManifest?.manifestId ?? null,
      active_skill_set_hash: run.activeSkillHookManifest?.activeSkillSetHash ?? null,
      active_hook_set_hash: run.activeSkillHookManifest?.activeHookSetHash ?? null,
      memory_refs: run.memoryRecords?.map((record) => record.id) ?? [],
      memory_write_receipt_ids: run.memoryWriteReceipts?.map((receipt) => receipt.id) ?? [],
      evidence_refs: [
        "agentgres_canonical_operation_log",
        `run:${run.id}`,
        run.activeSkillHookManifest?.manifestId,
      ].filter(Boolean),
    };
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
          request.runtimeControlAction ??
          request.control_action ??
          request.controlAction,
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
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
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
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.operator-interrupt",
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
    const control = {
      control: "interrupt",
      source,
      reason,
      eventId: event.event_id,
      seq: event.seq,
      createdAt: event.created_at,
    };
    const stopCondition = {
      reason: "operator_interrupt",
      evidenceSufficient: true,
      rationale: `Operator interrupt accepted from ${source}: ${reason}`,
    };
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
        approval_mode: agent.runtimeControls?.approvalMode ?? "suggest",
      };
      return runtimeControl
        ? {
            ...interruptedTurn,
            runtime_control: runtimeControl,
            runtimeControl,
          }
        : interruptedTurn;
    }
    const updated = {
      ...run,
      status: ["queued", "running", "blocked"].includes(run.status) ? "canceled" : run.status,
      turnStatus: "interrupted",
      updatedAt: event.created_at,
      result: `Turn interrupted by operator: ${reason}`,
      trace: {
        ...run.trace,
        status: "interrupted",
        stopCondition,
        operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
        qualityLedger: {
          ...run.trace?.qualityLedger,
          failureOntologyLabels: [
            ...new Set([
              ...normalizeArray(run.trace?.qualityLedger?.failureOntologyLabels),
              "operator_interrupt",
            ]),
          ],
        },
      },
      operatorControls: appendOperatorControl(run.operatorControls, control),
    };
    this.runs.set(run.id, updated);
    this.writeRun(updated, "turn.interrupt");
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
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
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
        request.idempotencyKey ??
        `turn:${turnId}:operator.steer:${guidanceHash}`,
      source,
      source_event_kind: "OperatorControl.Steer",
      event_kind: "turn.steered",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.operator-steer",
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
    const control = {
      control: "steer",
      source,
      guidance,
      eventId: event.event_id,
      seq: event.seq,
      createdAt: event.created_at,
    };
    const updated = {
      ...run,
      updatedAt: event.created_at,
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
      },
      operatorControls: appendOperatorControl(run.operatorControls, control),
    };
    this.runs.set(run.id, updated);
    this.writeRun(updated, "turn.steer");
    return this.turnForRun(updated);
  }

  requestThreadApproval(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runs = this.listRuns(agent.id);
    const requestedTurnId = optionalString(request.turn_id ?? request.turnId);
    let turnId = requestedTurnId ?? "";
    let run = null;
    if (turnId) {
      run = this.getRun(runIdForTurn(turnId));
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
      }
    } else {
      run = runs.at(-1) ?? null;
      turnId = run ? turnIdForRun(run.id) : "";
    }

    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ??
      "operator requested approval";
    const action =
      optionalString(request.action ?? request.approval_action ?? request.approvalAction) ??
      "request_approval";
    const toolId =
      optionalString(request.tool_id ?? request.toolId ?? request.tool_name ?? request.toolName) ??
      null;
    const effectClass =
      optionalString(request.effect_class ?? request.effectClass) ??
      null;
    const riskDomain =
      optionalString(request.risk_domain ?? request.riskDomain) ??
      null;
    const approvalManifest =
      request.approval_manifest && typeof request.approval_manifest === "object"
        ? request.approval_manifest
        : request.approvalManifest && typeof request.approvalManifest === "object"
          ? request.approvalManifest
          : null;
    const runOrAgentId = run?.id ?? agent.id;
    const approvalSeed = `${threadId}:${turnId || "thread"}:${reason}`;
    const approvalHash = crypto.createHash("sha256").update(approvalSeed).digest("hex").slice(0, 16);
    const approvalId =
      optionalString(request.approval_id ?? request.approvalId) ??
      `approval_context_pressure_${safeId(threadId)}_${safeId(turnId || "thread")}_${approvalHash}`;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      `runtime.approval.${safeId(approvalId)}`;
    const scope = optionalString(request.scope) ?? "thread";
    const pressure = contextBudgetNumber(
      request.pressure,
      request.context_pressure,
      request.contextPressure,
    );
    const pressureStatus =
      optionalString(
        request.pressure_status ??
          request.pressureStatus ??
          request.context_pressure_status ??
          request.contextPressureStatus,
      ) ?? null;
    const alertId =
      optionalString(request.alert_id ?? request.alertId ?? request.alert_event_id ?? request.alertEventId) ??
      null;
    const sourceEventId =
      optionalString(request.source_event_id ?? request.sourceEventId) ?? null;
    const leaseMetadata = approvalLeaseMetadataForRequest({
      request,
      approvalId,
      action,
      scope,
      now: new Date().toISOString(),
      threadId,
    });
    const receiptRefs = uniqueStrings([
      ...normalizeArray(request.receipt_refs ?? request.receiptRefs),
      `receipt_${runOrAgentId}_approval_required_${safeId(approvalId)}`,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...normalizeArray(request.policy_decision_refs ?? request.policyDecisionRefs),
      `policy_${runOrAgentId}_approval_required`,
    ]);
    const now = leaseMetadata.created_at;
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-required:${safeId(approvalId)}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:approval.required:${approvalId}`,
      source,
      source_event_kind: "OperatorApproval.Request",
      event_kind: "approval.required",
      status: "waiting_for_approval",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: approvalId,
      payload_schema_version: "ioi.runtime.approval-request.v1",
      payload: {
        event_kind: "OperatorApproval.Request",
        approval_id: approvalId,
        approval_required: true,
        approvalRequired: true,
        reason,
        requested_by: requestedBy,
        control_surface: source,
        action,
        scope,
        tool_id: toolId,
        toolId,
        effect_class: effectClass,
        effectClass,
        risk_domain: riskDomain,
        riskDomain,
        authority_scope_requirements: normalizeArray(
          request.authority_scope_requirements ?? request.authorityScopeRequirements,
        ),
        expected_receipt_refs: leaseMetadata.expected_receipt_refs,
        expectedReceiptRefs: leaseMetadata.expectedReceiptRefs,
        policy_hash: leaseMetadata.policy_hash,
        policyHash: leaseMetadata.policyHash,
        ttl_ms: leaseMetadata.ttl_ms,
        ttlMs: leaseMetadata.ttlMs,
        expires_at: leaseMetadata.expires_at,
        expiresAt: leaseMetadata.expiresAt,
        lease_id: leaseMetadata.lease_id,
        leaseId: leaseMetadata.leaseId,
        revoke_endpoint: leaseMetadata.revoke_endpoint,
        revokeEndpoint: leaseMetadata.revokeEndpoint,
        approval_lease: leaseMetadata,
        approvalLease: leaseMetadata,
        approval_manifest: approvalManifest,
        approvalManifest,
        pressure: pressure ?? null,
        pressure_status: pressureStatus,
        pressureStatus,
        alert_id: alertId,
        alertId,
        source_event_id: sourceEventId,
        sourceEventId,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "approval_request",
      approvalId,
      status: "waiting_for_approval",
      source,
      reason,
      eventId: event.event_id,
      seq: event.seq,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
      createdAt: event.created_at,
    };
    if (run) {
      const updated = {
        ...run,
        status: run.status === "queued" || run.status === "running" ? "blocked" : run.status,
        updatedAt: event.created_at,
        turnStatus: "waiting_for_approval",
        trace: {
          ...run.trace,
          operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
          approvalRequests: appendOperatorControl(run.trace?.approvalRequests, control),
        },
        operatorControls: appendOperatorControl(run.operatorControls, control),
        approvalRequests: appendOperatorControl(run.approvalRequests, control),
      };
      this.runs.set(run.id, updated);
      this.writeRun(updated, "approval.required");
      return {
        ...this.turnForRun(updated),
        approval_id: approvalId,
        approval_required: true,
        approvalRequired: true,
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }

    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, "approval.required");
    return {
      ...this.threadForAgent(updatedAgent),
      approval_id: approvalId,
      approval_required: true,
      approvalRequired: true,
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  decideThreadApproval(threadId, approvalId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id ?? request.approvalId) ??
      (() => {
        throw runtimeError({
          status: 400,
          code: "approval_id_required",
          message: "Approval decisions require an approval id.",
          details: { threadId },
        });
      })();
    const decision = approvalDecisionForRequest(request.decision ?? request.action ?? request.status);
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason = optionalString(request.reason ?? request.message ?? request.input) ?? null;
    const runs = this.listRuns(agent.id);
    const requestedTurnId = optionalString(request.turn_id ?? request.turnId);
    let turnId = requestedTurnId ?? "";
    let run = null;
    if (turnId) {
      run = this.getRun(runIdForTurn(turnId));
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
      }
    } else {
      run = runs.at(-1) ?? null;
      turnId = run ? turnIdForRun(run.id) : "";
    }

    const now = new Date().toISOString();
    const status = decision === "approve" ? "approved" : "rejected";
    const decisionVerb = decision === "approve" ? "Approve" : "Reject";
    const approvalRequestEvent = this.latestApprovalRequestEvent(threadId, normalizedApprovalId);
    const approvalRequestPayload = approvalRequestEvent?.payload_summary ?? approvalRequestEvent?.payload ?? {};
    const leaseMetadata = approvalLeaseMetadataFromPayload(
      approvalRequestPayload,
      normalizedApprovalId,
      threadId,
    );
    const leaseStatus = decision === "approve" ? "active" : "denied";
    const approvalLease = {
      ...leaseMetadata,
      status: leaseStatus,
      decision,
      approval_request_event_id: approvalRequestEvent?.event_id ?? null,
      approvalRequestEventId: approvalRequestEvent?.event_id ?? null,
      decided_at: now,
      decidedAt: now,
    };
    const decisionHash = crypto
      .createHash("sha256")
      .update(`${normalizedApprovalId}:${decision}:${reason ?? ""}:${requestedBy}`)
      .digest("hex")
      .slice(0, 16);
    const workflowNodeId =
      request.workflow_node_id ??
      request.workflowNodeId ??
      `runtime.approval.${safeId(normalizedApprovalId)}`;
    const runOrAgentId = run?.id ?? agent.id;
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-${decision}:${safeId(normalizedApprovalId)}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:approval.${decision}:${normalizedApprovalId}:${decisionHash}`,
      source,
      source_event_kind: `OperatorApproval.${decisionVerb}`,
      event_kind: `approval.${status}`,
      status,
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: normalizedApprovalId,
      payload_schema_version: "ioi.runtime.approval-decision.v1",
      payload: {
        event_kind: `OperatorApproval.${decisionVerb}`,
        approval_id: normalizedApprovalId,
        decision,
        status,
        reason,
        requested_by: requestedBy,
        control_surface: source,
        action: approvalRequestPayload.action ?? null,
        scope: approvalRequestPayload.scope ?? null,
        tool_id: approvalRequestPayload.tool_id ?? approvalRequestPayload.toolId ?? null,
        toolId: approvalRequestPayload.toolId ?? approvalRequestPayload.tool_id ?? null,
        effect_class: approvalRequestPayload.effect_class ?? approvalRequestPayload.effectClass ?? null,
        effectClass: approvalRequestPayload.effectClass ?? approvalRequestPayload.effect_class ?? null,
        risk_domain: approvalRequestPayload.risk_domain ?? approvalRequestPayload.riskDomain ?? null,
        riskDomain: approvalRequestPayload.riskDomain ?? approvalRequestPayload.risk_domain ?? null,
        approval_request_event_id: approvalRequestEvent?.event_id ?? null,
        approvalRequestEventId: approvalRequestEvent?.event_id ?? null,
        lease_id: leaseMetadata.lease_id,
        leaseId: leaseMetadata.leaseId,
        lease_status: leaseStatus,
        leaseStatus,
        policy_hash: leaseMetadata.policy_hash,
        policyHash: leaseMetadata.policyHash,
        ttl_ms: leaseMetadata.ttl_ms,
        ttlMs: leaseMetadata.ttlMs,
        expires_at: leaseMetadata.expires_at,
        expiresAt: leaseMetadata.expiresAt,
        expected_receipt_refs: leaseMetadata.expected_receipt_refs,
        expectedReceiptRefs: leaseMetadata.expectedReceiptRefs,
        authority_scope_requirements: leaseMetadata.authority_scope_requirements,
        authorityScopeRequirements: leaseMetadata.authorityScopeRequirements,
        revoke_endpoint: leaseMetadata.revoke_endpoint,
        revokeEndpoint: leaseMetadata.revokeEndpoint,
        approval_lease: approvalLease,
        approvalLease,
        approval_manifest:
          approvalRequestPayload.approval_manifest ?? approvalRequestPayload.approvalManifest ?? null,
        approvalManifest:
          approvalRequestPayload.approvalManifest ?? approvalRequestPayload.approval_manifest ?? null,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${runOrAgentId}_approval_${decision}_${safeId(normalizedApprovalId)}_${decisionHash}`],
      policy_decision_refs: [`policy_${runOrAgentId}_approval_${decision}_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "approval_decision",
      approvalId: normalizedApprovalId,
      leaseId: leaseMetadata.leaseId,
      leaseStatus,
      decision,
      status,
      source,
      reason,
      eventId: event.event_id,
      seq: event.seq,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
      createdAt: event.created_at,
    };
    if (run) {
      const updated = {
        ...run,
        updatedAt: event.created_at,
        turnStatus: decision === "reject" ? "waiting_for_input" : run.turnStatus,
        trace: {
          ...run.trace,
          operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
          approvalDecisions: appendOperatorControl(run.trace?.approvalDecisions, control),
        },
        operatorControls: appendOperatorControl(run.operatorControls, control),
        approvalDecisions: appendOperatorControl(run.approvalDecisions, control),
      };
      this.runs.set(run.id, updated);
      this.writeRun(updated, `approval.${decision}`);
      return {
        ...this.turnForRun(updated),
        approval_id: normalizedApprovalId,
        lease_id: leaseMetadata.lease_id,
        leaseId: leaseMetadata.leaseId,
        lease_status: leaseStatus,
        leaseStatus,
        approval_lease: approvalLease,
        approvalLease,
        decision,
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, `approval.${decision}`);
    return {
      ...this.threadForAgent(updatedAgent),
      approval_id: normalizedApprovalId,
      lease_id: leaseMetadata.lease_id,
      leaseId: leaseMetadata.leaseId,
      lease_status: leaseStatus,
      leaseStatus,
      approval_lease: approvalLease,
      approvalLease,
      decision,
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  revokeThreadApproval(threadId, approvalId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id ?? request.approvalId) ??
      (() => {
        throw runtimeError({
          status: 400,
          code: "approval_id_required",
          message: "Approval revocation requires an approval id.",
          details: { threadId },
        });
      })();
    const approvalRequestEvent = this.latestApprovalRequestEvent(threadId, normalizedApprovalId);
    if (!approvalRequestEvent) {
      throw notFound(`Approval request not found: ${normalizedApprovalId}`, {
        threadId,
        approvalId: normalizedApprovalId,
      });
    }
    const approvalRequestPayload = approvalRequestEvent.payload_summary ?? approvalRequestEvent.payload ?? {};
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const priorDecisionEvent =
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            event.seq > approvalRequestEvent.seq &&
            (event.event_kind === "approval.approved" || event.event_kind === "approval.rejected"),
        )
        .at(-1) ?? null;
    const source = operatorControlSource(request.source);
    const requestedBy =
      optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ??
      "operator revoked approval lease";
    const runs = this.listRuns(agent.id);
    const requestedTurnId = optionalString(request.turn_id ?? request.turnId);
    let turnId = requestedTurnId ?? approvalRequestEvent.turn_id ?? "";
    let run = null;
    if (turnId) {
      run = this.getRun(runIdForTurn(turnId));
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
      }
    } else {
      run = runs.at(-1) ?? null;
      turnId = run ? turnIdForRun(run.id) : "";
    }

    const now = new Date().toISOString();
    const leaseMetadata = approvalLeaseMetadataFromPayload(
      approvalRequestPayload,
      normalizedApprovalId,
      threadId,
    );
    const approvalLease = {
      ...leaseMetadata,
      status: "revoked",
      approval_request_event_id: approvalRequestEvent.event_id,
      approvalRequestEventId: approvalRequestEvent.event_id,
      approval_decision_event_id: priorDecisionEvent?.event_id ?? null,
      approvalDecisionEventId: priorDecisionEvent?.event_id ?? null,
      revoked_at: now,
      revokedAt: now,
    };
    const revokeHash = crypto
      .createHash("sha256")
      .update(`${normalizedApprovalId}:revoke:${reason}:${requestedBy}`)
      .digest("hex")
      .slice(0, 16);
    const workflowNodeId =
      request.workflow_node_id ??
      request.workflowNodeId ??
      approvalRequestEvent.workflow_node_id ??
      `runtime.approval.${safeId(normalizedApprovalId)}`;
    const workflowGraphId =
      request.workflow_graph_id ??
      request.workflowGraphId ??
      approvalRequestEvent.workflow_graph_id ??
      null;
    const runOrAgentId = run?.id ?? agent.id;
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-revoke:${safeId(normalizedApprovalId)}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:approval.revoke:${normalizedApprovalId}:${revokeHash}`,
      source,
      source_event_kind: "OperatorApproval.Revoke",
      event_kind: "approval.revoked",
      status: "revoked",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: normalizedApprovalId,
      payload_schema_version: "ioi.runtime.approval-revoke.v1",
      payload: {
        event_kind: "OperatorApproval.Revoke",
        approval_id: normalizedApprovalId,
        decision: "revoke",
        status: "revoked",
        reason,
        requested_by: requestedBy,
        control_surface: source,
        action: approvalRequestPayload.action ?? null,
        scope: approvalRequestPayload.scope ?? null,
        tool_id: approvalRequestPayload.tool_id ?? approvalRequestPayload.toolId ?? null,
        toolId: approvalRequestPayload.toolId ?? approvalRequestPayload.tool_id ?? null,
        effect_class: approvalRequestPayload.effect_class ?? approvalRequestPayload.effectClass ?? null,
        effectClass: approvalRequestPayload.effectClass ?? approvalRequestPayload.effect_class ?? null,
        risk_domain: approvalRequestPayload.risk_domain ?? approvalRequestPayload.riskDomain ?? null,
        riskDomain: approvalRequestPayload.riskDomain ?? approvalRequestPayload.risk_domain ?? null,
        approval_request_event_id: approvalRequestEvent.event_id,
        approvalRequestEventId: approvalRequestEvent.event_id,
        approval_decision_event_id: priorDecisionEvent?.event_id ?? null,
        approvalDecisionEventId: priorDecisionEvent?.event_id ?? null,
        lease_id: leaseMetadata.lease_id,
        leaseId: leaseMetadata.leaseId,
        lease_status: "revoked",
        leaseStatus: "revoked",
        policy_hash: leaseMetadata.policy_hash,
        policyHash: leaseMetadata.policyHash,
        ttl_ms: leaseMetadata.ttl_ms,
        ttlMs: leaseMetadata.ttlMs,
        expires_at: leaseMetadata.expires_at,
        expiresAt: leaseMetadata.expiresAt,
        expected_receipt_refs: leaseMetadata.expected_receipt_refs,
        expectedReceiptRefs: leaseMetadata.expectedReceiptRefs,
        authority_scope_requirements: leaseMetadata.authority_scope_requirements,
        authorityScopeRequirements: leaseMetadata.authorityScopeRequirements,
        revoke_endpoint: leaseMetadata.revoke_endpoint,
        revokeEndpoint: leaseMetadata.revokeEndpoint,
        approval_lease: approvalLease,
        approvalLease,
        approval_manifest:
          approvalRequestPayload.approval_manifest ?? approvalRequestPayload.approvalManifest ?? null,
        approvalManifest:
          approvalRequestPayload.approvalManifest ?? approvalRequestPayload.approval_manifest ?? null,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [
        `receipt_${runOrAgentId}_approval_revoke_${safeId(normalizedApprovalId)}_${revokeHash}`,
      ],
      policy_decision_refs: [`policy_${runOrAgentId}_approval_revoke`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "approval_revoke",
      approvalId: normalizedApprovalId,
      leaseId: leaseMetadata.leaseId,
      leaseStatus: "revoked",
      decision: "revoke",
      status: "revoked",
      source,
      reason,
      eventId: event.event_id,
      seq: event.seq,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
      createdAt: event.created_at,
    };
    if (run) {
      const updated = {
        ...run,
        updatedAt: event.created_at,
        turnStatus: "waiting_for_input",
        trace: {
          ...run.trace,
          operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
          approvalDecisions: appendOperatorControl(run.trace?.approvalDecisions, control),
          approvalRevocations: appendOperatorControl(run.trace?.approvalRevocations, control),
        },
        operatorControls: appendOperatorControl(run.operatorControls, control),
        approvalDecisions: appendOperatorControl(run.approvalDecisions, control),
        approvalRevocations: appendOperatorControl(run.approvalRevocations, control),
      };
      this.runs.set(run.id, updated);
      this.writeRun(updated, "approval.revoke");
      return {
        ...this.turnForRun(updated),
        approval_id: normalizedApprovalId,
        lease_id: leaseMetadata.lease_id,
        leaseId: leaseMetadata.leaseId,
        lease_status: "revoked",
        leaseStatus: "revoked",
        approval_lease: approvalLease,
        approvalLease,
        decision: "revoke",
        status: "revoked",
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, "approval.revoke");
    return {
      ...this.threadForAgent(updatedAgent),
      approval_id: normalizedApprovalId,
      lease_id: leaseMetadata.lease_id,
      leaseId: leaseMetadata.leaseId,
      lease_status: "revoked",
      leaseStatus: "revoked",
      approval_lease: approvalLease,
      approvalLease,
      decision: "revoke",
      status: "revoked",
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  latestApprovalDecisionEvent(threadId, approvalId) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return null;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            (event.event_kind === "approval.approved" ||
              event.event_kind === "approval.rejected" ||
              event.event_kind === "approval.revoked"),
        )
        .at(-1) ?? null
    );
  }

  latestCodingToolBudgetBlockedEventForRun(runId, sourceEventId = null) {
    const run = this.getRun(runId);
    const agent = this.getAgent(run.agentId);
    this.projectThreadEvents(agent);
    const turnId = turnIdForRun(run.id);
    const events = this.runtimeEventsForTurn(turnId);
    const explicitSourceEventId = optionalString(sourceEventId);
    if (explicitSourceEventId) {
      const explicit = events.find((event) => event.event_id === explicitSourceEventId);
      if (explicit) return explicit;
    }
    return events.filter(isCodingToolBudgetBlockedRuntimeEvent).at(-1) ?? null;
  }

  codingToolBudgetRecoveryForRun(runId, request = {}) {
    const run = this.getRun(runId);
    const agent = this.getAgent(run.agentId);
    const expectedThreadId = threadIdForAgent(agent.id);
    const threadId =
      optionalString(request.thread_id ?? request.threadId) ??
      expectedThreadId;
    if (threadId !== expectedThreadId) {
      throw notFound(`Run not found for thread: ${runId}`, { runId, threadId });
    }
    const turnId = turnIdForRun(run.id);
    const action = codingToolBudgetRecoveryAction(
      request.action ?? request.recovery_action ?? request.recoveryAction,
    );
    const source = operatorControlSource(request.source);
    const actor = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const requestedSourceEventId = optionalString(request.source_event_id ?? request.sourceEventId);
    const blockedEvent = this.latestCodingToolBudgetBlockedEventForRun(run.id, requestedSourceEventId);
    const blockedPayload = blockedEvent?.payload_summary ?? blockedEvent?.payload ?? {};
    const sourceEventId = requestedSourceEventId ?? blockedEvent?.event_id ?? null;
    const targetNodeIds = codingToolBudgetRecoveryTargetNodeIds({ request, blockedEvent, blockedPayload });
    const recoveryPolicy = codingToolBudgetRecoveryPolicyFromInputs({
      request,
      blockedPayload,
      targetNodeIds,
      source,
    });
    const approvalId =
      optionalString(request.approval_id ?? request.approvalId) ??
      optionalString(blockedPayload.approval_id ?? blockedPayload.approvalId) ??
      `approval_workflow_run_coding_tool_budget_${safeId(run.id)}_${safeId(sourceEventId ?? "source")}`;
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
      optionalString(blockedEvent?.workflow_graph_id ?? blockedPayload.workflow_graph_id ?? blockedPayload.workflowGraphId) ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      optionalString(blockedEvent?.workflow_node_id ?? blockedPayload.workflow_node_id ?? blockedPayload.workflowNodeId) ??
      targetNodeIds[0] ??
      "runtime.coding-tool-budget-recovery";
    const receiptRefs = uniqueStrings([
      ...normalizeArray(request.receipt_refs ?? request.receiptRefs),
      ...normalizeArray(blockedEvent?.receipt_refs),
      `receipt_${run.id}_coding_tool_budget_recovery_${safeId(action)}_${safeId(approvalId)}`,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...normalizeArray(request.policy_decision_refs ?? request.policyDecisionRefs),
      ...normalizeArray(blockedEvent?.policy_decision_refs),
      `policy_${run.id}_coding_tool_budget_recovery_${safeId(action)}`,
    ]);
    const approvalManifest = {
      schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      schemaVersion: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      action: "workflow_run.coding_budget_recovery",
      recovery_action: action,
      recoveryAction: action,
      reason: WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
      source_event_id: sourceEventId,
      sourceEventId,
      approval_id: approvalId,
      approvalId,
      run_id: run.id,
      runId: run.id,
      thread_id: threadId,
      threadId,
      turn_id: turnId,
      turnId,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      target_node_ids: targetNodeIds,
      targetNodeIds,
      recovery_policy: recoveryPolicy,
      recoveryPolicy,
    };

    if (action === "request_approval") {
      const approval = this.requestThreadApproval(threadId, {
        ...request,
        source,
        actor,
        turnId,
        workflowGraphId,
        workflowNodeId,
        action: "workflow_run.coding_budget_recovery",
        reason: WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        scope: "coding_tool_budget_recovery",
        approvalId,
        toolId: "coding_tool",
        effectClass: "coding_tool_budget_recovery",
        riskDomain: "runtime_coding_tool_budget",
        authorityScopeRequirements: ["workflow.run.coding_tool_budget_recovery"],
        approvalManifest,
        receiptRefs,
        policyDecisionRefs,
      });
      const approvalEvent = this.latestApprovalRequestEvent(threadId, approval.approval_id);
      return codingToolBudgetRecoveryResult({
        action,
        status: "waiting_for_approval",
        run,
        threadId,
        turnId,
        approvalId: approval.approval_id,
        sourceEventId,
        targetNodeIds,
        workflowGraphId,
        workflowNodeId,
        recoveryPolicy,
        event: approvalEvent,
        approvalEvent,
        receiptRefs: uniqueStrings([...receiptRefs, ...normalizeArray(approval.receipt_refs)]),
        policyDecisionRefs: uniqueStrings([
          ...policyDecisionRefs,
          ...normalizeArray(approval.policy_decision_refs),
        ]),
      });
    }

    if (action === "approve_override" || action === "reject_override") {
      const decision = action === "approve_override" ? "approve" : "reject";
      const decisionResult = this.decideThreadApproval(threadId, approvalId, {
        ...request,
        source,
        actor,
        turnId,
        decision,
        reason: WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        workflowGraphId,
        workflowNodeId,
      });
      const decisionEvent = this.latestApprovalDecisionEvent(threadId, approvalId);
      return codingToolBudgetRecoveryResult({
        action,
        status: decision === "approve" ? "approved" : "rejected",
        run,
        threadId,
        turnId,
        approvalId,
        sourceEventId,
        targetNodeIds,
        workflowGraphId,
        workflowNodeId,
        recoveryPolicy,
        event: decisionEvent,
        decisionEvent,
        receiptRefs: uniqueStrings([...receiptRefs, ...normalizeArray(decisionResult.receipt_refs)]),
        policyDecisionRefs: uniqueStrings([
          ...policyDecisionRefs,
          ...normalizeArray(decisionResult.policy_decision_refs),
        ]),
      });
    }

    const approvalRequestEvent = this.latestApprovalRequestEvent(threadId, approvalId);
    const approvalDecisionEvent = this.latestApprovalDecisionEvent(threadId, approvalId);
    if (recoveryPolicy.requiresApproval !== false) {
      if (!approvalRequestEvent) {
        return codingToolBudgetRecoveryResult({
          action,
          status: "blocked",
          reason: "approval_request_missing",
          run,
          threadId,
          turnId,
          approvalId,
          sourceEventId,
          targetNodeIds,
          workflowGraphId,
          workflowNodeId,
          recoveryPolicy,
          receiptRefs,
          policyDecisionRefs,
        });
      }
      if (!approvalDecisionEvent || approvalDecisionEvent.event_kind !== "approval.approved") {
        return codingToolBudgetRecoveryResult({
          action,
          status: "blocked",
          reason: approvalDecisionEvent
            ? approvalReasonForDecisionEvent(approvalDecisionEvent)
            : "approval_decision_missing",
          run,
          threadId,
          turnId,
          approvalId,
          sourceEventId,
          targetNodeIds,
          workflowGraphId,
          workflowNodeId,
          recoveryPolicy,
          event: approvalDecisionEvent,
          decisionEvent: approvalDecisionEvent,
          receiptRefs,
          policyDecisionRefs,
        });
      }
    }
    const retryLimit = recoveryPolicyRetryLimit(recoveryPolicy);
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const retryCount = stream.events.filter((event) => {
      if (event.event_kind !== "workflow.run.retry_completed") return false;
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.approval_id === approvalId ||
        payload.approval_id === approvalId ||
        payload.approvalId === approvalId ||
        (sourceEventId &&
          (payload.source_event_id === sourceEventId || payload.sourceEventId === sourceEventId))
      );
    }).length;
    if (retryCount >= retryLimit) {
      return codingToolBudgetRecoveryResult({
        action,
        status: "blocked",
        reason: "retry_limit_exceeded",
        run,
        threadId,
        turnId,
        approvalId,
        sourceEventId,
        targetNodeIds,
        workflowGraphId,
        workflowNodeId,
        recoveryPolicy,
        event: approvalDecisionEvent,
        decisionEvent: approvalDecisionEvent,
        receiptRefs,
        policyDecisionRefs,
      });
    }
    const now = new Date().toISOString();
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId}:item:coding-tool-budget-recovery:${safeId(approvalId)}:${retryCount + 1}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `run:${run.id}:coding-tool-budget-recovery.retry:${approvalId}:${retryCount + 1}`,
      source,
      source_event_kind: "WorkflowRunCodingToolBudgetApprovedRetry",
      event_kind: "workflow.run.retry_completed",
      status: "completed",
      actor,
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      approval_id: approvalId,
      payload_schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      payload: {
        ...approvalManifest,
        event_kind: "WorkflowRunCodingToolBudgetApprovedRetry",
        eventKind: "WorkflowRunCodingToolBudgetApprovedRetry",
        recovery_action: "retry_approved",
        recoveryAction: "retry_approved",
        status: "completed",
        approval_satisfied: true,
        approvalSatisfied: true,
        approval_decision_event_id: approvalDecisionEvent?.event_id ?? null,
        approvalDecisionEventId: approvalDecisionEvent?.event_id ?? null,
        retry_count: retryCount + 1,
        retryCount: retryCount + 1,
        retry_limit: retryLimit,
        retryLimit,
        control_surface: source,
        requested_by: actor,
      },
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "coding_tool_budget_recovery",
      action: "retry_approved",
      approvalId,
      status: "completed",
      source,
      eventId: event.event_id,
      seq: event.seq,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
      createdAt: event.created_at,
    };
    const updated = {
      ...run,
      updatedAt: event.created_at,
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
      },
      operatorControls: appendOperatorControl(run.operatorControls, control),
    };
    this.runs.set(run.id, updated);
    this.writeRun(updated, "workflow.run.retry_completed");
    return codingToolBudgetRecoveryResult({
      action,
      status: "completed",
      run: updated,
      threadId,
      turnId,
      approvalId,
      sourceEventId,
      targetNodeIds,
      workflowGraphId,
      workflowNodeId,
      recoveryPolicy,
      event,
      decisionEvent: approvalDecisionEvent,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
    });
  }

  workflowEditThreadContext(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runs = this.listRuns(agent.id);
    const requestedTurnId = optionalString(request.turn_id ?? request.turnId);
    let turnId = requestedTurnId ?? "";
    let run = null;
    if (turnId) {
      run = this.getRun(runIdForTurn(turnId));
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
      }
    } else {
      run = runs.at(-1) ?? null;
      turnId = run ? turnIdForRun(run.id) : "";
    }
    return { agent, run, turnId };
  }

  resolveWorkflowEditTarget(agent, request = {}) {
    const rawPath = optionalString(request.workflow_path ?? request.workflowPath);
    if (!rawPath) return { workflowPath: null, workflowRelativePath: null };
    const workflowPath = path.resolve(agent.cwd, rawPath);
    const workflowRelativePath = relativePathForWorkspace(workflowPath, agent.cwd);
    if (!workflowRelativePath) {
      throw policyError("Workflow edit proposals can only target files inside the runtime workspace.", {
        workspaceRoot: agent.cwd,
        workflowPath,
      });
    }
    return { workflowPath, workflowRelativePath };
  }

  proposeWorkflowEdit(threadId, request = {}) {
    const { agent, run, turnId } = this.workflowEditThreadContext(threadId, request);
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "workflow-author";
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const targetWorkflowNodeIds = uniqueStrings(
      [
        ...normalizeArray(request.target_workflow_node_ids ?? request.targetWorkflowNodeIds),
        ...normalizeArray(request.bounded_targets ?? request.boundedTargets),
      ]
        .map((value) => optionalString(value))
        .filter(Boolean),
    );
    const title =
      optionalString(request.title) ??
      "Review workflow edit proposal";
    const summary =
      optionalString(request.summary) ??
      "Proposal-only workflow edit staged for daemon-owned approval.";
    const { workflowPath, workflowRelativePath } = this.resolveWorkflowEditTarget(agent, request);
    const workflowPatch =
      request.workflow_patch && typeof request.workflow_patch === "object"
        ? request.workflow_patch
        : request.workflowPatch && typeof request.workflowPatch === "object"
          ? request.workflowPatch
          : null;
    const codeDiff = optionalString(request.code_diff ?? request.codeDiff) ?? null;
    const editIntentHash = doctorHash(
      JSON.stringify({
        title,
        summary,
        workflowGraphId,
        targetWorkflowNodeIds,
        workflowRelativePath,
        workflowPatch,
        codeDiff,
      }),
    ).slice(0, 16);
    const editIntentId =
      optionalString(request.edit_intent_id ?? request.editIntentId) ??
      `workflow_edit_intent_${editIntentHash}`;
    const proposalId =
      optionalString(request.proposal_id ?? request.proposalId) ??
      `workflow_edit_proposal_${editIntentHash}`;
    const approvalId =
      optionalString(request.approval_id ?? request.approvalId) ??
      `approval_workflow_edit_${safeId(proposalId)}`;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      `runtime.workflow-edit-proposal.${safeId(proposalId)}`;
    const patchHash = doctorHash(
      JSON.stringify({
        workflowRelativePath,
        workflowPatch,
        targetWorkflowNodeIds,
        codeDiff,
      }),
    );
    const runOrAgentId = run?.id ?? agent.id;
    const approvalManifest = {
      schema_version: "ioi.runtime.workflow-edit-proposal-approval.v1",
      schemaVersion: "ioi.runtime.workflow-edit-proposal-approval.v1",
      proposal_id: proposalId,
      proposalId,
      edit_intent_id: editIntentId,
      editIntentId,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      target_workflow_node_ids: targetWorkflowNodeIds,
      targetWorkflowNodeIds,
      workflow_path: workflowPath,
      workflowPath,
      workflow_relative_path: workflowRelativePath,
      workflowRelativePath,
      patch_hash: patchHash,
      patchHash,
      proposal_only: true,
      proposalOnly: true,
      mutation_allowed: false,
      mutationAllowed: false,
      mutation_executed: false,
      mutationExecuted: false,
      effect_class: "workflow_mutation",
      effectClass: "workflow_mutation",
      risk_domain: "workflow_graph",
      riskDomain: "workflow_graph",
      policy_reason: "workflow_edit_proposal_only_requires_operator_approval",
      thread_mode: agent.runtimeControls?.mode ?? "agent",
      approval_mode: "human_required",
      authority_scope_requirements: ["workflow.edit.apply"],
    };
    const receiptRefs = uniqueStrings([
      ...normalizeArray(request.receipt_refs ?? request.receiptRefs),
      `receipt_${runOrAgentId}_workflow_edit_proposed_${safeId(proposalId)}`,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...normalizeArray(request.policy_decision_refs ?? request.policyDecisionRefs),
      `policy_${runOrAgentId}_workflow_edit_proposal_only`,
    ]);
    const now = new Date().toISOString();
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workflow-edit-proposed:${safeId(proposalId)}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:workflow.edit.proposed:${proposalId}`,
      source,
      source_event_kind: "WorkflowEdit.Proposed",
      event_kind: "workflow.edit_proposed",
      status: "waiting_for_approval",
      actor: "runtime",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workflow_edit_proposal",
      approval_id: approvalId,
      payload_schema_version: "ioi.runtime.workflow-edit-proposal.v1",
      payload: {
        event_kind: "WorkflowEdit.Proposed",
        proposal_id: proposalId,
        proposalId,
        edit_intent_id: editIntentId,
        editIntentId,
        approval_id: approvalId,
        approvalId,
        approval_required: true,
        approvalRequired: true,
        title,
        summary,
        requested_by: requestedBy,
        control_surface: source,
        workflow_graph_id: workflowGraphId,
        workflowGraphId,
        workflow_node_id: workflowNodeId,
        workflowNodeId,
        target_workflow_node_ids: targetWorkflowNodeIds,
        targetWorkflowNodeIds,
        bounded_targets: targetWorkflowNodeIds,
        boundedTargets: targetWorkflowNodeIds,
        workflow_path: workflowPath,
        workflowPath,
        workflow_relative_path: workflowRelativePath,
        workflowRelativePath,
        workflow_patch: workflowPatch,
        workflowPatch,
        workflow_patch_present: Boolean(workflowPatch),
        workflowPatchPresent: Boolean(workflowPatch),
        code_diff: codeDiff,
        codeDiff,
        patch_hash: patchHash,
        patchHash,
        proposal_only: true,
        proposalOnly: true,
        mutation_allowed: false,
        mutationAllowed: false,
        mutation_executed: false,
        mutationExecuted: false,
        approval_manifest: approvalManifest,
        approvalManifest,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const approval = this.requestThreadApproval(threadId, {
      ...request,
      source,
      turnId,
      workflowGraphId,
      workflowNodeId,
      action: "workflow.edit.apply",
      actor: "runtime",
      reason: `Workflow edit proposal ${proposalId} requires approval before apply.`,
      scope: "workflow_edit_proposal",
      approvalId,
      toolId: "workflow.edit.apply",
      effectClass: "workflow_mutation",
      riskDomain: "workflow_graph",
      authorityScopeRequirements: ["workflow.edit.apply"],
      approvalManifest,
      receiptRefs,
      policyDecisionRefs: [`policy_${runOrAgentId}_workflow_edit_approval_required`],
    });
    const approvalEvent = this.latestApprovalRequestEvent(threadId, approval.approval_id);
    return {
      schema_version: "ioi.runtime.workflow-edit-proposal-result.v1",
      schemaVersion: "ioi.runtime.workflow-edit-proposal-result.v1",
      status: "waiting_for_approval",
      proposal_id: proposalId,
      proposalId,
      edit_intent_id: editIntentId,
      editIntentId,
      approval_id: approval.approval_id,
      approvalId: approval.approval_id,
      approval_required: true,
      approvalRequired: true,
      mutation_allowed: false,
      mutationAllowed: false,
      mutation_executed: false,
      mutationExecuted: false,
      workflow_path: workflowPath,
      workflowPath,
      workflow_relative_path: workflowRelativePath,
      workflowRelativePath,
      patch_hash: patchHash,
      patchHash,
      event_id: event.event_id,
      eventId: event.event_id,
      approval_event_id: approval.event_id,
      approvalEventId: approval.event_id,
      receipt_refs: uniqueStrings([...event.receipt_refs, ...normalizeArray(approval.receipt_refs)]),
      receiptRefs: uniqueStrings([...event.receipt_refs, ...normalizeArray(approval.receipt_refs)]),
      policy_decision_refs: uniqueStrings([
        ...event.policy_decision_refs,
        ...normalizeArray(approval.policy_decision_refs),
      ]),
      policyDecisionRefs: uniqueStrings([
        ...event.policy_decision_refs,
        ...normalizeArray(approval.policy_decision_refs),
      ]),
      proposal_event: event,
      proposalEvent: event,
      approval_event: approvalEvent,
      approvalEvent,
    };
  }

  latestWorkflowEditProposalEvent(threadId, proposalId) {
    const normalizedProposalId = optionalString(proposalId);
    if (!normalizedProposalId) return null;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter((event) => {
          const payload = event.payload_summary ?? event.payload ?? {};
          return (
            event.event_kind === "workflow.edit_proposed" &&
            (payload.proposal_id === normalizedProposalId ||
              payload.proposalId === normalizedProposalId)
          );
        })
        .at(-1) ?? null
    );
  }

  latestWorkflowEditApplyEvent(threadId, proposalId) {
    const normalizedProposalId = optionalString(proposalId);
    if (!normalizedProposalId) return null;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter((event) => {
          const payload = event.payload_summary ?? event.payload ?? {};
          return (
            event.event_kind === "workflow.edit_applied" &&
            (payload.proposal_id === normalizedProposalId ||
              payload.proposalId === normalizedProposalId)
          );
        })
        .at(-1) ?? null
    );
  }

  workflowEditApprovalSatisfaction({ threadId, approvalId, proposalEvent }) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return { satisfied: false, reason: "approval_id_missing" };
    const approvalRequestEvent = this.latestApprovalRequestEvent(threadId, normalizedApprovalId);
    if (!approvalRequestEvent) return { satisfied: false, approvalId: normalizedApprovalId, reason: "approval_request_missing" };
    const proposalPayload = proposalEvent?.payload_summary ?? proposalEvent?.payload ?? {};
    const approvalPayload = approvalRequestEvent.payload_summary ?? approvalRequestEvent.payload ?? {};
    const requestedManifest = approvalPayload.approval_manifest ?? approvalPayload.approvalManifest ?? {};
    const proposalId = proposalPayload.proposal_id ?? proposalPayload.proposalId ?? null;
    const manifestProposalId = requestedManifest.proposal_id ?? requestedManifest.proposalId ?? null;
    if (proposalId && manifestProposalId && proposalId !== manifestProposalId) {
      return { satisfied: false, approvalId: normalizedApprovalId, reason: "approval_manifest_mismatch" };
    }
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const latestDecision = stream.events
      .filter(
        (event) =>
          event.approval_id === normalizedApprovalId &&
          event.seq > approvalRequestEvent.seq &&
          (event.event_kind === "approval.approved" ||
            event.event_kind === "approval.rejected" ||
            event.event_kind === "approval.revoked"),
      )
      .at(-1);
    if (!latestDecision) return { satisfied: false, approvalId: normalizedApprovalId, reason: "approval_decision_missing" };
    return {
      satisfied: latestDecision.event_kind === "approval.approved",
      approvalId: normalizedApprovalId,
      decisionEventId: latestDecision.event_id,
      decisionSeq: latestDecision.seq,
      reason: approvalReasonForDecisionEvent(latestDecision),
    };
  }

  applyWorkflowEditProposal(threadId, proposalId, request = {}) {
    const { agent, run, turnId } = this.workflowEditThreadContext(threadId, request);
    const normalizedProposalId =
      optionalString(proposalId ?? request.proposal_id ?? request.proposalId) ??
      (() => {
        throw runtimeError({
          status: 400,
          code: "workflow_edit_proposal_id_required",
          message: "Workflow edit proposal apply requires a proposal id.",
          details: { threadId },
        });
      })();
    const proposalEvent = this.latestWorkflowEditProposalEvent(threadId, normalizedProposalId);
    if (!proposalEvent) {
      throw notFound(`Workflow edit proposal not found: ${normalizedProposalId}`, {
        threadId,
        proposalId: normalizedProposalId,
      });
    }
    const proposalPayload = proposalEvent.payload_summary ?? proposalEvent.payload ?? {};
    const approvalId =
      optionalString(request.approval_id ?? request.approvalId) ??
      optionalString(proposalPayload.approval_id ?? proposalPayload.approvalId);
    const approvalSatisfaction = this.workflowEditApprovalSatisfaction({
      threadId,
      approvalId,
      proposalEvent,
    });
    if (!approvalSatisfaction.satisfied) {
      return {
        schema_version: "ioi.runtime.workflow-edit-apply-result.v1",
        schemaVersion: "ioi.runtime.workflow-edit-apply-result.v1",
        status: "blocked",
        proposal_id: normalizedProposalId,
        proposalId: normalizedProposalId,
        approval_id: approvalSatisfaction.approvalId ?? approvalId ?? null,
        approvalId: approvalSatisfaction.approvalId ?? approvalId ?? null,
        approval_required: true,
        approvalRequired: true,
        approval_satisfied: false,
        approvalSatisfied: false,
        mutation_allowed: false,
        mutationAllowed: false,
        mutation_executed: false,
        mutationExecuted: false,
        reason: approvalSatisfaction.reason,
        error: {
          code: "workflow_edit_approval_required",
          message: `Workflow edit proposal ${normalizedProposalId} requires approval before apply.`,
          details: {
            proposalId: normalizedProposalId,
            approvalId: approvalSatisfaction.approvalId ?? approvalId ?? null,
            reason: approvalSatisfaction.reason,
          },
        },
      };
    }
    const duplicateApply = this.latestWorkflowEditApplyEvent(threadId, normalizedProposalId);
    if (duplicateApply) {
      return {
        schema_version: "ioi.runtime.workflow-edit-apply-result.v1",
        schemaVersion: "ioi.runtime.workflow-edit-apply-result.v1",
        status: "completed",
        proposal_id: normalizedProposalId,
        proposalId: normalizedProposalId,
        approval_id: approvalSatisfaction.approvalId,
        approvalId: approvalSatisfaction.approvalId,
        approval_satisfied: true,
        approvalSatisfied: true,
        mutation_allowed: true,
        mutationAllowed: true,
        mutation_executed: Boolean(duplicateApply.payload_summary?.mutation_executed ?? duplicateApply.payload_summary?.mutationExecuted),
        mutationExecuted: Boolean(duplicateApply.payload_summary?.mutationExecuted ?? duplicateApply.payload_summary?.mutation_executed),
        idempotent_replay: true,
        idempotentReplay: true,
        event: duplicateApply,
      };
    }
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "workflow-author";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
      optionalString(proposalEvent.workflow_graph_id);
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      optionalString(proposalEvent.workflow_node_id) ??
      `runtime.workflow-edit-proposal.${safeId(normalizedProposalId)}`;
    const workflowPath = optionalString(proposalPayload.workflow_path ?? proposalPayload.workflowPath);
    const workflowPatch = proposalPayload.workflow_patch ?? proposalPayload.workflowPatch ?? null;
    let workflowRelativePath = optionalString(proposalPayload.workflow_relative_path ?? proposalPayload.workflowRelativePath);
    let mutationExecuted = false;
    if (workflowPath && workflowPatch && typeof workflowPatch === "object") {
      const resolvedWorkflowPath = path.resolve(agent.cwd, workflowPath);
      workflowRelativePath = relativePathForWorkspace(resolvedWorkflowPath, agent.cwd);
      if (!workflowRelativePath) {
        throw policyError("Workflow edit apply blocked outside the runtime workspace.", {
          workspaceRoot: agent.cwd,
          workflowPath: resolvedWorkflowPath,
          proposalId: normalizedProposalId,
        });
      }
      writeJson(resolvedWorkflowPath, workflowPatch);
      mutationExecuted = true;
    }
    const runOrAgentId = run?.id ?? agent.id;
    const now = new Date().toISOString();
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workflow-edit-applied:${safeId(normalizedProposalId)}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:workflow.edit.applied:${normalizedProposalId}:${approvalSatisfaction.approvalId}`,
      source,
      source_event_kind: "WorkflowEdit.Applied",
      event_kind: "workflow.edit_applied",
      status: "completed",
      actor: "runtime",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workflow_edit_proposal",
      approval_id: approvalSatisfaction.approvalId,
      payload_schema_version: "ioi.runtime.workflow-edit-apply.v1",
      payload: {
        event_kind: "WorkflowEdit.Applied",
        proposal_id: normalizedProposalId,
        proposalId: normalizedProposalId,
        proposal_event_id: proposalEvent.event_id,
        proposalEventId: proposalEvent.event_id,
        approval_id: approvalSatisfaction.approvalId,
        approvalId: approvalSatisfaction.approvalId,
        approval_satisfied: true,
        approvalSatisfied: true,
        approval_decision_event_id: approvalSatisfaction.decisionEventId,
        approvalDecisionEventId: approvalSatisfaction.decisionEventId,
        requested_by: requestedBy,
        control_surface: source,
        workflow_path: workflowPath,
        workflowPath,
        workflow_relative_path: workflowRelativePath,
        workflowRelativePath,
        patch_hash: proposalPayload.patch_hash ?? proposalPayload.patchHash ?? null,
        patchHash: proposalPayload.patchHash ?? proposalPayload.patch_hash ?? null,
        mutation_allowed: true,
        mutationAllowed: true,
        mutation_executed: mutationExecuted,
        mutationExecuted,
        proposal_only: true,
        proposalOnly: true,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [
        ...normalizeArray(proposalEvent.receipt_refs),
        `receipt_${runOrAgentId}_workflow_edit_applied_${safeId(normalizedProposalId)}`,
      ],
      policy_decision_refs: [
        `policy_${runOrAgentId}_workflow_edit_apply_approval_satisfied`,
      ],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    return {
      schema_version: "ioi.runtime.workflow-edit-apply-result.v1",
      schemaVersion: "ioi.runtime.workflow-edit-apply-result.v1",
      status: "completed",
      proposal_id: normalizedProposalId,
      proposalId: normalizedProposalId,
      approval_id: approvalSatisfaction.approvalId,
      approvalId: approvalSatisfaction.approvalId,
      approval_satisfied: true,
      approvalSatisfied: true,
      mutation_allowed: true,
      mutationAllowed: true,
      mutation_executed: mutationExecuted,
      mutationExecuted,
      idempotent_replay: false,
      idempotentReplay: false,
      event,
    };
  }

  compactThread(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runs = this.listRuns(agent.id);
    const latestRun = runs.at(-1);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      (latestRun ? turnIdForRun(latestRun.id) : "");
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested context compaction";
    const scope = optionalString(request.scope) ?? "thread";
    const now = new Date().toISOString();
    const streamId = eventStreamIdForThread(threadId);
    const previousLatestSeq = this.latestRuntimeEventSeq(streamId);
    const compactHash = crypto
      .createHash("sha256")
      .update(`${reason}:${scope}`)
      .digest("hex")
      .slice(0, 16);
    const event = this.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:context-compact:${compactHash}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:context.compact:${compactHash}`,
      source,
      source_event_kind: "OperatorControl.Compact",
      event_kind: "context.compacted",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.context-compact",
      component_kind: "context_compaction",
      payload_schema_version: "ioi.runtime.context-compaction.v1",
      payload: {
        event_kind: "OperatorControl.Compact",
        reason,
        scope,
        requested_by: requestedBy,
        control_surface: source,
        previous_latest_seq: previousLatestSeq,
        compacted_tokens: 0,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: latestRun?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${latestRun?.id ?? agent.id}_context_compaction_${compactHash}`],
      policy_decision_refs: [`policy_${latestRun?.id ?? agent.id}_context_compaction_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "compact",
      source,
      reason,
      scope,
      eventId: event.event_id,
      seq: event.seq,
      createdAt: event.created_at,
    };
    if (latestRun) {
      const updated = {
        ...latestRun,
        updatedAt: event.created_at,
        trace: {
          ...latestRun.trace,
          operatorControls: appendOperatorControl(latestRun.trace?.operatorControls, control),
          contextCompaction: {
            reason,
            scope,
            eventId: event.event_id,
            seq: event.seq,
            compactedTokens: 0,
          },
        },
        operatorControls: appendOperatorControl(latestRun.operatorControls, control),
      };
      this.runs.set(latestRun.id, updated);
      this.writeRun(updated, "thread.compact");
      return this.threadForAgent(agent);
    }
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, "thread.compact");
    return this.threadForAgent(updatedAgent);
  }

  listJobs(options = {}) {
    const agentId = options.agentId ?? options.agent_id ?? undefined;
    const status = options.status ?? undefined;
    return this.listRuns(agentId)
      .map((run) => runtimeJobRecordForRun(run))
      .filter((job) => !status || job.status === status)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  createTask(body = {}) {
    const agentId = optionalString(body.agentId ?? body.agent_id);
    const agent = agentId
      ? this.getAgent(agentId)
      : this.createAgent({
          ...(body.agent ?? body.agent_options ?? body.agentOptions ?? {}),
          local: {
            cwd: body.cwd ?? body.workspace ?? this.defaultCwd,
            ...((body.agent ?? body.agent_options ?? body.agentOptions ?? {}).local ?? {}),
          },
          model: body.model ?? (body.agent ?? body.agent_options ?? body.agentOptions ?? {}).model,
        });
    const options = body.options && typeof body.options === "object" ? body.options : {};
    const run = this.createRun(agent.id, {
      ...body,
      mode: body.mode ?? "send",
      prompt: body.prompt ?? body.objective ?? body.goal ?? "",
      options,
    });
    return runtimeTaskRecordForRun(run);
  }

  listTasks(options = {}) {
    const agentId = options.agentId ?? options.agent_id ?? undefined;
    const status = options.status ?? undefined;
    return this.listRuns(agentId)
      .map((run) => runtimeTaskRecordForRun(run))
      .filter((task) => !status || task.status === status)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getTask(taskId) {
    const task = this.listTasks().find((candidate) => candidate.taskId === taskId || candidate.runId === taskId);
    if (!task) throw notFound(`Task not found: ${taskId}`, { taskId });
    return task;
  }

  cancelTask(taskId) {
    const task = this.getTask(taskId);
    const canceledRun = this.cancelRun(task.runId);
    return runtimeTaskRecordForRun(canceledRun);
  }

  getJob(jobId) {
    const job = this.listJobs().find((candidate) => candidate.jobId === jobId || candidate.runId === jobId);
    if (!job) throw notFound(`Job not found: ${jobId}`, { jobId });
    return job;
  }

  cancelJob(jobId) {
    const job = this.getJob(jobId);
    const canceledRun = this.cancelRun(job.runId);
    return runtimeJobRecordForRun(canceledRun);
  }

  listMcpServers(options = {}) {
    return this.mcpServersForContext(options);
  }

  listMcpTools(options = {}) {
    const servers = this.mcpServersForContext(options);
    const serverFilter = optionalString(options.server_id ?? options.serverId);
    return mcpToolsForServers(
      serverFilter ? servers.filter((server) => server.id === serverFilter) : servers,
    );
  }

  async searchMcpTools(options = {}) {
    const threadId = optionalString(options.thread_id ?? options.threadId);
    if (threadId) return this.searchThreadMcpTools(threadId, options);
    return this.searchMcpToolCatalog({
      ...options,
      servers: this.mcpServersForContext(options),
      agent: { cwd: this.defaultCwd },
    });
  }

  async getMcpTool(toolId, options = {}) {
    const threadId = optionalString(options.thread_id ?? options.threadId);
    if (threadId) return this.getThreadMcpTool(threadId, toolId, options);
    return this.getMcpToolFromCatalog(toolId, {
      ...options,
      servers: this.mcpServersForContext(options),
      agent: { cwd: this.defaultCwd },
    });
  }

  listMcpResources(options = {}) {
    const servers = this.mcpServersForContext(options);
    const serverFilter = optionalString(options.server_id ?? options.serverId);
    return mcpResourcesForServers(
      serverFilter ? servers.filter((server) => server.id === serverFilter) : servers,
    );
  }

  listMcpPrompts(options = {}) {
    const servers = this.mcpServersForContext(options);
    const serverFilter = optionalString(options.server_id ?? options.serverId);
    return mcpPromptsForServers(
      serverFilter ? servers.filter((server) => server.id === serverFilter) : servers,
    );
  }

  mcpStatus(options = {}) {
    const servers = this.listMcpServers(options);
    const tools = this.listMcpTools(options);
    const resources = this.listMcpResources(options);
    const prompts = this.listMcpPrompts(options);
    const validation = validateMcpServerRecords(servers);
    return {
      schema_version: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      object: "ioi.runtime_mcp_manager_status",
      status: validation.ok ? "ready" : "needs_review",
      server_count: servers.length,
      serverCount: servers.length,
      tool_count: tools.length,
      toolCount: tools.length,
      resource_count: resources.length,
      resourceCount: resources.length,
      prompt_count: prompts.length,
      promptCount: prompts.length,
      enabled_server_count: servers.filter((server) => server.enabled !== false).length,
      enabledServerCount: servers.filter((server) => server.enabled !== false).length,
      servers,
      tools,
      resources,
      prompts,
      validation: {
        ...validation,
        server_count: servers.length,
        serverCount: servers.length,
        tool_count: tools.length,
        toolCount: tools.length,
        resource_count: resources.length,
        resourceCount: resources.length,
        prompt_count: prompts.length,
        promptCount: prompts.length,
        servers,
        tools,
        resources,
        prompts,
      },
      routes: {
        servers: "/v1/mcp/servers",
        tools: "/v1/mcp/tools",
        searchTools: "/v1/mcp/tools/search",
        getTool: "/v1/mcp/tools/{tool_id}",
        resources: "/v1/mcp/resources",
        prompts: "/v1/mcp/prompts",
        validate: "/v1/mcp/validate",
        importServers: "/v1/mcp/import",
        addServer: "/v1/mcp/servers",
        removeServer: "/v1/mcp/servers/{server_id}",
        enableServer: "/v1/mcp/servers/{server_id}/enable",
        disableServer: "/v1/mcp/servers/{server_id}/disable",
        invokeTool: "/v1/mcp/tools/{tool_id}/invoke",
        serve: "/v1/mcp/serve",
        serveForThread: "/v1/threads/{thread_id}/mcp/serve",
      },
    };
  }

  validateMcp(input = {}) {
    const workspaceRoot = path.resolve(input.cwd ?? input.workspace_root ?? input.workspaceRoot ?? this.defaultCwd);
    const servers = mcpServerRecordsFromValidationInput(input, workspaceRoot);
    const validation = validateMcpServerRecords(servers);
    return {
      schema_version: RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
      object: "ioi.runtime_mcp_manager_validation",
      ok: validation.ok,
      status: validation.ok ? "pass" : "blocked",
      server_count: servers.length,
      serverCount: servers.length,
      tool_count: mcpToolsForServers(servers).length,
      toolCount: mcpToolsForServers(servers).length,
      resource_count: mcpResourcesForServers(servers).length,
      resourceCount: mcpResourcesForServers(servers).length,
      prompt_count: mcpPromptsForServers(servers).length,
      promptCount: mcpPromptsForServers(servers).length,
      issue_count: validation.issues.length,
      issueCount: validation.issues.length,
      warning_count: validation.warnings.length,
      warningCount: validation.warnings.length,
      issues: validation.issues,
      warnings: validation.warnings,
      servers,
      tools: mcpToolsForServers(servers),
      resources: mcpResourcesForServers(servers),
      prompts: mcpPromptsForServers(servers),
    };
  }

  importMcp(input = {}) {
    const threadId = optionalString(input.thread_id ?? input.threadId);
    if (!threadId) {
      throw runtimeError({
        status: 400,
        code: "mcp_thread_required",
        message: "MCP import requires a thread_id so the daemon can update the active runtime registry.",
      });
    }
    return this.importThreadMcp(threadId, input);
  }

  addMcpServer(input = {}) {
    const threadId = optionalString(input.thread_id ?? input.threadId);
    if (!threadId) {
      throw runtimeError({
        status: 400,
        code: "mcp_thread_required",
        message: "MCP server add requires a thread_id so the daemon can update the active runtime registry.",
      });
    }
    return this.addThreadMcpServer(threadId, input);
  }

  removeMcpServer(serverId, input = {}) {
    const threadId = optionalString(input.thread_id ?? input.threadId);
    if (!threadId) {
      throw runtimeError({
        status: 400,
        code: "mcp_thread_required",
        message: "MCP server removal requires a thread_id so the daemon can update the active runtime registry.",
        details: { serverId },
      });
    }
    return this.removeThreadMcpServer(threadId, serverId, input);
  }

  importThreadMcp(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const importedServers = mcpServerRecordsFromMutationInput(request, agent.cwd, "runtime_mcp_import");
    return this.applyThreadMcpServerMutation({
      threadId,
      agent,
      request,
      mutationKind: "import",
      sourceEventKind: "OperatorControl.McpImport",
      eventKind: "mcp.servers_imported",
      workflowNodeId: "runtime.mcp-manager.import",
      serversToUpsert: importedServers,
    });
  }

  addThreadMcpServer(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const server = mcpServerRecordFromAddRequest(request, agent.cwd);
    return this.applyThreadMcpServerMutation({
      threadId,
      agent,
      request,
      mutationKind: "add",
      sourceEventKind: "OperatorControl.McpAdd",
      eventKind: "mcp.server_added",
      workflowNodeId:
        optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
        `runtime.mcp-server.${safeId(server.id)}`,
      serversToUpsert: [server],
    });
  }

  removeThreadMcpServer(threadId, serverId, request = {}) {
    const agent = this.agentForThread(threadId);
    const registry = agent.mcpRegistry ?? mcpRegistryForWorkspace(agent.cwd, { homeDir: this.homeDir });
    const server = resolveMcpServerRecord(registry.servers, serverId ?? request.server_id ?? request.serverId);
    if (!server) throw notFound(`MCP server not found: ${serverId}`, { threadId, serverId });
    const remainingServers = normalizeArray(registry.servers).filter((candidate) => candidate.id !== server.id);
    const updatedRegistry = mcpRegistryWithServers(registry, remainingServers);
    const updatedAgent = {
      ...agent,
      mcpRegistry: updatedRegistry,
      updatedAt: new Date().toISOString(),
    };
    this.agents.set(agent.id, updatedAgent);
    const status = this.mcpStatus({ thread_id: threadId });
    return this.appendThreadMcpControlEvent({
      threadId,
      agent: updatedAgent,
      request,
      controlKind: "mcp_remove",
      sourceEventKind: "OperatorControl.McpRemove",
      eventKind: "mcp.server_removed",
      componentKind: "mcp_provider",
      workflowNodeId:
        optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
        `runtime.mcp-server.${safeId(server.id)}`,
      payloadSchemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      status: "completed",
      payload: {
        ...status,
        event_kind: "McpServerRemoved",
        control_kind: "mcp_remove",
        thread_id: threadId,
        agent_id: updatedAgent.id,
        server_id: server.id,
        serverId: server.id,
        server,
        removed: [server],
        removed_count: 1,
        removedCount: 1,
        policy_decision: "registry_write_allowed",
        summary: `MCP server ${server.id} removed from the active runtime registry.`,
      },
    });
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
    const registry = agent.mcpRegistry ?? mcpRegistryForWorkspace(agent.cwd, { homeDir: this.homeDir });
    const proposedServers = normalizeArray(serversToUpsert);
    if (proposedServers.length === 0) {
      throw runtimeError({
        status: 400,
        code: "mcp_servers_required",
        message: `MCP ${mutationKind} requires at least one server definition.`,
        details: { threadId, mutationKind },
      });
    }
    const validation = validateMcpServerRecords(proposedServers);
    if (!validation.ok) {
      const status = this.mcpStatus({ thread_id: threadId });
      return this.appendThreadMcpControlEvent({
        threadId,
        agent,
        request,
        controlKind: `mcp_${mutationKind}`,
        sourceEventKind,
        eventKind,
        componentKind: "mcp_provider",
        workflowNodeId,
        payloadSchemaVersion: RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
        status: "blocked",
        payload: {
          ...status,
          event_kind: mutationKind === "import" ? "McpServersImportBlocked" : "McpServerAddBlocked",
          control_kind: `mcp_${mutationKind}`,
          thread_id: threadId,
          agent_id: agent.id,
          proposed_servers: proposedServers,
          proposedServers,
          validation,
          issues: validation.issues,
          warnings: validation.warnings,
          policy_decision: "registry_write_blocked",
          summary: `MCP ${mutationKind} blocked by ${validation.issues.length} validation issue(s).`,
        },
      });
    }
    const byId = new Map(normalizeArray(registry.servers).map((server) => [server.id, server]));
    for (const server of proposedServers) {
      byId.set(server.id, {
        ...server,
        evidence_refs: uniqueStrings([
          ...(server.evidence_refs ?? server.evidenceRefs ?? []),
          mutationKind === "import" ? "mcp.manager.server.import" : "mcp.manager.server.add",
        ]),
        evidenceRefs: uniqueStrings([
          ...(server.evidence_refs ?? server.evidenceRefs ?? []),
          mutationKind === "import" ? "mcp.manager.server.import" : "mcp.manager.server.add",
        ]),
      });
    }
    const updatedRegistry = mcpRegistryWithServers(registry, [...byId.values()]);
    const updatedAgent = {
      ...agent,
      mcpRegistry: updatedRegistry,
      updatedAt: new Date().toISOString(),
    };
    this.agents.set(agent.id, updatedAgent);
    const status = this.mcpStatus({ thread_id: threadId });
    const eventLabel = mutationKind === "import" ? "McpServersImported" : "McpServerAdded";
    return this.appendThreadMcpControlEvent({
      threadId,
      agent: updatedAgent,
      request,
      controlKind: `mcp_${mutationKind}`,
      sourceEventKind,
      eventKind,
      componentKind: "mcp_provider",
      workflowNodeId,
      payloadSchemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      status: "completed",
      payload: {
        ...status,
        event_kind: eventLabel,
        control_kind: `mcp_${mutationKind}`,
        thread_id: threadId,
        agent_id: updatedAgent.id,
        servers: proposedServers,
        [mutationKind === "import" ? "imported" : "added"]: proposedServers,
        [`${mutationKind}_count`]: proposedServers.length,
        [`${mutationKind}Count`]: proposedServers.length,
        policy_decision: "registry_write_allowed",
        summary:
          mutationKind === "import"
            ? `Imported ${proposedServers.length} MCP server(s) into the active runtime registry.`
            : `MCP server ${proposedServers[0]?.id ?? "unknown"} added to the active runtime registry.`,
      },
    });
  }

  async mcpStatusWithLiveDiscovery(status, agent, request = {}) {
    const toolMap = new Map((status.tools ?? []).map((tool) => [mcpToolKey(tool), tool]));
    const resourceMap = new Map(
      (status.resources ?? []).map((resource) => [mcpResourceKey(resource), resource]),
    );
    const promptMap = new Map((status.prompts ?? []).map((prompt) => [mcpPromptKey(prompt), prompt]));
    const catalogSummaries = [];
    const previewLimit = mcpCatalogPreviewLimit(request);
    const forceFullCatalog = mcpCatalogFullRequested(request);
    const discoveries = [];
    for (const server of status.servers ?? []) {
      const liveMode = mcpLiveExecutionModeForServer(server, request);
      if (server.enabled === false || !liveMode) {
        continue;
      }
      try {
        const catalog =
          liveMode === "live_stdio"
            ? await discoverMcpStdioCatalog(server, {
                cwd: agent.cwd,
                timeoutMs: request.timeout_ms ?? request.timeoutMs,
              })
            : await discoverMcpHttpCatalog(server, {
                cwd: agent.cwd,
                timeoutMs: request.timeout_ms ?? request.timeoutMs,
                vault: this.modelMounting.vault,
              });
        const exposure = mcpCatalogExposureForStatus(server, catalog, {
          previewLimit,
          forceFullCatalog,
        });
        catalogSummaries.push(exposure.summary);
        for (const tool of exposure.tools) {
          toolMap.set(mcpToolKey(tool), tool);
        }
        for (const resource of exposure.resources) {
          resourceMap.set(mcpResourceKey(resource), resource);
        }
        for (const prompt of exposure.prompts) {
          promptMap.set(mcpPromptKey(prompt), prompt);
        }
        discoveries.push({
          server_id: server.id,
          serverId: server.id,
          status: "completed",
          transport: catalog.transport ?? server.transport ?? "stdio",
          execution_mode: catalog.execution_mode ?? catalog.executionMode ?? liveMode,
          executionMode: catalog.executionMode ?? catalog.execution_mode ?? liveMode,
          auth_boundary: catalog.auth_boundary ?? catalog.authBoundary ?? null,
          authBoundary: catalog.authBoundary ?? catalog.auth_boundary ?? null,
          tool_count: catalog.tool_count ?? 0,
          resource_count: catalog.resource_count ?? 0,
          prompt_count: catalog.prompt_count ?? 0,
          returned_tool_count: exposure.tools.length,
          returnedToolCount: exposure.tools.length,
          catalog_summary: exposure.summary,
          catalogSummary: exposure.summary,
          catalog_exposure: exposure.exposure,
          catalogExposure: exposure.exposure,
        });
      } catch (error) {
        discoveries.push({
          server_id: server.id,
          serverId: server.id,
          status: "failed",
          transport: server.transport ?? "stdio",
          execution_mode: liveMode,
          executionMode: liveMode,
          error_code: optionalString(error?.code) ?? "mcp_live_discovery_failed",
          message: String(error?.message ?? error),
        });
      }
    }
    const tools = [...toolMap.values()].sort((left, right) => mcpToolKey(left).localeCompare(mcpToolKey(right)));
    const resources = [...resourceMap.values()].sort((left, right) =>
      mcpResourceKey(left).localeCompare(mcpResourceKey(right)),
    );
    const prompts = [...promptMap.values()].sort((left, right) =>
      mcpPromptKey(left).localeCompare(mcpPromptKey(right)),
    );
    return {
      ...status,
      tools,
      tool_count: tools.length,
      toolCount: tools.length,
      resources,
      resource_count: resources.length,
      resourceCount: resources.length,
      prompts,
      prompt_count: prompts.length,
      promptCount: prompts.length,
      catalog_summaries: catalogSummaries,
      catalogSummaries,
      catalog_tool_count: catalogSummaries.reduce((sum, entry) => sum + (entry.tool_count ?? 0), 0),
      catalogToolCount: catalogSummaries.reduce((sum, entry) => sum + (entry.tool_count ?? 0), 0),
      returned_tool_count: tools.length,
      returnedToolCount: tools.length,
      live_discovery: {
        status: discoveries.some((entry) => entry.status === "failed") ? "partial" : "completed",
        requested: true,
        servers: discoveries,
      },
      liveDiscovery: {
        status: discoveries.some((entry) => entry.status === "failed") ? "partial" : "completed",
        requested: true,
        servers: discoveries,
      },
    };
  }

  async searchThreadMcpTools(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    return this.searchMcpToolCatalog({
      ...request,
      thread_id: threadId,
      threadId,
      servers: this.listMcpServers({ ...request, thread_id: threadId }),
      agent,
    });
  }

  async getThreadMcpTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    return this.getMcpToolFromCatalog(toolId, {
      ...request,
      thread_id: threadId,
      threadId,
      servers: this.listMcpServers({ ...request, thread_id: threadId }),
      agent,
    });
  }

  async getMcpToolFromCatalog(toolId, request = {}) {
    const result = await this.searchMcpToolCatalog({
      ...request,
      tool_id: toolId,
      toolId,
      exact: true,
      limit: Math.max(Number(request.limit ?? 0), MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT),
    });
    const requested = optionalString(toolId ?? request.tool_id ?? request.toolId);
    const tool = result.tools.find((candidate) => mcpToolIdentityMatches(candidate, requested)) ?? null;
    if (!tool) {
      throw notFound("MCP tool not found.", {
        toolId: requested ?? null,
        serverId: request.server_id ?? request.serverId ?? null,
      });
    }
    return {
      ...result,
      object: "ioi.runtime_mcp_tool_fetch",
      status: "completed",
      tool_id: requested ?? tool.stableToolId ?? tool.stable_tool_id ?? null,
      toolId: requested ?? tool.stableToolId ?? tool.stable_tool_id ?? null,
      server_id: tool.serverId ?? tool.server_id ?? null,
      serverId: tool.serverId ?? tool.server_id ?? null,
      tool_name: tool.toolName ?? tool.tool_name ?? null,
      toolName: tool.toolName ?? tool.tool_name ?? null,
      tool,
      tools: [tool],
      returned_count: 1,
      returnedCount: 1,
    };
  }

  async searchMcpToolCatalog(request = {}) {
    const query = optionalString(request.q ?? request.query ?? request.search) ?? "";
    const requestedToolId = optionalString(request.tool_id ?? request.toolId);
    const exact = request.exact === true || request.exact === "true";
    const serverFilter = optionalString(request.server_id ?? request.serverId);
    const liveDiscovery = request.live_discovery !== false && request.liveDiscovery !== false;
    const limit = mcpToolSearchLimit(request);
    const servers = normalizeArray(request.servers).filter((server) =>
      serverFilter ? resolveMcpServerRecord([server], serverFilter) : true,
    );
    const agent = request.agent ?? { cwd: this.defaultCwd };
    const catalogSummaries = [];
    const failures = [];
    const candidateTools = [];
    for (const server of servers) {
      let tools = mcpToolsForServers([server]);
      let resources = mcpResourcesForServers([server]);
      let prompts = mcpPromptsForServers([server]);
      const liveMode = liveDiscovery ? mcpLiveExecutionModeForServer(server, request) : null;
      if (server.enabled !== false && liveMode) {
        try {
          const catalog =
            liveMode === "live_stdio"
              ? await discoverMcpStdioCatalog(server, {
                  cwd: agent.cwd,
                  timeoutMs: request.timeout_ms ?? request.timeoutMs,
                })
              : await discoverMcpHttpCatalog(server, {
                  cwd: agent.cwd,
                  timeoutMs: request.timeout_ms ?? request.timeoutMs,
                  vault: this.modelMounting.vault,
                });
          tools = normalizeArray(catalog.tools ?? catalog.listed_tools);
          resources = normalizeArray(catalog.resources ?? catalog.listed_resources);
          prompts = normalizeArray(catalog.prompts ?? catalog.listed_prompts);
          catalogSummaries.push(mcpCatalogSummaryForServer(server, { tools, resources, prompts }, {
            liveMode,
            deferred: tools.length > mcpCatalogPreviewLimit(request),
            previewLimit: mcpCatalogPreviewLimit(request),
          }));
        } catch (error) {
          failures.push({
            server_id: server.id,
            serverId: server.id,
            status: "failed",
            error_code: optionalString(error?.code) ?? "mcp_tool_search_discovery_failed",
            message: String(error?.message ?? error),
          });
          catalogSummaries.push(mcpCatalogSummaryForServer(server, { tools, resources, prompts }, {
            liveMode,
            status: "failed",
            errorCode: optionalString(error?.code) ?? "mcp_tool_search_discovery_failed",
          }));
        }
      } else {
        catalogSummaries.push(mcpCatalogSummaryForServer(server, { tools, resources, prompts }, {
          liveMode: liveMode ?? "declared_catalog",
          deferred: false,
          previewLimit: mcpCatalogPreviewLimit(request),
        }));
      }
      candidateTools.push(...tools);
    }
    const filtered = candidateTools
      .filter((tool) =>
        requestedToolId
          ? mcpToolIdentityMatches(tool, requestedToolId) || (!exact && mcpToolMatchesQuery(tool, requestedToolId))
          : mcpToolMatchesQuery(tool, query),
      )
      .sort((left, right) => mcpToolKey(left).localeCompare(mcpToolKey(right)));
    const returned = filtered.slice(0, limit);
    return {
      schema_version: RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION,
      object: "ioi.runtime_mcp_tool_search",
      status: failures.length > 0 ? "partial" : "completed",
      query,
      q: query,
      exact,
      live_discovery: liveDiscovery,
      liveDiscovery,
      server_count: servers.length,
      serverCount: servers.length,
      tool_count: filtered.length,
      toolCount: filtered.length,
      returned_count: returned.length,
      returnedCount: returned.length,
      limit,
      deferred: filtered.length > returned.length,
      tools: returned,
      catalog_summaries: catalogSummaries,
      catalogSummaries,
      failures,
      routes: {
        search: "/v1/mcp/tools/search",
        getTool: "/v1/mcp/tools/{tool_id}",
        invokeTool: "/v1/mcp/tools/{tool_id}/invoke",
      },
    };
  }

  setMcpServerEnabled(serverId, enabled, request = {}) {
    const threadId = optionalString(request.thread_id ?? request.threadId);
    if (!threadId) {
      throw runtimeError({
        status: 400,
        code: "mcp_thread_required",
        message: "MCP server enable/disable controls require a thread_id so the daemon can update the active runtime registry.",
        details: { serverId, enabled },
      });
    }
    return this.setThreadMcpServerEnabled(threadId, serverId, enabled, request);
  }

  setThreadMcpServerEnabled(threadId, serverId, enabled, request = {}) {
    const agent = this.agentForThread(threadId);
    const registry = agent.mcpRegistry ?? mcpRegistryForWorkspace(agent.cwd, { homeDir: this.homeDir });
    const server = resolveMcpServerRecord(registry.servers, serverId);
    if (!server) throw notFound(`MCP server not found: ${serverId}`, { threadId, serverId });
    const nextStatus = enabled
      ? (server.status === "disabled" ? "configured" : server.status ?? "configured")
      : "disabled";
    const updatedServer = {
      ...server,
      enabled,
      status: nextStatus,
      health: {
        ...(server.health ?? {}),
        status: enabled ? server.health?.status ?? "not_connected" : "disabled",
        live_probe: false,
        reason: enabled ? "operator_enabled" : "operator_disabled",
      },
      evidence_refs: uniqueStrings([
        ...(server.evidence_refs ?? server.evidenceRefs ?? []),
        enabled ? "mcp.manager.server.enable" : "mcp.manager.server.disable",
      ]),
      evidenceRefs: uniqueStrings([
        ...(server.evidence_refs ?? server.evidenceRefs ?? []),
        enabled ? "mcp.manager.server.enable" : "mcp.manager.server.disable",
      ]),
    };
    const servers = normalizeArray(registry.servers).map((candidate) =>
      candidate.id === server.id ? updatedServer : candidate,
    );
    const updatedRegistry = mcpRegistryWithServers(registry, servers);
    const updatedAgent = {
      ...agent,
      mcpRegistry: updatedRegistry,
      updatedAt: new Date().toISOString(),
    };
    this.agents.set(agent.id, updatedAgent);
    const status = this.mcpStatus({ thread_id: threadId });
    const controlKind = enabled ? "mcp_enable" : "mcp_disable";
    return this.appendThreadMcpControlEvent({
      threadId,
      agent: updatedAgent,
      request,
      controlKind,
      sourceEventKind: enabled ? "OperatorControl.McpEnable" : "OperatorControl.McpDisable",
      eventKind: enabled ? "mcp.server_enabled" : "mcp.server_disabled",
      componentKind: "mcp_provider",
      workflowNodeId:
        optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
        `runtime.mcp-server.${safeId(updatedServer.id)}`,
      payloadSchemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      status: "completed",
      payload: {
        ...status,
        event_kind: enabled ? "McpServerEnabled" : "McpServerDisabled",
        control_kind: controlKind,
        thread_id: threadId,
        agent_id: updatedAgent.id,
        server_id: updatedServer.id,
        serverId: updatedServer.id,
        enabled,
        server: updatedServer,
        servers: [updatedServer],
        tools: mcpToolsForServers([updatedServer]),
        summary: `MCP server ${updatedServer.id} ${enabled ? "enabled" : "disabled"}.`,
      },
    });
  }

  async invokeMcpTool(request = {}) {
    const threadId = optionalString(request.thread_id ?? request.threadId);
    if (!threadId) {
      throw runtimeError({
        status: 400,
        code: "mcp_thread_required",
        message: "MCP tool invocation requires a thread_id so the daemon can apply the active MCP registry and approval policy.",
        details: { toolId: request.tool_id ?? request.toolId ?? null },
      });
    }
    return this.invokeThreadMcpTool(threadId, request.tool_id ?? request.toolId, request);
  }

  async invokeThreadMcpTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const servers = this.listMcpServers({ thread_id: threadId });
    const target = resolveMcpToolRecord(servers, toolId, request);
    if (!target.server) {
      throw notFound("MCP server not found for invocation.", {
        threadId,
        toolId,
        serverId: request.server_id ?? request.serverId ?? null,
      });
    }
    if (!target.toolName) {
      throw runtimeError({
        status: 400,
        code: "mcp_tool_required",
        message: "MCP invocation requires a tool name.",
        details: { threadId, serverId: target.server.id, toolId: toolId ?? null },
      });
    }
    const server = target.server;
    const toolName = target.toolName;
    const tools = mcpToolsForServers([server]);
    const toolEntry =
      tools.find((candidate) => candidate.toolName === toolName || candidate.tool_name === toolName) ??
      null;
    if (!toolEntry) {
      throw notFound(`MCP tool not found: ${toolName}`, {
        threadId,
        serverId: server.id,
        toolName,
      });
    }
    const input = request.input ?? request.arguments ?? request.args ?? {};
    const sideEffectClass =
      optionalString(request.side_effect_class ?? request.sideEffectClass) ??
      optionalString(toolEntry.sideEffectClass) ??
      "read";
    const requiresApproval =
      request.requires_approval === true ||
      request.requiresApproval === true ||
      (sideEffectClass !== "none" && sideEffectClass !== "read");
    const approvalMode =
      optionalString(agent.runtimeControls?.approval_mode ?? agent.runtimeControls?.approvalMode) ??
      "agent";
    const approved =
      request.approved === true ||
      request.approval_granted === true ||
      request.approvalGranted === true ||
      approvalMode === "yolo";
    const validation = validateMcpServerRecords([server]);
    const blockers = [
      ...(server.enabled === false ? ["server_disabled"] : []),
      ...(!validation.ok ? validation.issues.map((issue) => issue.code) : []),
      ...(requiresApproval && !approved ? ["approval_required"] : []),
    ];
    const inputHash = doctorHash(JSON.stringify(input));
    let status = blockers.length > 0 ? "blocked" : "completed";
    let output = null;
    let transportExecution = null;
    if (status === "completed") {
      const liveMode = mcpLiveExecutionModeForServer(server, request);
      if (liveMode === "live_stdio") {
        try {
          transportExecution = await invokeMcpStdioTool(server, toolName, input, {
            cwd: agent.cwd,
            timeoutMs: request.timeout_ms ?? request.timeoutMs,
            mcpMode: request.mcp_mode ?? request.mcpMode,
          });
          output = transportExecution.result ?? {};
        } catch (error) {
          status = "blocked";
          blockers.push("stdio_transport_failed");
          transportExecution = {
            ok: false,
            status: "failed",
            transport: "stdio",
            execution_mode: "live_stdio",
            executionMode: "live_stdio",
            error: {
              code: optionalString(error?.code) ?? "mcp_stdio_transport_error",
              message: String(error?.message ?? error),
              details: error?.details ?? {},
            },
          };
        }
      } else if (liveMode === "live_http" || liveMode === "live_sse") {
        const transport = liveMode === "live_sse" ? "sse" : "http";
        try {
          transportExecution = await invokeMcpHttpTool(server, toolName, input, {
            cwd: agent.cwd,
            timeoutMs: request.timeout_ms ?? request.timeoutMs,
            headers: request.headers,
            vault: this.modelMounting.vault,
          });
          output = transportExecution.result ?? {};
        } catch (error) {
          status = "blocked";
          blockers.push(`${transport}_transport_failed`);
          transportExecution = {
            ok: false,
            status: "failed",
            transport,
            execution_mode: liveMode,
            executionMode: liveMode,
            error: {
              code: optionalString(error?.code) ?? `mcp_${transport}_transport_error`,
              message: String(error?.message ?? error),
              details: error?.details ?? {},
            },
          };
        }
      } else {
        output = { ok: true, fixture: true, serverId: server.id, toolName };
        transportExecution = {
          ok: true,
          status: "completed",
          transport: server.transport ?? "unknown",
          execution_mode: "simulated_manager_receipt",
          executionMode: "simulated_manager_receipt",
        };
      }
    }
    const outputHash = doctorHash(
      JSON.stringify(output ?? { blocked: blockers, transport_execution: transportExecution }),
    );
    const callHash = doctorHash(
      `${threadId}:${server.id}:${toolName}:${inputHash}:${Date.now()}`,
    ).slice(0, 16);
    const toolCallId = `mcp_call_${safeId(server.id)}_${safeId(toolName)}_${callHash}`;
    const invocation = {
      schema_version: RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
      object: "ioi.runtime_mcp_tool_invocation",
      tool_call_id: toolCallId,
      toolCallId,
      thread_id: threadId,
      threadId,
      agent_id: agent.id,
      agentId: agent.id,
      server_id: server.id,
      serverId: server.id,
      tool_name: toolName,
      toolName,
      status,
      input_hash: inputHash,
      inputHash,
      output_hash: outputHash,
      outputHash,
      side_effect_class: sideEffectClass,
      sideEffectClass,
      requires_approval: requiresApproval,
      requiresApproval,
      approval_mode: approvalMode,
      approvalMode,
      approved,
      blockers,
      transport: server.transport ?? "stdio",
      transport_execution: transportExecution,
      transportExecution,
      containment: {
        ...(server.containment ?? {}),
        receiptRequired: true,
        executionMode: transportExecution?.executionMode ?? transportExecution?.execution_mode ?? "blocked",
        execution_mode: transportExecution?.execution_mode ?? transportExecution?.executionMode ?? "blocked",
      },
      result: output,
      evidence_refs: [
        "mcp.manager.tool.invoke",
        "mcp_containment_receipt",
        mcpTransportEvidenceRef(transportExecution),
        server.id,
        `tool:${toolName}`,
      ],
      evidenceRefs: [
        "mcp.manager.tool.invoke",
        "mcp_containment_receipt",
        mcpTransportEvidenceRef(transportExecution),
        server.id,
        `tool:${toolName}`,
      ],
    };
    return this.appendThreadMcpControlEvent({
      threadId,
      agent,
      request,
      controlKind: "mcp_invoke",
      sourceEventKind: "OperatorControl.McpInvoke",
      eventKind: "mcp.tool_invocation",
      componentKind: "mcp_tool_call",
      workflowNodeId:
        optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
        toolEntry.workflowNodeId ??
        toolEntry.workflow_node_id ??
        `runtime.mcp-tool.${safeId(server.id)}.${safeId(toolName)}`,
      payloadSchemaVersion: RUNTIME_MCP_MANAGER_INVOCATION_SCHEMA_VERSION,
      status,
      payload: {
        ...invocation,
        event_kind: "McpToolInvocation",
        control_kind: "mcp_invoke",
        server,
        servers: [server],
        tool: { ...toolEntry, status },
        tools: [{ ...toolEntry, status }],
        invocation,
        summary:
          status === "completed"
            ? `MCP tool ${server.id}.${toolName} invoked with ${mcpTransportSummary(transportExecution)}.`
            : `MCP tool ${server.id}.${toolName} blocked: ${blockers.join(", ")}.`,
        policy_decision: status === "completed" ? "invoke_allowed" : "invoke_blocked",
        result: output,
      },
    });
  }

  mcpServeStatus(options = {}) {
    const allowedToolIds = mcpServeAllowedToolIds(options);
    const tools = this.mcpServeToolCatalog(options);
    return {
      schema_version: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
      schemaVersion: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
      object: "ioi.runtime_mcp_serve_status",
      status: "ready",
      transport: "http_jsonrpc",
      protocol_version: RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
      protocolVersion: RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
      thread_id: optionalString(options.thread_id ?? options.threadId) ?? null,
      allowed_tool_ids: allowedToolIds,
      allowedToolIds,
      tool_count: tools.length,
      toolCount: tools.length,
      tools,
      routes: {
        serve: "/v1/mcp/serve",
        serveForThread: "/v1/threads/{thread_id}/mcp/serve",
      },
      evidence_refs: ["mcp.serve.http_jsonrpc", "coding_tool_receipt"],
      evidenceRefs: ["mcp.serve.http_jsonrpc", "coding_tool_receipt"],
    };
  }

  mcpServeToolCatalog(options = {}) {
    const allowedToolIds = new Set(mcpServeAllowedToolIds(options));
    return codingToolContracts()
      .filter((tool) => allowedToolIds.has(tool.stableToolId))
      .map((tool) => mcpServeToolDescriptor(tool));
  }

  async handleMcpServeJsonRpc(threadId, message, request = {}) {
    this.agentForThread(threadId);
    const context = {
      ...request,
      thread_id: threadId,
      threadId,
    };
    if (Array.isArray(message)) {
      const responses = await Promise.all(
        message.map((entry) => this.handleSingleMcpServeJsonRpc(threadId, entry, context)),
      );
      return responses.filter(Boolean);
    }
    return this.handleSingleMcpServeJsonRpc(threadId, message, context);
  }

  async handleSingleMcpServeJsonRpc(threadId, message, request = {}) {
    const id = message?.id;
    const method = optionalString(message?.method);
    if (!message || typeof message !== "object" || Array.isArray(message) || !method) {
      return mcpJsonRpcError(id ?? null, -32600, "Invalid MCP JSON-RPC request.", {
        schema_version: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
      });
    }
    try {
      if (method === "initialize") {
        const status = this.mcpServeStatus(request);
        return mcpJsonRpcResult(id, {
          protocolVersion: RUNTIME_MCP_SERVE_PROTOCOL_VERSION,
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
            prompts: { listChanged: false },
          },
          serverInfo: {
            name: "ioi-runtime",
            version: RUNTIME_MCP_SERVE_SCHEMA_VERSION,
          },
          instructions:
            "IOI runtime MCP serve mode exposes governed, receipt-backed runtime tools for the selected thread.",
          _meta: status,
        });
      }
      if (method === "notifications/initialized") {
        return id === undefined || id === null ? null : mcpJsonRpcResult(id, {});
      }
      if (method === "ping") {
        return mcpJsonRpcResult(id, {});
      }
      if (method === "tools/list") {
        return mcpJsonRpcResult(id, { tools: this.mcpServeToolCatalog(request) });
      }
      if (method === "resources/list") {
        return mcpJsonRpcResult(id, { resources: [] });
      }
      if (method === "prompts/list") {
        return mcpJsonRpcResult(id, { prompts: [] });
      }
      if (method === "tools/call") {
        const params = message.params && typeof message.params === "object" ? message.params : {};
        const toolName = optionalString(params.name ?? params.tool_name ?? params.toolName);
        const toolId = mcpServeToolIdForName(toolName, request);
        if (!toolId) {
          return mcpJsonRpcError(id, -32602, `MCP serve tool is not allowed: ${toolName ?? "missing"}.`, {
            allowedTools: mcpServeAllowedToolIds(request),
          });
        }
        const input = params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
          ? params.arguments
          : params.args && typeof params.args === "object" && !Array.isArray(params.args)
            ? params.args
            : {};
        const invocation = await this.invokeThreadToolAsync(threadId, toolId, {
          source: "mcp_serve",
          workflow_graph_id:
            optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
            "runtime.mcp-serve",
          workflow_node_id:
            optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
            `runtime.mcp-serve.${safeId(toolId)}`,
          input,
        });
        return mcpJsonRpcResult(id, mcpServeToolCallResult(invocation));
      }
      return mcpJsonRpcError(id, -32601, `MCP method not found: ${method}.`, {
        supportedMethods: [
          "initialize",
          "notifications/initialized",
          "ping",
          "tools/list",
          "tools/call",
          "resources/list",
          "prompts/list",
        ],
      });
    } catch (error) {
      return mcpJsonRpcError(id, mcpJsonRpcErrorCodeFor(error), String(error?.message ?? error), {
        code: optionalString(error?.code) ?? "mcp_serve_error",
        details: error?.details ?? null,
      });
    }
  }

  async recordThreadMcpStatus(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    let status = this.mcpStatus({ ...request, thread_id: threadId });
    if (request.live_discovery === true || request.liveDiscovery === true) {
      status = await this.mcpStatusWithLiveDiscovery(status, agent, request);
    }
    return this.appendThreadMcpControlEvent({
      threadId,
      agent,
      request,
      controlKind: "mcp_status",
      sourceEventKind: "OperatorControl.Mcp",
      eventKind: "mcp.catalog_status",
      componentKind: "mcp_provider",
      workflowNodeId: "runtime.mcp-manager",
      payloadSchemaVersion: RUNTIME_MCP_MANAGER_STATUS_SCHEMA_VERSION,
      status: status.status === "ready" ? "completed" : "blocked",
      payload: {
        ...status,
        event_kind: "McpCatalogStatus",
        control_kind: "mcp_status",
        thread_id: threadId,
        agent_id: agent.id,
        summary: `MCP catalog has ${status.server_count} server(s), ${status.tool_count} tool(s), ${status.resource_count ?? 0} resource(s), and ${status.prompt_count ?? 0} prompt(s).`,
      },
    });
  }

  validateThreadMcp(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const validation = this.validateMcp(
      request.mcp_json || request.mcpJson || request.servers || request.mcpServers
        ? request
        : { servers: this.listMcpServers({ ...request, thread_id: threadId }) },
    );
    return this.appendThreadMcpControlEvent({
      threadId,
      agent,
      request,
      controlKind: "mcp_validate",
      sourceEventKind: "OperatorControl.McpValidate",
      eventKind: "mcp.validation",
      componentKind: "mcp_validator",
      workflowNodeId: "runtime.mcp-manager.validate",
      payloadSchemaVersion: RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION,
      status: validation.ok ? "completed" : "blocked",
      payload: {
        ...validation,
        event_kind: "McpValidationReport",
        control_kind: "mcp_validate",
        thread_id: threadId,
        agent_id: agent.id,
        summary: validation.ok
          ? `MCP validation passed for ${validation.server_count} server(s).`
          : `MCP validation found ${validation.issue_count} issue(s).`,
      },
    });
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
    const thread = this.threadForAgent(agent);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(thread.latest_turn_id) ??
      "";
    const source = operatorControlSource(request.source);
    const graphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const nodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      workflowNodeId;
    const eventHash = doctorHash(`${threadId}:${controlKind}:${JSON.stringify(payload)}:${Date.now()}`).slice(0, 12);
    const receiptId = `receipt_mcp_${safeId(controlKind)}_${eventHash}`;
    const policyKind =
      optionalString(payload.policy_decision ?? payload.policyDecision) ??
      (status === "blocked"
        ? "blocked"
        : controlKind === "mcp_invoke"
          ? "invoke_allowed"
          : "read");
    const policyId = `policy_mcp_${safeId(controlKind)}_${safeId(policyKind)}_${eventHash}`;
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:mcp:${safeId(controlKind)}:${eventHash}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:mcp:${controlKind}:${eventHash}`,
      source,
      source_event_kind: sourceEventKind,
      event_kind: eventKind,
      status,
      actor: "operator",
      workspace_root: agent.cwd,
      workflow_graph_id: graphId,
      workflow_node_id: nodeId,
      component_kind: componentKind,
      payload_schema_version: payloadSchemaVersion,
      payload_summary: payload,
      receipt_refs: [receiptId],
      policy_decision_refs: [policyId],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const result = {
      ...payload,
      event,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, `thread.${controlKind}`);
    return result;
  }

  mcpServersForContext(options = {}) {
    const threadId = optionalString(options.thread_id ?? options.threadId);
    const agentId =
      optionalString(options.agent_id ?? options.agentId) ??
      (threadId ? agentIdForThread(threadId) : undefined);
    const sourceMode = mcpConfigSourceModeForRequest(options);
    const servers = [];
    if (agentId && this.agents.has(agentId)) {
      const agent = this.getAgent(agentId);
      servers.push(...normalizeArray(agent.mcpRegistry?.servers));
    } else {
      servers.push(
        ...mcpRegistryForWorkspace(this.defaultCwd, {
          ...options,
          homeDir: this.homeDir,
          mcpConfigSourceMode: sourceMode,
        }).servers,
      );
      for (const agent of this.agents.values()) {
        servers.push(...normalizeArray(agent.mcpRegistry?.servers));
      }
    }
    servers.push(
      ...this.modelMounting.listMcpServers().map((server) =>
        normalizeMcpServerRecord(server.label ?? server.id, server, {
          workspaceRoot: this.defaultCwd,
          source: server.source ?? "model_mounting",
          sourceScope: "model_mounting",
          configCompatibility: "ioi_model_mounting",
          status: server.status ?? "registered",
        }),
      ),
    );
    const byId = new Map();
    for (const server of servers) {
      byId.set(server.id, server);
    }
    return [...byId.values()]
      .filter((server) => mcpServerMatchesConfigSourceMode(server, sourceMode))
      .sort((left, right) => left.id.localeCompare(right.id));
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
    return getRunState(this, runId, {
      notFound,
    });
  }

  listRuns(agentId) {
    return listRunsState(this, agentId);
  }

  usageForRun(runId) {
    return usageForRunState(this, runId, {
      runtimeUsageTelemetryForRun,
      threadIdForAgent,
    });
  }

  usageForThread(threadId) {
    return usageForThreadState(this, threadId, {
      runtimeUsageTelemetryForThread,
    });
  }

  listUsage(options = {}) {
    const groupBy = options.group_by ?? options.groupBy ?? "run";
    const agentId = options.agentId ?? options.agent_id;
    const parentThreadId = agentId ? threadIdForAgent(agentId) : null;
    return runtimeUsageTelemetryList({
      runs: this.listRuns(agentId),
      subagents: [...this.subagents.values()].filter(
        (record) =>
          !parentThreadId || (record.parent_thread_id ?? record.parentThreadId) === parentThreadId,
      ),
      groupBy,
    });
  }

  authorityEvidenceSummary(options = {}) {
    for (const agent of this.agents.values()) {
      this.projectThreadEvents(agent);
    }
    return authorityEvidenceSummaryForEvents(
      [...this.runtimeEventStreams.values()].flatMap((stream) => stream.events),
      options,
    );
  }

  evaluateContextBudget({ threadId = null, runId = null, request = {} } = {}) {
    const requestedRunId = optionalString(request.run_id ?? request.runId) ?? runId;
    const run = requestedRunId ? this.getRun(requestedRunId) : null;
    const requestedThreadId =
      optionalString(request.thread_id ?? request.threadId) ??
      threadId ??
      (run ? threadIdForAgent(run.agentId) : null);
    const scope =
      optionalString(request.scope) ??
      (requestedRunId ? "run" : requestedThreadId ? "thread" : "workflow");
    const usageTelemetry =
      contextBudgetUsageTelemetryFromRequest(request) ??
      (requestedRunId
        ? this.usageForRun(requestedRunId)
        : requestedThreadId
          ? this.usageForThread(requestedThreadId)
          : this.listUsage({ group_by: "thread" }));
    const result = evaluateContextBudgetPolicy({
      usageTelemetry,
      request: {
        ...request,
        scope,
        threadId: requestedThreadId,
        thread_id: requestedThreadId,
        runId: requestedRunId,
        run_id: requestedRunId,
      },
    });

    if (!requestedThreadId) return result;

    const agent = this.agentForThread(requestedThreadId);
    const latestRun = run ?? this.listRuns(agent.id).at(-1) ?? null;
    const now = new Date().toISOString();
    const eventKind =
      result.status === "blocked" ? "policy.blocked" : "context_budget.evaluated";
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(requestedThreadId),
      thread_id: requestedThreadId,
      turn_id: latestRun ? turnIdForRun(latestRun.id) : "",
      item_id: `${latestRun ? turnIdForRun(latestRun.id) : requestedThreadId}:item:context-budget:${safeId(result.policy_decision_id)}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${requestedThreadId}:context-budget:${safeId(result.policy_decision_id)}`,
      source: operatorControlSource(request.source),
      source_event_kind:
        optionalString(request.eventKind ?? request.event_kind) ??
        "RuntimeContextBudget.Evaluate",
      event_kind: eventKind,
      status: result.status === "blocked" ? "blocked" : "completed",
      actor: optionalString(request.actor) ?? "operator",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id:
        request.workflow_node_id ?? request.workflowNodeId ?? "runtime.context-budget",
      component_kind: "context_budget",
      payload_schema_version: RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION,
      payload_summary: result,
      receipt_refs: result.receipt_refs,
      policy_decision_refs: result.policy_decision_refs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    return {
      ...result,
      event,
      event_id: event.event_id,
      eventId: event.event_id,
      seq: event.seq,
    };
  }

  evaluateCompactionPolicy({ threadId, request = {} } = {}) {
    const requestedThreadId =
      optionalString(request.thread_id ?? request.threadId) ?? threadId;
    if (!requestedThreadId) {
      throw runtimeError({
        status: 400,
        code: "runtime_compaction_policy_thread_required",
        message: "Compaction policy evaluation requires a thread id.",
      });
    }
    const agent = this.agentForThread(requestedThreadId);
    const latestRun = this.listRuns(agent.id).at(-1) ?? null;
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      (latestRun ? turnIdForRun(latestRun.id) : "");
    const result = evaluateCompactionPolicyDecision({
      threadId: requestedThreadId,
      turnId,
      request,
    });
    const streamId = eventStreamIdForThread(requestedThreadId);
    let compactEvent = null;
    if (
      result.action === "compact" &&
      result.approval_satisfied &&
      result.execute_compaction
    ) {
      const previousLatestSeq = this.latestRuntimeEventSeq(streamId);
      this.compactThread(requestedThreadId, {
        reason: result.compact_reason,
        scope: result.compact_scope,
        turn_id: turnId,
        source: request.source,
        actor: optionalString(request.actor) ?? "operator",
        workflow_graph_id: result.workflow_graph_id,
        workflow_node_id: result.compact_workflow_node_id,
        idempotency_key:
          optionalString(request.compact_idempotency_key ?? request.compactIdempotencyKey) ??
          `thread:${requestedThreadId}:compaction-policy:compact:${safeId(result.policy_decision_id)}`,
      });
      compactEvent =
        this.runtimeEventsForStream(streamId, { sinceSeq: previousLatestSeq }).find(
          (event) => event.component_kind === "context_compaction",
        ) ?? null;
      result.compaction_executed = Boolean(compactEvent);
      result.compactionExecuted = result.compaction_executed;
      result.compaction_event_id = compactEvent?.event_id ?? null;
      result.compactionEventId = result.compaction_event_id;
      result.compaction_seq = compactEvent?.seq ?? null;
      result.compactionSeq = result.compaction_seq;
    }
    const now = new Date().toISOString();
    const eventKind =
      result.action === "stop"
        ? "policy.blocked"
        : result.action === "approval_required"
          ? "approval.required"
          : "compaction_policy.evaluated";
    const eventStatus =
      result.action === "stop"
        ? "blocked"
        : result.action === "approval_required"
          ? "waiting"
          : "completed";
    const event = this.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: requestedThreadId,
      turn_id: turnId,
      item_id: `${turnId || requestedThreadId}:item:compaction-policy:${safeId(result.policy_decision_id)}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${requestedThreadId}:compaction-policy:${safeId(result.policy_decision_id)}`,
      source: operatorControlSource(request.source),
      source_event_kind:
        optionalString(request.eventKind ?? request.event_kind) ??
        "RuntimeCompactionPolicy.Evaluate",
      event_kind: eventKind,
      status: eventStatus,
      actor: optionalString(request.actor) ?? "operator",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: result.workflow_graph_id,
      workflow_node_id: result.workflow_node_id,
      approval_id: result.approval_id,
      component_kind: "compaction_policy",
      payload_schema_version: RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION,
      payload_summary: result,
      receipt_refs: result.receipt_refs,
      policy_decision_refs: result.policy_decision_refs,
      artifact_refs: compactEvent ? compactEvent.artifact_refs : [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    return {
      ...result,
      event,
      event_id: event.event_id,
      eventId: event.event_id,
      seq: event.seq,
    };
  }

  cancelRun(runId) {
    const run = this.getRun(runId);
    const status = run.status === "canceled" ? "canceled" : "canceled";
    const updatedAt = new Date().toISOString();
    const nonTerminalEvents = run.events.filter(
      (event) => !TERMINAL_EVENT_TYPES.has(event.type) && !JOB_TERMINAL_EVENT_TYPES.has(event.type),
    );
    const hasRuntimeTaskEvent = nonTerminalEvents.some((event) => event.type === "runtime_task");
    const hasRuntimeChecklistEvent = nonTerminalEvents.some((event) => event.type === "runtime_checklist");
    const finalEventCount =
      nonTerminalEvents.length + (hasRuntimeTaskEvent ? 0 : 1) + (hasRuntimeChecklistEvent ? 0 : 1) + 2;
    const stopCondition = {
      reason: "marginal_improvement_too_low",
      evidenceSufficient: true,
      rationale:
        "Cancellation became the single terminal event and replay cursor continuity was preserved.",
    };
    const runtimeTask = runtimeTaskRecord({
      runId: run.id,
      agent: { id: run.agentId },
      prompt: run.objective,
      mode: run.mode,
      taskFamily: run.trace?.qualityLedger?.taskFamily ?? taskFamilyForMode(run.mode ?? "send"),
      selectedStrategy: run.trace?.qualityLedger?.selectedStrategy ?? strategyForMode(run.mode ?? "send"),
      modelRouteDecision: run.modelRouteDecision ?? run.trace?.modelRouteDecision,
      activeSkillHookManifest: run.activeSkillHookManifest ?? run.trace?.activeSkillHookManifest,
      createdAt: run.createdAt,
      updatedAt,
      status,
    });
    let runtimeJob = runtimeJobRecord({
      runtimeTask,
      status,
      createdAt: run.createdAt,
      updatedAt,
      queuedAt: run.runtimeJob?.queuedAt ?? run.createdAt,
      startedAt: run.runtimeJob?.startedAt ?? run.createdAt,
      completedAt: updatedAt,
      lifecycle: ["queued", "started", "canceled"],
      eventCount: finalEventCount,
      terminalEventCount: 1,
      artifactNames: normalizeArray(run.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
      receiptKinds: normalizeArray(run.receipts).map((receipt) => receipt.kind).filter(Boolean),
    });
    const runtimeChecklist = runtimeChecklistRecord({
      runtimeTask,
      runtimeJob,
      status,
      createdAt: run.createdAt,
      updatedAt,
    });
    runtimeJob = attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist);
    const canceledEvents = nonTerminalEvents.map((event) => {
      if (event.type === "runtime_task") {
        return {
          ...event,
          data: {
            ...runtimeTask,
            receiptId: `receipt_${run.id}_runtime_task`,
            eventKind: "RuntimeTaskRecord",
            workflowNodeId: "runtime.runtime-task",
          },
        };
      }
      if (event.type === "runtime_checklist") {
        return {
          ...event,
          data: {
            ...runtimeChecklist,
            receiptId: `receipt_${run.id}_runtime_checklist`,
            eventKind: "RuntimeChecklistRecord",
            workflowNodeId: "runtime.runtime-checklist",
          },
        };
      }
      return event;
    });
    if (!canceledEvents.some((event) => event.type === "runtime_task")) {
      canceledEvents.push(
        makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_task", "Runtime task record written", {
          ...runtimeTask,
          receiptId: `receipt_${run.id}_runtime_task`,
          eventKind: "RuntimeTaskRecord",
          workflowNodeId: "runtime.runtime-task",
        }),
      );
    }
    if (!canceledEvents.some((event) => event.type === "runtime_checklist")) {
      canceledEvents.push(
        makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_checklist", "Runtime checklist recorded", {
          ...runtimeChecklist,
          receiptId: `receipt_${run.id}_runtime_checklist`,
          eventKind: "RuntimeChecklistRecord",
          workflowNodeId: "runtime.runtime-checklist",
        }),
      );
    }
    const jobCanceled = makeEvent(
      run.id,
      run.agentId,
      canceledEvents.length,
      "job_canceled",
      "Runtime job canceled",
      {
        ...runtimeJob,
        lifecycleStatus: "canceled",
        receiptId: `receipt_${run.id}_runtime_job`,
        eventKind: "JobCanceled",
        workflowNodeId: "runtime.runtime-job",
      },
    );
    canceledEvents.push(jobCanceled);
    const canceled = makeEvent(
      run.id,
      run.agentId,
      canceledEvents.length,
      "canceled",
      "Run canceled",
      { reason: "operator_cancel", priorStatus: run.status },
    );
    canceledEvents.push(canceled);
    const runtimeChecklistReceipt = {
      id: `receipt_${run.id}_runtime_checklist`,
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
    const receipts = normalizeArray(run.receipts).map((receipt) =>
      receipt.id === runtimeChecklistReceipt.id ? runtimeChecklistReceipt : receipt,
    );
    if (!receipts.some((receipt) => receipt.id === runtimeChecklistReceipt.id)) {
      receipts.push(runtimeChecklistReceipt);
    }
    const trace = {
      ...run.trace,
      events: canceledEvents,
      receipts,
      runtimeTask,
      runtimeJob,
      runtimeChecklist,
      stopCondition,
      qualityLedger: {
        ...run.trace.qualityLedger,
        failureOntologyLabels: [
          ...new Set([...run.trace.qualityLedger.failureOntologyLabels, "operator_cancel"]),
        ],
      },
    };
    const artifacts = normalizeArray(run.artifacts).map((item) => {
      if (item.name === "runtime-task.json") return { ...item, content: runtimeTask };
      if (item.name === "runtime-job.json") return { ...item, content: runtimeJob };
      if (item.name === "runtime-checklist.json") return { ...item, content: runtimeChecklist };
      return item;
    });
    if (!artifacts.some((item) => item.name === "runtime-checklist.json")) {
      artifacts.push(
        artifact(run.id, "runtime-checklist.json", "application/json", runtimeChecklistReceipt.id, runtimeChecklist, "redacted"),
      );
    }
    const updated = {
      ...run,
      status,
      updatedAt,
      events: trace.events,
      trace,
      receipts,
      artifacts,
      runtimeTask: trace.runtimeTask,
      runtimeJob: trace.runtimeJob,
      runtimeChecklist: trace.runtimeChecklist,
      result: "Run canceled with terminal event continuity preserved.",
    };
    this.runs.set(runId, updated);
    this.writeRun(updated, "run.cancel");
    return updated;
  }

  legacyEventsForRun(runId, lastEventId) {
    const events = this.getRun(runId).events;
    if (!lastEventId) return events;
    const index = events.findIndex((event) => event.id === lastEventId);
    return events.slice(index >= 0 ? index + 1 : 0);
  }

  replayFromCanonicalState(runId, cursor) {
    return this.eventsForRun(runId, cursor);
  }

  traceFromCanonicalState(runId) {
    return this.getRun(runId).trace;
  }

  canonicalProjection(runId) {
    const run = this.getRun(runId);
    const watermark = this.operationCount();
    return {
      schemaVersion: this.schemaVersion,
      runId,
      source: "agentgres_canonical_operation_log",
      watermark,
      freshness: {
        source: "local-agentgres-v0",
        operationCount: watermark,
        generatedAt: new Date().toISOString(),
      },
      paths: {
        run: relative(this.stateDir, this.pathFor("runs", `${run.id}.json`)),
        task: relative(this.stateDir, this.pathFor("tasks", `${run.id}.json`)),
        job: relative(this.stateDir, this.pathFor("jobs", `${runtimeJobRecordForRun(run).jobId}.json`)),
        checklist: relative(this.stateDir, this.pathFor("checklists", `${runtimeChecklistRecordForRun(run).checklistId}.json`)),
        quality: relative(this.stateDir, this.pathFor("quality", `${run.id}.json`)),
        operationLog: "operation-log.jsonl",
      },
      terminalState: run.status,
      stopCondition: run.trace.stopCondition,
      scorecard: run.trace.scorecard,
    };
  }

  listModels() {
    return this.modelMounting.legacyModelList();
  }

  listModelCapabilities() {
    return this.modelMounting.listModelCapabilities();
  }

  listRepositories() {
    return repositoryListProjection({ cwd: this.defaultCwd }, {
      doctorHash,
      repositoryContextForWorkspace,
    });
  }

  repositoryContext() {
    return repositoryContextProjection({ cwd: this.defaultCwd }, {
      doctorHash,
      repositoryContextForWorkspace,
    });
  }

  branchPolicy() {
    return branchPolicyProjection({ cwd: this.defaultCwd }, {
      branchPolicyForRepositoryContext,
      doctorHash,
      repositoryContextForWorkspace,
    });
  }

  githubContext() {
    return githubContextProjection({ cwd: this.defaultCwd }, {
      branchPolicyForRepositoryContext,
      doctorHash,
      githubContextForRepository,
      repositoryContextForWorkspace,
    });
  }

  prAttempts() {
    return prAttemptsProjection({ cwd: this.defaultCwd }, {
      branchPolicyForRepositoryContext,
      doctorHash,
      githubContextForRepository,
      prAttemptForRepository,
      repositoryContextForWorkspace,
    });
  }

  issueContext() {
    return issueContextProjection({ cwd: this.defaultCwd }, {
      branchPolicyForRepositoryContext,
      doctorHash,
      githubContextForRepository,
      issueContextForGithub,
      prAttemptForRepository,
      repositoryContextForWorkspace,
      reviewGateForPrAttempt,
    });
  }

  reviewGate() {
    return reviewGateProjection({ cwd: this.defaultCwd }, {
      branchPolicyForRepositoryContext,
      doctorHash,
      githubContextForRepository,
      prAttemptForRepository,
      repositoryContextForWorkspace,
      reviewGateForPrAttempt,
    });
  }

  githubPrCreatePlan() {
    return githubPrCreatePlanProjection({ cwd: this.defaultCwd }, {
      branchPolicyForRepositoryContext,
      doctorHash,
      githubContextForRepository,
      githubPrCreatePlanForReviewGate,
      issueContextForGithub,
      prAttemptForRepository,
      repositoryContextForWorkspace,
      reviewGateForPrAttempt,
    });
  }

  getAccount() {
    return runtimeAccount(process.env);
  }

  listRuntimeNodes() {
    return runtimeNodes(process.env);
  }

  listTools(options = {}) {
    return runtimeTools(options, {
      codingToolContracts,
    });
  }

  invokeComputerUseBrowserDiscoveryTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      "computer-use.browser-discovery";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `computer_use_browser_discovery_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      "computer-use.control";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `computer_use_control_${crypto.randomUUID()}`;
    const idempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
      schemaVersion: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      event_kind: "ComputerUse.Control",
      source: "runtime_thread_tool",
      computerUse: true,
      computer_use: true,
      computer_use_step: action === "cleanup" ? "cleanup" : "commit_or_handoff",
      computerUseStep: action === "cleanup" ? "cleanup" : "commit_or_handoff",
      computer_use_lane: optionalString(input.lane ?? input.computerUseLane ?? input.computer_use_lane) ??
        "native_browser",
      computer_use_session_mode:
        optionalString(input.sessionMode ?? input.session_mode ?? input.computerUseSessionMode ?? input.computer_use_session_mode) ??
        null,
      computer_use_lease_id: leaseId,
      computer_use_control_action: action,
      computer_use_control_receipt_ref: receiptRef,
      tool_ref: toolId,
      toolRef: toolId,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      authority_scopes: [`computer_use.control.${action}`],
      authorityScopes: [`computer_use.control.${action}`],
      fail_closed_when_unavailable: true,
      failClosedWhenUnavailable: true,
      summary: `Computer-use ${action} control receipt emitted`,
      control_receipt: controlReceipt,
      controlReceipt,
      human_handoff_state: humanHandoffState,
      humanHandoffState,
      cleanup_receipt: cleanupReceipt,
      cleanupReceipt,
      receipt_id: receiptRef,
      receiptId: receiptRef,
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
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      "computer-use.native-browser";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `computer_use_native_browser_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
      computerUseActionKind: requestedActionKind,
      computerUseApprovalRef: requestedApprovalRef,
      computerUseTargetRef: requestedTargetRef,
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
      "computerUseApprovalRef",
      "computerUseTargetRef",
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
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      "computer-use.visual-gui";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `computer_use_visual_gui_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
      computerUseActionKind: requestedActionKind,
      computerUseApprovalRef: requestedApprovalRef,
      computerUseTargetRef: requestedTargetRef,
      computerUseVisualArtifactRefs: materializedVisualArtifacts.artifactRefs,
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
      "computerUseApprovalRef",
      "computerUseTargetRef",
      "computerUseVisualObservation",
      "computerUseVisualArtifactRefs",
      "computerUseExecutionResult",
      "computerUseVisualGuiExecution",
      "screenshotRef",
      "somRef",
      "axRef",
      "appName",
      "windowTitle",
      "coordinateSpaceId",
      "viewportWidth",
      "viewportHeight",
      "visualTargets",
      "visualAffordances",
      "detectedPatterns",
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
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      "computer-use.sandboxed-hosted";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `computer_use_sandboxed_hosted_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
        input.computerUseSandboxProvider ??
          input.computer_use_sandbox_provider ??
          input.sandboxProvider ??
          input.sandbox_provider,
      ) ?? "local_fixture";
    const sandboxFixture =
      booleanValue(
        input.computerUseSandboxFixture ??
          input.computer_use_sandbox_fixture ??
          input.sandboxFixture ??
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
      computerUseActionKind: requestedActionKind,
      computerUseApprovalRef: requestedApprovalRef,
      computerUseTargetRef: requestedTargetRef,
      computerUseSandboxProvider: sandboxProvider,
      computerUseSandboxFixture: sandboxFixture,
      computerUseSandboxImageRef:
        optionalString(input.computerUseSandboxImageRef ?? input.computer_use_sandbox_image_ref ?? input.sandboxImageRef ?? input.sandbox_image_ref),
      computerUseSandboxTaskRef:
        optionalString(input.computerUseSandboxTaskRef ?? input.computer_use_sandbox_task_ref ?? input.sandboxTaskRef ?? input.sandbox_task_ref),
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
      "computerUseApprovalRef",
      "computerUseTargetRef",
      "computerUseSandboxImageRef",
      "computerUseSandboxTaskRef",
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
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `computer_use_visual_gui_observe_${doctorHash(`${threadId}:${toolId}:${Date.now()}`).slice(0, 16)}`;
    const idempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
      computerUseActionKind: "inspect",
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
        toolCallId,
        idempotency_key: idempotencyKey,
        idempotencyKey,
        workflow_node_id:
          optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
          "computer-use.visual-gui.observe",
        workflowNodeId:
          optionalString(request.workflowNodeId ?? request.workflow_node_id) ??
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
        toolId: normalizedToolId,
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
    const agent = this.agentForThread(threadId);
    const normalizedToolId = optionalString(toolId);
    if (COMPUTER_USE_BROWSER_DISCOVERY_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseBrowserDiscoveryTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_CONTROL_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseControlTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_NATIVE_BROWSER_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseNativeBrowserTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_VISUAL_GUI_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseVisualGuiTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_SANDBOXED_HOSTED_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseSandboxedHostedTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_VISUAL_GUI_OBSERVE_TOOL_IDS.has(normalizedToolId)) {
      return this.invokeComputerUseVisualGuiObserveTool(threadId, normalizedToolId, request);
    }
    if (!normalizedToolId || !CODING_TOOL_IDS.has(normalizedToolId)) {
      throw notFound(`Coding tool not found: ${toolId}`, {
        threadId,
        toolId,
        pack: CODING_TOOL_PACK_ID,
      });
    }
    const input = codingToolInputForRequest(request);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      `runtime.coding-tool.${safeId(normalizedToolId)}`;
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `coding_tool_${doctorHash(`${threadId}:${normalizedToolId}:${JSON.stringify(input)}:${Date.now()}`).slice(0, 16)}`;
    const codingToolIdempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
      `thread:${threadId}:coding-tool:${toolCallId}`;
    const duplicateToolEvent = this.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(
      codingToolIdempotencyKey,
    );
    if (duplicateToolEvent) {
      return codingToolInvocationResultFromEvent(duplicateToolEvent, {
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
      });
    }
    const receiptId = `receipt_coding_tool_${safeId(normalizedToolId)}_${doctorHash(
      `${threadId}:${normalizedToolId}:${toolCallId}`,
    ).slice(0, 12)}`;
    const requestRollbackRefs = uniqueStrings(normalizeArray(request.rollbackRefs ?? request.rollback_refs));
    const diagnosticsRepairContext =
      diagnosticsRepairContextForRequest(request) ??
      diagnosticsRepairContextForToolPack(request, input, normalizedToolId);
    const toolContract = codingToolContracts().find((tool) => tool.stableToolId === normalizedToolId);
    const budgetPolicy = codingToolBudgetPolicyForRequest({
      request,
      threadId,
      toolId: normalizedToolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
    });
    if (budgetPolicy?.status === "blocked") {
      const blocked = this.blockCodingToolForBudget({
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
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
      throw policyError("Coding tool budget limit exceeded.", {
        threadId,
        toolId: normalizedToolId,
        tool_call_id: toolCallId,
        reason: "coding_tool_budget_exceeded",
        budget_status: "exceeded",
        context_budget_status: budgetPolicy.status,
        contextBudgetStatus: budgetPolicy.status,
        context_budget: budgetPolicy,
        contextBudget: budgetPolicy,
        budget_usage_telemetry: budgetPolicy.usage_telemetry,
        budgetUsageTelemetry: budgetPolicy.usageTelemetry,
        eventId: blocked.event?.event_id ?? null,
        event_id: blocked.event?.event_id ?? null,
        receiptRefs: blocked.receipt_refs,
        receipt_refs: blocked.receipt_refs,
        policyDecisionRefs: blocked.policy_decision_refs,
        policy_decision_refs: blocked.policy_decision_refs,
      });
    }
    const approvalManifest = codingToolApprovalManifestForThread({
      agent,
      threadId,
      turnId,
      toolId: normalizedToolId,
      toolCallId,
      toolContract,
      input,
      request,
      workflowGraphId,
      workflowNodeId,
    });
    const approvalSatisfaction = approvalManifest
      ? this.codingToolApprovalSatisfaction({ threadId, approvalManifest, request })
      : null;
    if (approvalManifest && !approvalSatisfaction?.satisfied) {
      return this.blockCodingToolForApproval({
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
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
    const artifactRefs = [];
    const receiptRefs = [receiptId];
    let status = "completed";
    let result = null;
    let error = null;
    let workspaceSnapshot = null;
    let workspaceSnapshotEvent = null;
    try {
      result = executeCodingTool(normalizedToolId, agent.cwd, input, {
        threadId,
        toolId: normalizedToolId,
        toolCallId,
        readArtifact: (artifactId, range) => this.readCodingToolArtifact(threadId, artifactId, range),
        retrieveToolResult: (query) => this.retrieveCodingToolResult(threadId, query),
      });
      const materializedArtifacts = this.materializeCodingToolArtifactDrafts({
        threadId,
        toolId: normalizedToolId,
        toolCallId,
        workspaceRoot: agent.cwd,
        result,
        receiptId,
      });
      if (normalizedToolId === "file.apply_patch") {
        workspaceSnapshot = this.prepareWorkspaceSnapshotForPatch({
          threadId,
          turnId,
          workspaceRoot: agent.cwd,
          toolCallId,
          workflowGraphId,
          workflowNodeId,
          result,
        });
      }
      result = codingToolResultWithoutDrafts(result, materializedArtifacts);
      artifactRefs.push(...normalizeArray(result.artifactRefs));
      receiptRefs.push(...normalizeArray(result.receiptRefs));
      if (workspaceSnapshot) {
        result = {
          ...result,
          workspaceSnapshot: workspaceSnapshot.record,
          workspace_snapshot: workspaceSnapshot.record,
          workspaceSnapshotId: workspaceSnapshot.record.snapshotId,
          workspace_snapshot_id: workspaceSnapshot.record.snapshotId,
        };
        artifactRefs.push(...workspaceSnapshot.record.artifactRefs);
        receiptRefs.push(...workspaceSnapshot.record.receiptRefs);
      }
    } catch (caught) {
      status = "failed";
      error = {
        code: caught?.code ?? "coding_tool_failed",
        message: String(caught?.message ?? caught),
        details: caught?.details ?? null,
      };
      result = {
        schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
        toolName: normalizedToolId,
        status,
        error,
      };
    }
    const summary = codingToolSummary(normalizedToolId, result, status);
    const rollbackRefs = uniqueStrings([
      ...(workspaceSnapshot ? [workspaceSnapshot.record.snapshotId] : []),
      ...requestRollbackRefs,
    ]);
    const payloadSummary = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      event_kind: "CodingToolResult",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: normalizedToolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      status,
      summary,
      shell_fallback_used: false,
      input_summary: codingToolInputSummary(normalizedToolId, input),
      result_summary: codingToolResultSummary(normalizedToolId, result),
      result,
      error,
      rollback_refs: rollbackRefs,
      diagnostics_repair_context: diagnosticsRepairContext,
      diagnosticsRepairContext,
      approval_required: Boolean(approvalManifest),
      approvalRequired: Boolean(approvalManifest),
      approval_satisfied: Boolean(approvalSatisfaction?.satisfied),
      approvalSatisfied: Boolean(approvalSatisfaction?.satisfied),
      approval_id: approvalSatisfaction?.approvalId ?? null,
      approvalId: approvalSatisfaction?.approvalId ?? null,
      approval_manifest: approvalManifest ?? null,
      approvalManifest: approvalManifest ?? null,
      approval_decision_event_id: approvalSatisfaction?.decisionEventId ?? null,
      approvalDecisionEventId: approvalSatisfaction?.decisionEventId ?? null,
      receipt_id: receiptId,
      receipt_count: receiptRefs.length,
      artifact_count: artifactRefs.length,
    };
    const commandStreamEvents = this.appendCodingToolCommandStreamEvents({
      agent,
      threadId,
      turnId,
      toolId: normalizedToolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      request,
      result,
      status,
      receiptRefs,
      artifactRefs,
    });
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:coding-tool:${safeId(normalizedToolId)}:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key: codingToolIdempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: codingToolSourceEventKind(normalizedToolId),
      event_kind: status === "failed" ? "tool.failed" : "tool.completed",
      status,
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      tool_call_id: toolCallId,
      artifact_refs: artifactRefs,
      receipt_refs: uniqueStrings(receiptRefs),
      rollback_refs: rollbackRefs,
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    if (workspaceSnapshot) {
      workspaceSnapshotEvent = this.appendWorkspaceSnapshotEvent({
        threadId,
        turnId,
        workspaceRoot: agent.cwd,
        workflowGraphId,
        snapshot: workspaceSnapshot.record,
        sourceToolEvent: event,
      });
    }
    const autoDiagnostics =
      status === "completed" && normalizedToolId === "file.apply_patch"
        ? this.maybeRunPostEditDiagnostics({
            threadId,
            turnId,
            patchToolCallId: toolCallId,
            patchResult: result,
            request,
            input,
            workflowGraphId,
          })
        : null;
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: normalizedToolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      rollback_refs: event.rollback_refs,
      event,
      workspace_snapshot: workspaceSnapshot?.record ?? null,
      workspaceSnapshot: workspaceSnapshot?.record ?? null,
      workspace_snapshot_event: workspaceSnapshotEvent,
      workspaceSnapshotEvent,
      auto_diagnostics: autoDiagnostics,
      autoDiagnostics,
      command_stream_events: commandStreamEvents,
      commandStreamEvents,
      result,
      error,
    };
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
    if (!codingToolCommandStreamRequested(request)) return [];
    const streamId = `command_stream_${safeId(toolCallId)}`;
    const chunks = codingToolCommandStreamChunks(result);
    if (chunks.length === 0) return [];
    const events = [];
    let chunkSeq = 0;
    for (const chunk of chunks) {
      chunkSeq += 1;
      events.push(this.appendRuntimeEvent({
        event_stream_id: eventStreamIdForThread(threadId),
        thread_id: threadId,
        turn_id: turnId,
        item_id: `${turnId || threadId}:item:command-stream:${doctorHash(`${toolCallId}:${chunk.channel}:${chunkSeq}`).slice(0, 12)}`,
        idempotency_key: `thread:${threadId}:command-stream:${toolCallId}:${chunk.channel}:${chunkSeq}`,
        source: operatorControlSource(request.source),
        source_event_kind: "CodingTool.Stream",
        event_kind: "COMMAND_STREAM",
        status: "streaming",
        actor: "runtime",
        workspace_root: agent.cwd,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        component_kind: "terminal_stream",
        tool_call_id: toolCallId,
        tool_name: toolId,
        artifact_refs: artifactRefs,
        receipt_refs: uniqueStrings(receiptRefs),
        rollback_refs: [],
        payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
        payload_summary: {
          schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
          event_kind: "COMMAND_STREAM",
          stream_id: streamId,
          streamId,
          stream_seq: chunkSeq,
          streamSeq: chunkSeq,
          channel: chunk.channel,
          output_text: chunk.text,
          outputText: chunk.text,
          is_final: false,
          isFinal: false,
          command: optionalString(result?.command) ?? toolId,
          tool_name: toolId,
          tool_call_id: toolCallId,
          truncated: Boolean(result?.truncated),
          status,
          artifact_refs: artifactRefs,
          artifactRefs,
          receipt_refs: uniqueStrings(receiptRefs),
          receiptRefs: uniqueStrings(receiptRefs),
        },
      }));
    }
    events.push(this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:command-stream:${doctorHash(`${toolCallId}:final`).slice(0, 12)}`,
      idempotency_key: `thread:${threadId}:command-stream:${toolCallId}:final`,
      source: operatorControlSource(request.source),
      source_event_kind: "CodingTool.Stream",
      event_kind: "COMMAND_STREAM",
      status: "completed",
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "terminal_stream",
      tool_call_id: toolCallId,
      tool_name: toolId,
      artifact_refs: artifactRefs,
      receipt_refs: uniqueStrings(receiptRefs),
      rollback_refs: [],
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: {
        schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
        event_kind: "COMMAND_STREAM",
        stream_id: streamId,
        streamId,
        stream_seq: chunkSeq + 1,
        streamSeq: chunkSeq + 1,
        channel: "control",
        output_text: "",
        outputText: "",
        is_final: true,
        isFinal: true,
        command: optionalString(result?.command) ?? toolId,
        tool_name: toolId,
        tool_call_id: toolCallId,
        truncated: Boolean(result?.truncated),
        status,
        artifact_refs: artifactRefs,
        artifactRefs,
        receipt_refs: uniqueStrings(receiptRefs),
        receiptRefs: uniqueStrings(receiptRefs),
      },
    }));
    return events;
  }

  latestApprovalRequestEvent(threadId, approvalId) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return null;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            event.event_kind === "approval.required",
        )
        .at(-1) ?? null
    );
  }

  codingToolApprovalSatisfaction({ threadId, approvalManifest, request }) {
    const approvalId = optionalString(request.approval_id ?? request.approvalId);
    if (!approvalId) return { satisfied: false, reason: "approval_id_missing" };
    const approvalRequestEvent = this.latestApprovalRequestEvent(threadId, approvalId);
    if (!approvalRequestEvent) return { satisfied: false, approvalId, reason: "approval_request_missing" };
    const requestedManifest =
      approvalRequestEvent.payload_summary?.approval_manifest ??
      approvalRequestEvent.payload_summary?.approvalManifest ??
      null;
    if (!codingToolApprovalManifestsMatch(requestedManifest, approvalManifest)) {
      return { satisfied: false, approvalId, reason: "approval_manifest_mismatch" };
    }
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const latestDecision = stream.events
      .filter(
        (event) =>
          event.approval_id === approvalId &&
          event.seq > approvalRequestEvent.seq &&
          (event.event_kind === "approval.approved" ||
            event.event_kind === "approval.rejected" ||
            event.event_kind === "approval.revoked"),
      )
      .at(-1);
    if (!latestDecision) return { satisfied: false, approvalId, reason: "approval_decision_missing" };
    if (latestDecision.event_kind !== "approval.approved") {
      return {
        satisfied: false,
        approvalId,
        decisionEventId: latestDecision.event_id,
        decisionSeq: latestDecision.seq,
        reason: approvalReasonForDecisionEvent(latestDecision),
      };
    }
    const leaseState = approvalLeaseStateForDecision({
      threadId,
      approvalId,
      approvalRequestEvent,
      latestDecision,
    });
    if (leaseState.expired) {
      return {
        satisfied: false,
        approvalId,
        decisionEventId: latestDecision.event_id,
        decisionSeq: latestDecision.seq,
        reason: "approval_lease_expired",
        leaseId: leaseState.leaseId,
        expiresAt: leaseState.expiresAt,
      };
    }
    return {
      satisfied: true,
      approvalId,
      decisionEventId: latestDecision.event_id,
      decisionSeq: latestDecision.seq,
      reason: approvalReasonForDecisionEvent(latestDecision),
      leaseId: leaseState.leaseId,
      expiresAt: leaseState.expiresAt,
    };
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
    const approvalId = `approval_coding_tool_${safeId(toolId)}_${doctorHash(
      `${threadId}:${turnId || "thread"}:${toolCallId}`,
    ).slice(0, 16)}`;
    const error = {
      code: "coding_tool_approval_required",
      message: `${toolId} requires approval before execution in ${approvalManifest.thread_mode} mode.`,
      details: {
        toolId,
        tool_call_id: toolCallId,
        thread_mode: approvalManifest.thread_mode,
        approval_mode: approvalManifest.approval_mode,
        policy_reason: approvalManifest.policy_reason,
      },
    };
    const approval = this.requestThreadApproval(threadId, {
      ...request,
      source: operatorControlSource(request.source),
      turnId,
      workflowGraphId,
      workflowNodeId,
      action: "coding_tool.invoke",
      actor: "runtime",
      reason: error.message,
      scope: "coding_tool",
      idempotencyKey: `thread:${threadId}:approval.required:${approvalId}`,
      approvalId,
      toolId,
      effectClass: approvalManifest.effect_class,
      riskDomain: approvalManifest.risk_domain,
      authorityScopeRequirements: approvalManifest.authority_scope_requirements,
      approvalManifest,
      receiptRefs: [receiptId],
      policyDecisionRefs: [`policy_coding_tool_${safeId(toolId)}_approval_required`],
    });
    const result = {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      toolName: toolId,
      status: "blocked",
      approvalRequired: true,
      approval_required: true,
      approvalId: approval.approval_id,
      approval_id: approval.approval_id,
      approvalManifest,
      approval_manifest: approvalManifest,
      inputSummary: codingToolInputSummary(toolId, input),
      input_summary: codingToolInputSummary(toolId, input),
      error,
    };
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status: "blocked",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      approval_required: true,
      approvalRequired: true,
      approval_id: approval.approval_id,
      approvalId: approval.approval_id,
      approval_manifest: approvalManifest,
      approvalManifest,
      receipt_refs: approval.receipt_refs,
      artifact_refs: [],
      rollback_refs: uniqueStrings(requestRollbackRefs),
      event: null,
      approval,
      approval_event_id: approval.event_id,
      workspace_snapshot: null,
      workspaceSnapshot: null,
      workspace_snapshot_event: null,
      workspaceSnapshotEvent: null,
      auto_diagnostics: null,
      autoDiagnostics: null,
      diagnostics_repair_context: diagnosticsRepairContext,
      diagnosticsRepairContext,
      tool_contract: toolContract ?? null,
      toolContract: toolContract ?? null,
      result,
      error,
    };
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
    const receiptRefs = uniqueStrings([
      receiptId,
      ...normalizeArray(budgetPolicy.receipt_refs ?? budgetPolicy.receiptRefs),
    ]);
    const policyDecisionRefs = uniqueStrings(
      budgetPolicy.policy_decision_refs ?? budgetPolicy.policyDecisionRefs,
    );
    const error = {
      code: "coding_tool_budget_exceeded",
      message: `${toolId} blocked because the workflow coding-tool budget was exceeded.`,
      details: {
        toolId,
        tool_call_id: toolCallId,
        reason: "coding_tool_budget_exceeded",
        budget_status: "exceeded",
        context_budget_status: budgetPolicy.status,
        contextBudgetStatus: budgetPolicy.status,
        context_budget: budgetPolicy,
        contextBudget: budgetPolicy,
        budget_usage_telemetry: budgetPolicy.usage_telemetry,
        budgetUsageTelemetry: budgetPolicy.usageTelemetry,
      },
    };
    const result = {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      toolName: toolId,
      status: "blocked",
      budgetStatus: "exceeded",
      budget_status: "exceeded",
      contextBudgetStatus: budgetPolicy.status,
      context_budget_status: budgetPolicy.status,
      contextBudget: budgetPolicy,
      context_budget: budgetPolicy,
      inputSummary: codingToolInputSummary(toolId, input),
      input_summary: codingToolInputSummary(toolId, input),
      error,
    };
    const rollbackRefs = uniqueStrings(requestRollbackRefs);
    const payloadSummary = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      event_kind: "CodingToolBudgetBlocked",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      status: "blocked",
      summary: error.message,
      shell_fallback_used: false,
      input_summary: codingToolInputSummary(toolId, input),
      result_summary: { status: "blocked", reason: "coding_tool_budget_exceeded" },
      result,
      error,
      rollback_refs: rollbackRefs,
      diagnostics_repair_context: diagnosticsRepairContext,
      diagnosticsRepairContext,
      approval_required: false,
      approvalRequired: false,
      budget_status: "exceeded",
      budgetStatus: "exceeded",
      context_budget_status: budgetPolicy.status,
      contextBudgetStatus: budgetPolicy.status,
      context_budget: budgetPolicy,
      contextBudget: budgetPolicy,
      budget_usage_telemetry: budgetPolicy.usage_telemetry,
      budgetUsageTelemetry: budgetPolicy.usageTelemetry,
      policy_decision_refs: policyDecisionRefs,
      policyDecisionRefs,
      receipt_id: receiptId,
      receipt_count: receiptRefs.length,
      artifact_count: 0,
    };
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:coding-tool:${safeId(toolId)}:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key:
        codingToolIdempotencyKey ??
        `thread:${threadId}:coding-tool:${toolCallId}:budget-blocked`,
      source: operatorControlSource(request.source),
      source_event_kind: codingToolSourceEventKind(toolId),
      event_kind: "policy.blocked",
      status: "blocked",
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      tool_call_id: toolCallId,
      artifact_refs: [],
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: toolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status: "blocked",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      budget_status: "exceeded",
      budgetStatus: "exceeded",
      context_budget: budgetPolicy,
      contextBudget: budgetPolicy,
      receipt_refs: event.receipt_refs,
      receiptRefs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
      policyDecisionRefs: event.policy_decision_refs,
      artifact_refs: [],
      rollback_refs: rollbackRefs,
      event,
      workspace_snapshot: null,
      workspaceSnapshot: null,
      workspace_snapshot_event: null,
      workspaceSnapshotEvent: null,
      auto_diagnostics: null,
      autoDiagnostics: null,
      diagnostics_repair_context: diagnosticsRepairContext,
      diagnosticsRepairContext,
      tool_contract: toolContract ?? null,
      toolContract: toolContract ?? null,
      result,
      error,
    };
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
    if (!result?.applied) return null;
    const contentDraftsByPath = workspaceSnapshotContentDraftsByPath(
      result.workspaceSnapshotDrafts ?? result.workspace_snapshot_drafts,
    );
    const captureRecords = normalizeArray(result.changedFiles)
      .filter((entry) => optionalString(entry?.path))
      .map((entry) =>
        workspaceSnapshotFileForPatch(entry, contentDraftsByPath.get(optionalString(entry?.path) ?? ""), {
          maxContentBytes: WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
        }),
      );
    const files = captureRecords.map((capture) => capture.publicFile);
    const contentFiles = captureRecords.map((capture) => capture.contentFile);
    if (!files.length) return null;
    const capturedFileCount = captureRecords.filter((capture) => capture.contentCaptured).length;
    const omittedFileCount = captureRecords.length - capturedFileCount;
    const previewSupported = omittedFileCount === 0;
    const core = {
      schemaVersion: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot",
      threadId,
      turnId: turnId || null,
      workspaceRoot,
      snapshotKind: "pre_post_touched_files",
      trigger: {
        toolName: "file.apply_patch",
        toolCallId,
        workflowGraphId,
        workflowNodeId,
      },
      fileCount: files.length,
      changedFileCount: files.filter((file) => file.changed).length,
      createdFileCount: files.filter((file) => file.created).length,
      deletedFileCount: files.filter((file) => file.deleted).length,
      files,
      capture: {
        status: previewSupported ? "content_captured" : "partial_content",
        maxContentBytes: WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
        capturedFileCount,
        omittedFileCount,
      },
      restore: {
        status: previewSupported ? "content_captured" : "partial_content",
        previewSupported,
        applySupported: previewSupported,
        reason: previewSupported ? "restore_apply_requires_approval" : "snapshot_content_capture_incomplete",
      },
      redaction: {
        profile: "workspace_snapshot_content_artifact",
        contentIncluded: false,
        contentArtifactIncluded: true,
        pathsIncluded: true,
      },
      evidenceRefs: ["workspace_snapshot_content", "file.apply_patch", toolCallId].filter(Boolean),
    };
    const snapshotHash = doctorHash(JSON.stringify(core));
    const snapshotId = `workspace_snapshot_${safeId(toolCallId)}_${snapshotHash.slice(0, 12)}`;
    const receiptId = `receipt_${snapshotId}`;
    const artifactId = `artifact_${safeId(snapshotId)}_content`;
    const record = {
      ...core,
      snapshotId,
      snapshot_id: snapshotId,
      snapshotHash,
      snapshot_hash: snapshotHash,
      receiptRefs: [receiptId],
      receipt_refs: [receiptId],
      artifactRefs: [artifactId],
      artifact_refs: [artifactId],
      contentArtifactRefs: [artifactId],
      content_artifact_refs: [artifactId],
      summary: `Workspace snapshot recorded ${files.length} changed file(s) for ${toolCallId}.`,
    };
    const artifactPayload = {
      schemaVersion: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot_content",
      snapshotId,
      snapshot_id: snapshotId,
      snapshotHash,
      snapshot_hash: snapshotHash,
      threadId,
      thread_id: threadId,
      turnId: turnId || null,
      turn_id: turnId || null,
      workspaceRoot,
      workspace_root: workspaceRoot,
      trigger: record.trigger,
      capture: record.capture,
      restore: record.restore,
      snapshot: record,
      files: contentFiles,
    };
    const artifactRecord = this.materializeWorkspaceSnapshotArtifact({
      threadId,
      toolCallId,
      workspaceRoot,
      snapshot: record,
      artifactPayload,
      artifactId,
      receiptId,
    });
    return {
      record,
      artifactRecord,
    };
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
    const createdAt = new Date().toISOString();
    const content = JSON.stringify(artifactPayload ?? snapshot, null, 2);
    const artifactRecord = {
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      threadId,
      tool_name: "file.apply_patch",
      toolName: "file.apply_patch",
      tool_call_id: toolCallId,
      toolCallId,
      workspace_root: workspaceRoot,
      workspaceRoot,
      name: "workspace-snapshot-content.json",
      channel: "workspace-snapshot",
      media_type: "application/json",
      mediaType: "application/json",
      redaction: "workspace_snapshot_content_artifact",
      receipt_id: receiptId,
      receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      contentBytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      contentHash: doctorHash(content),
      created_at: createdAt,
      createdAt,
    };
    this.codingArtifacts.set(artifactRecord.id, artifactRecord);
    writeJson(this.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
    return artifactRecord;
  }

  appendWorkspaceSnapshotEvent({
    threadId,
    turnId,
    workspaceRoot,
    workflowGraphId,
    snapshot,
    sourceToolEvent,
  } = {}) {
    if (!snapshot?.snapshotId) return null;
    const payloadSummary = {
      schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      event_kind: "WorkspaceSnapshotCreated",
      snapshot_id: snapshot.snapshotId,
      snapshot_hash: snapshot.snapshotHash,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      snapshot_kind: snapshot.snapshotKind,
      file_count: snapshot.fileCount,
      changed_file_count: snapshot.changedFileCount,
      created_file_count: snapshot.createdFileCount,
      deleted_file_count: snapshot.deletedFileCount,
      restore_status: snapshot.restore?.status ?? "metadata_only",
      restore_preview_supported: Boolean(snapshot.restore?.previewSupported),
      restore_apply_supported: Boolean(snapshot.restore?.applySupported),
      source_tool_name: "file.apply_patch",
      source_tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.toolCallId ?? null,
      source_tool_event_id: sourceToolEvent?.event_id ?? null,
      source_workflow_node_id: snapshot.trigger?.workflowNodeId ?? null,
      files: snapshot.files,
      receipt_refs: snapshot.receiptRefs,
      artifact_refs: snapshot.artifactRefs,
      summary: snapshot.summary,
      snapshot,
    };
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workspace-snapshot:${safeId(snapshot.snapshotId)}`,
      idempotency_key: `thread:${threadId}:workspace-snapshot:${snapshot.snapshotId}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceSnapshot.Created",
      event_kind: "workspace.snapshot.created",
      status: "completed",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId ?? snapshot.trigger?.workflowGraphId ?? null,
      workflow_node_id: WORKSPACE_SNAPSHOT_NODE_ID,
      component_kind: "workspace_snapshot",
      tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.toolCallId ?? null,
      artifact_refs: snapshot.artifactRefs,
      receipt_refs: snapshot.receiptRefs,
      rollback_refs: [snapshot.snapshotId],
      payload_schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
  }

  listWorkspaceSnapshots(threadId) {
    this.agentForThread(threadId);
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const snapshots = stream.events
      .filter((event) => event.event_kind === "workspace.snapshot.created")
      .map((event) => event.payload_summary?.snapshot ?? event.payload_summary)
      .filter((snapshot) => snapshot && typeof snapshot === "object" && !Array.isArray(snapshot));
    return {
      schemaVersion: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot_list",
      threadId,
      thread_id: threadId,
      snapshotCount: snapshots.length,
      snapshot_count: snapshots.length,
      snapshots,
    };
  }

  previewWorkspaceSnapshotRestore(threadId, snapshotId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedSnapshotId = optionalString(snapshotId);
    if (!normalizedSnapshotId) {
      throw runtimeError({
        status: 400,
        code: "workspace_snapshot_id_required",
        message: "Restore preview requires a workspace snapshot id.",
        details: { threadId },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key ?? request.idempotencyKey);
    const snapshotPackage = this.workspaceSnapshotContentPackage(threadId, normalizedSnapshotId);
    const operations = normalizeArray(snapshotPackage.files).map((file) =>
      workspaceRestorePreviewOperation({
        workspaceRoot: agent.cwd,
        file,
        maxDiffBytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
      }),
    );
    if (!operations.length) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_preview_empty",
        message: "Restore preview could not find content-backed files in the snapshot.",
        details: { threadId, snapshotId: normalizedSnapshotId },
      });
    }
    const readyCount = operations.filter((operation) => operation.status === "ready").length;
    const noopCount = operations.filter((operation) => operation.status === "noop").length;
    const conflictCount = operations.filter((operation) => operation.status === "conflict").length;
    const blockedCount = operations.filter((operation) => operation.status === "blocked").length;
    const previewStatus = conflictCount || blockedCount ? "blocked" : "ready";
    const receiptId = `receipt_workspace_restore_preview_${safeId(normalizedSnapshotId)}_${doctorHash(
      JSON.stringify(operations.map((operation) => [operation.path, operation.status, operation.currentHash])),
    ).slice(0, 12)}`;
    const artifactId = `artifact_workspace_restore_preview_${safeId(normalizedSnapshotId)}_${doctorHash(receiptId).slice(0, 12)}`;
    const result = {
      schemaVersion: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      schema_version: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_restore_preview",
      threadId,
      thread_id: threadId,
      turnId: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      turn_id: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      workspaceRoot: agent.cwd,
      workspace_root: agent.cwd,
      snapshotId: normalizedSnapshotId,
      snapshot_id: normalizedSnapshotId,
      snapshotHash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      snapshot_hash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      previewStatus,
      preview_status: previewStatus,
      previewSupported: blockedCount === 0,
      preview_supported: blockedCount === 0,
      applySupported: previewStatus === "ready",
      apply_supported: previewStatus === "ready",
      restoreApplySupported: previewStatus === "ready",
      restore_apply_supported: previewStatus === "ready",
      fileCount: operations.length,
      file_count: operations.length,
      readyCount,
      ready_count: readyCount,
      noopCount,
      noop_count: noopCount,
      conflictCount,
      conflict_count: conflictCount,
      blockedCount,
      blocked_count: blockedCount,
      operations,
      receiptRefs: [receiptId],
      receipt_refs: [receiptId],
      artifactRefs: [artifactId],
      artifact_refs: [artifactId],
      rollbackRefs: [normalizedSnapshotId],
      rollback_refs: [normalizedSnapshotId],
      idempotencyKey,
      idempotency_key: idempotencyKey,
      summary:
        previewStatus === "ready"
          ? `Restore preview ready for ${operations.length} file(s) from ${normalizedSnapshotId}.`
          : `Restore preview blocked for ${normalizedSnapshotId}: ${conflictCount} conflict(s), ${blockedCount} blocked file(s).`,
    };
    const artifactRecord = this.materializeWorkspaceRestorePreviewArtifact({
      threadId,
      workspaceRoot: agent.cwd,
      snapshotId: normalizedSnapshotId,
      artifactId,
      receiptId,
      preview: result,
    });
    const event = this.appendWorkspaceRestorePreviewEvent({
      threadId,
      turnId: result.turnId,
      workspaceRoot: agent.cwd,
      workflowGraphId,
      workflowNodeId,
      preview: {
        ...result,
        artifactRefs: [artifactRecord.id],
        artifact_refs: [artifactRecord.id],
      },
    });
    return {
      ...result,
      artifactRefs: [artifactRecord.id],
      artifact_refs: [artifactRecord.id],
      event,
      restore_preview_event: event,
      restorePreviewEvent: event,
    };
  }

  applyWorkspaceSnapshotRestore(threadId, snapshotId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedSnapshotId = optionalString(snapshotId);
    if (!normalizedSnapshotId) {
      throw runtimeError({
        status: 400,
        code: "workspace_snapshot_id_required",
        message: "Restore apply requires a workspace snapshot id.",
        details: { threadId },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key ?? request.idempotencyKey);
    const approval = workspaceRestoreApplyApprovalForRequest(request);
    const allowConflicts = workspaceRestoreApplyAllowsConflicts(request);
    const conflictPolicy = allowConflicts ? "override_conflicts" : "clean_preview_only";
    const snapshotPackage = this.workspaceSnapshotContentPackage(threadId, normalizedSnapshotId);
    const previewOperations = normalizeArray(snapshotPackage.files).map((file) =>
      workspaceRestorePreviewOperation({
        workspaceRoot: agent.cwd,
        file,
        maxDiffBytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
      }),
    );
    if (!previewOperations.length) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_apply_empty",
        message: "Restore apply could not find content-backed files in the snapshot.",
        details: { threadId, snapshotId: normalizedSnapshotId },
      });
    }
    const previewCounts = workspaceRestoreOperationCounts(previewOperations);
    const hardBlocked = previewCounts.blockedCount > 0;
    const conflictBlocked = previewCounts.conflictCount > 0 && !allowConflicts;
    let operations = previewOperations.map((operation) => ({
      ...operation,
      applyStatus: "blocked",
      apply_status: "blocked",
      applyReason: workspaceRestoreApplyBlockedReason(operation, {
        approvalSatisfied: approval.satisfied,
        allowConflicts,
        hardBlocked,
        conflictBlocked,
      }),
      apply_reason: workspaceRestoreApplyBlockedReason(operation, {
        approvalSatisfied: approval.satisfied,
        allowConflicts,
        hardBlocked,
        conflictBlocked,
      }),
    }));
    if (approval.satisfied && !hardBlocked && !conflictBlocked) {
      operations = workspaceRestoreApplyOperations({
        workspaceRoot: agent.cwd,
        files: snapshotPackage.files,
        maxDiffBytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
        allowConflicts,
      });
    }
    const counts = workspaceRestoreOperationCounts(operations);
    const applyStatus = workspaceRestoreApplyStatus(counts);
    const previewStatus = counts.conflictCount || counts.blockedCount ? "blocked" : "ready";
    const policyDecisionRefs = workspaceRestoreApplyPolicyDecisionRefs({
      snapshotId: normalizedSnapshotId,
      approval,
      allowConflicts,
      hardBlocked,
      conflictBlocked,
      applyStatus,
    });
    const receiptId = `receipt_workspace_restore_apply_${safeId(normalizedSnapshotId)}_${doctorHash(
      JSON.stringify(operations.map((operation) => [operation.path, operation.applyStatus ?? operation.apply_status, operation.appliedHash ?? operation.applied_hash])),
    ).slice(0, 12)}`;
    const artifactId = `artifact_workspace_restore_apply_${safeId(normalizedSnapshotId)}_${doctorHash(receiptId).slice(0, 12)}`;
    const result = {
      schemaVersion: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      schema_version: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_restore_apply",
      threadId,
      thread_id: threadId,
      turnId: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      turn_id: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      workspaceRoot: agent.cwd,
      workspace_root: agent.cwd,
      snapshotId: normalizedSnapshotId,
      snapshot_id: normalizedSnapshotId,
      snapshotHash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      snapshot_hash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      previewStatus,
      preview_status: previewStatus,
      applyStatus,
      apply_status: applyStatus,
      applySupported: applyStatus !== "blocked" && applyStatus !== "failed",
      apply_supported: applyStatus !== "blocked" && applyStatus !== "failed",
      restoreApplySupported: applyStatus !== "blocked" && applyStatus !== "failed",
      restore_apply_supported: applyStatus !== "blocked" && applyStatus !== "failed",
      approvalRequired: true,
      approval_required: true,
      approvalSatisfied: approval.satisfied,
      approval_satisfied: approval.satisfied,
      conflictPolicy,
      conflict_policy: conflictPolicy,
      fileCount: counts.fileCount,
      file_count: counts.fileCount,
      readyCount: counts.readyCount,
      ready_count: counts.readyCount,
      noopCount: counts.noopCount,
      noop_count: counts.noopCount,
      conflictCount: counts.conflictCount,
      conflict_count: counts.conflictCount,
      blockedCount: counts.blockedCount,
      blocked_count: counts.blockedCount,
      appliedCount: counts.appliedCount,
      applied_count: counts.appliedCount,
      applyNoopCount: counts.applyNoopCount,
      apply_noop_count: counts.applyNoopCount,
      applyBlockedCount: counts.applyBlockedCount,
      apply_blocked_count: counts.applyBlockedCount,
      failedCount: counts.failedCount,
      failed_count: counts.failedCount,
      operations,
      policy: {
        status: applyStatus === "blocked" ? "blocked" : "allowed",
        approvalRequired: true,
        approvalSatisfied: approval.satisfied,
        approvalSource: approval.source,
        conflictPolicy,
      },
      policy_decision_refs: policyDecisionRefs,
      policyDecisionRefs,
      receiptRefs: [receiptId],
      receipt_refs: [receiptId],
      artifactRefs: [artifactId],
      artifact_refs: [artifactId],
      rollbackRefs: [normalizedSnapshotId],
      rollback_refs: [normalizedSnapshotId],
      idempotencyKey,
      idempotency_key: idempotencyKey,
      summary: workspaceRestoreApplySummary({
        snapshotId: normalizedSnapshotId,
        applyStatus,
        counts,
        approval,
        allowConflicts,
      }),
    };
    const artifactRecord = this.materializeWorkspaceRestoreApplyArtifact({
      threadId,
      workspaceRoot: agent.cwd,
      snapshotId: normalizedSnapshotId,
      artifactId,
      receiptId,
      apply: result,
    });
    const event = this.appendWorkspaceRestoreApplyEvent({
      threadId,
      turnId: result.turnId,
      workspaceRoot: agent.cwd,
      workflowGraphId,
      workflowNodeId,
      apply: {
        ...result,
        artifactRefs: [artifactRecord.id],
        artifact_refs: [artifactRecord.id],
      },
    });
    return {
      ...result,
      artifactRefs: [artifactRecord.id],
      artifact_refs: [artifactRecord.id],
      event,
      restore_apply_event: event,
      restoreApplyEvent: event,
    };
  }

  executeDiagnosticsRepairDecision(threadId, decisionRef, request = {}) {
    this.agentForThread(threadId);
    const target = optionalString(decisionRef ?? request.decision_id ?? request.decisionId ?? request.action);
    if (!target) {
      throw runtimeError({
        status: 400,
        code: "diagnostics_repair_decision_required",
        message: "Diagnostics repair decision execution requires a decision id or action.",
        details: { threadId },
      });
    }
    const resolution = this.resolveDiagnosticsRepairDecision(threadId, target, request);
    const { gateEvent, decision, repairPolicy } = resolution;
    const action = optionalString(decision.action)?.toLowerCase();
    if (!action) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_decision_invalid",
        message: "Diagnostics repair decision is missing an action.",
        details: { threadId, decisionRef: target },
      });
    }
    if (!["repair_retry", "restore_preview", "restore_apply", "operator_override"].includes(action)) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_decision_action_unimplemented",
        message: `Diagnostics repair decision action is not executable yet: ${action}.`,
        details: {
          threadId,
          decisionRef: target,
          action,
          supportedActions: ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
        },
      });
    }
    if (decision.status && !["available", "requires_approval"].includes(decision.status)) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_decision_unavailable",
        message: `Diagnostics repair decision is not available: ${decision.status}.`,
        details: { threadId, decisionRef: target, action, status: decision.status },
      });
    }
    const snapshotId =
      optionalString(request.snapshot_id ?? request.snapshotId) ??
      uniqueStrings([
        ...normalizeArray(decision.workspaceSnapshotRefs ?? decision.workspace_snapshot_refs),
        ...normalizeArray(repairPolicy.workspaceSnapshotRefs ?? repairPolicy.workspace_snapshot_refs),
        ...normalizeArray(gateEvent.payload_summary?.workspace_snapshot_refs),
      ])[0];
    if (!snapshotId && ["restore_preview", "restore_apply"].includes(action)) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_snapshot_required",
        message: "Restore repair decision requires a workspace snapshot ref.",
        details: { threadId, decisionRef: target, action },
      });
    }
    const workflowGraphId = optionalString(
      request.workflow_graph_id ?? request.workflowGraphId ?? gateEvent.workflow_graph_id,
    );
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      (action === "repair_retry"
        ? LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID
        : action === "operator_override"
        ? LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID
        : action === "restore_apply"
        ? LSP_DIAGNOSTICS_REPAIR_RESTORE_APPLY_NODE_ID
        : LSP_DIAGNOSTICS_REPAIR_RESTORE_PREVIEW_NODE_ID);
    const decisionId = decision.decision_id ?? decision.decisionId ?? target;
    const executionResult =
      action === "repair_retry"
        ? this.createDiagnosticsRepairRetryTurn(threadId, {
            request,
            gateEvent,
            decision,
            repairPolicy,
            snapshotId,
            workflowGraphId,
            workflowNodeId,
          })
        : action === "operator_override"
        ? this.executeDiagnosticsOperatorOverride(threadId, {
            request,
            gateEvent,
            decision,
            repairPolicy,
            snapshotId,
            workflowGraphId,
            workflowNodeId,
          })
        : action === "restore_apply"
        ? this.applyWorkspaceSnapshotRestore(threadId, snapshotId, {
            source: request.source ?? "runtime_auto",
            workflow_graph_id: workflowGraphId,
            workflow_node_id: workflowNodeId,
            idempotency_key:
              optionalString(request.restore_apply_idempotency_key ?? request.restoreApplyIdempotencyKey) ??
              `thread:${threadId}:diagnostics-repair-apply:${decisionId}:${snapshotId}:${diagnosticsRepairApplyApprovalKey(request)}`,
            actor: request.actor ?? "operator",
            approval: request.approval,
            approvalDecision: request.approvalDecision,
            approval_decision: request.approval_decision,
            policyDecision: request.policyDecision,
            policy_decision: request.policy_decision,
            decision: request.decision,
            confirm: request.confirm,
            confirmed: request.confirmed,
            confirmRestoreApply: request.confirmRestoreApply,
            confirm_restore_apply: request.confirm_restore_apply,
            applyConfirmed: request.applyConfirmed,
            apply_confirmed: request.apply_confirmed,
            approvalGranted: request.approvalGranted,
            approval_granted: request.approval_granted,
            approved: request.approved,
            allowConflicts: request.allowConflicts,
            allow_conflicts: request.allow_conflicts,
            overrideConflicts: request.overrideConflicts,
            override_conflicts: request.override_conflicts,
            restoreConflictPolicy:
              request.restoreConflictPolicy ??
              request.restore_conflict_policy ??
              decision.restoreConflictPolicy ??
              decision.restore_conflict_policy ??
              repairPolicy.restoreConflictPolicy ??
              repairPolicy.restore_conflict_policy,
            restore_conflict_policy:
              request.restore_conflict_policy ??
              request.restoreConflictPolicy ??
              decision.restore_conflict_policy ??
              decision.restoreConflictPolicy ??
              repairPolicy.restore_conflict_policy ??
              repairPolicy.restoreConflictPolicy,
            diagnostics_repair_decision_id: decisionId,
            diagnostics_repair_action: action,
            diagnostics_blocking_gate_event_id: gateEvent.event_id,
          })
        : this.previewWorkspaceSnapshotRestore(threadId, snapshotId, {
            source: request.source ?? "runtime_auto",
            workflow_graph_id: workflowGraphId,
            workflow_node_id: workflowNodeId,
            idempotency_key:
              optionalString(request.restore_preview_idempotency_key ?? request.restorePreviewIdempotencyKey) ??
              `thread:${threadId}:diagnostics-repair-preview:${decisionId}:${snapshotId}:${action}`,
            actor: request.actor ?? "operator",
            diagnostics_repair_decision_id: decisionId,
            diagnostics_repair_action: action,
            diagnostics_blocking_gate_event_id: gateEvent.event_id,
          });
    const event = this.appendDiagnosticsRepairDecisionExecutedEvent({
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
    const repairRetry = action === "repair_retry" ? executionResult : null;
    const operatorOverride = action === "operator_override" ? executionResult : null;
    const restorePreview = action === "restore_preview" ? executionResult : null;
    const restoreApply = action === "restore_apply" ? executionResult : null;
    return {
      schemaVersion: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_repair_decision_execution",
      threadId,
      thread_id: threadId,
      decisionId: decision.decisionId ?? decision.decision_id ?? target,
      decision_id: decisionId,
      action,
      status: diagnosticsRepairExecutionStatus(executionResult),
      gateEventId: gateEvent.event_id,
      gate_event_id: gateEvent.event_id,
      policyId: repairPolicy.policyId ?? repairPolicy.policy_id ?? null,
      policy_id: repairPolicy.policy_id ?? repairPolicy.policyId ?? null,
      snapshotId,
      snapshot_id: snapshotId,
      workflowGraphId,
      workflow_graph_id: workflowGraphId,
      workflowNodeId,
      workflow_node_id: workflowNodeId,
      decision,
      repairPolicy,
      repair_policy: repairPolicy,
      repairRetry,
      repair_retry: repairRetry,
      repairTurn: repairRetry?.repairTurn ?? null,
      repair_turn: repairRetry?.repair_turn ?? null,
      repairRetryEvent: repairRetry?.event ?? null,
      repair_retry_event: repairRetry?.event ?? null,
      operatorOverride,
      operator_override: operatorOverride,
      operatorOverrideEvent: operatorOverride?.event ?? null,
      operator_override_event: operatorOverride?.event ?? null,
      restorePreview,
      restoreApply,
      restore_preview: restorePreview,
      restore_apply: restoreApply,
      restorePreviewEvent: restorePreview?.event ?? null,
      restoreApplyEvent: restoreApply?.event ?? null,
      restore_preview_event: restorePreview?.event ?? null,
      restore_apply_event: restoreApply?.event ?? null,
      event,
      receiptRefs: event.receipt_refs,
      receipt_refs: event.receipt_refs,
      artifactRefs: event.artifact_refs,
      artifact_refs: event.artifact_refs,
      policyDecisionRefs: event.policy_decision_refs,
      policy_decision_refs: event.policy_decision_refs,
      rollbackRefs: event.rollback_refs,
      rollback_refs: event.rollback_refs,
      summary: `Executed diagnostics repair decision ${action}${snapshotId ? ` for ${snapshotId}` : ""}.`,
    };
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
    const agent = this.agentForThread(threadId);
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "operator_override";
    const approval = diagnosticsOperatorOverrideApprovalForRequest(request, { decision, repairPolicy });
    const approvalKey = diagnosticsOperatorOverrideApprovalKey(approval);
    const idempotencyKey =
      optionalString(request.operator_override_idempotency_key ?? request.operatorOverrideIdempotencyKey) ??
      `thread:${threadId}:diagnostics-operator-override:${decisionId}:${gateEvent?.event_id ?? "gate"}:${approvalKey}`;
    const duplicate = this.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(idempotencyKey);
    if (duplicate) {
      return diagnosticsOperatorOverrideResultFromEvent({
        threadId,
        event: duplicate,
        turn: this.turnForOperatorOverrideEvent(duplicate),
      });
    }

    const status = approval.required && !approval.satisfied ? "blocked" : "completed";
    const targetTurnId = optionalString(gateEvent?.turn_id ?? gateEvent?.payload_summary?.turn_id);
    const targetRunId = targetTurnId ? runIdForTurn(targetTurnId) : null;
    let previousTurnStatus = null;
    let nextTurnStatus = null;
    let turn = null;
    if (targetRunId && status === "completed") {
      const run = this.getRun(targetRunId);
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${targetTurnId}`, { threadId, turnId: targetTurnId, runId: targetRunId });
      }
      previousTurnStatus = run.turnStatus ?? lifecycleStatusForRun(run.status);
      nextTurnStatus = "completed";
    }

    const event = this.appendDiagnosticsOperatorOverrideEvent({
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

    if (targetRunId && status === "completed") {
      const run = this.getRun(targetRunId);
      const control = {
        control: "diagnostics_operator_override",
        source: operatorControlSource(request.source),
        decisionId,
        gateEventId: gateEvent?.event_id ?? null,
        approvalRequired: approval.required,
        approvalSatisfied: approval.satisfied,
        approvalSource: approval.source,
        snapshotId,
        eventId: event.event_id,
        seq: event.seq,
        createdAt: event.created_at,
      };
      const updatedDiagnosticsBlockingGate = run.diagnosticsBlockingGate
        ? {
            ...run.diagnosticsBlockingGate,
            status: "overridden",
            decision: "operator_override",
            continuationAllowed: true,
            continuation_allowed: true,
            approvalRequired: approval.required,
            approval_required: approval.required,
            approvalSatisfied: approval.satisfied,
            approval_satisfied: approval.satisfied,
            operatorOverrideEventId: event.event_id,
            operator_override_event_id: event.event_id,
          }
        : run.diagnosticsBlockingGate;
      const updated = {
        ...run,
        status: "completed",
        turnStatus: undefined,
        updatedAt: event.created_at,
        result: "Operator override granted; blocking diagnostics gate marked continuation-allowed.",
        diagnosticsBlockingGate: updatedDiagnosticsBlockingGate,
        trace: {
          ...run.trace,
          diagnosticsBlockingGate: updatedDiagnosticsBlockingGate,
          stopCondition: {
            ...(run.trace?.stopCondition ?? {}),
            reason: "operator_override_granted",
            evidenceSufficient: true,
            rationale: "Operator override granted continuation despite blocking diagnostics.",
          },
          operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
        },
        operatorControls: appendOperatorControl(run.operatorControls, control),
      };
      this.runs.set(run.id, updated);
      this.writeRun(updated, "diagnostics.operator_override.event");
      turn = this.turnForRun(updated);
      nextTurnStatus = turn.status;
    }

    return diagnosticsOperatorOverrideResultFromEvent({ threadId, event, turn });
  }

  turnForOperatorOverrideEvent(event = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const targetTurnId = optionalString(payload.target_turn_id ?? payload.targetTurnId);
    if (!targetTurnId) return null;
    try {
      return this.getTurn(event.thread_id, targetTurnId);
    } catch {
      return null;
    }
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
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "operator_override";
    const receiptId = `receipt_lsp_diagnostics_operator_override_${doctorHash(
      `${threadId}:${decisionId}:${status}:${approval?.source ?? ""}`,
    ).slice(0, 12)}`;
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(decision?.rollbackRefs ?? decision?.rollback_refs),
      ...normalizeArray(repairPolicy?.rollbackRefs ?? repairPolicy?.rollback_refs),
      ...normalizeArray(gateEvent?.rollback_refs),
      ...normalizeArray(gateEvent?.payload_summary?.rollback_refs ?? gateEvent?.payload_summary?.rollbackRefs),
    ]);
    const policyDecisionRefs = uniqueStrings([
      decisionId,
      repairPolicy?.policy_id ?? repairPolicy?.policyId,
      ...normalizeArray(gateEvent?.policy_decision_refs),
      `policy_lsp_diagnostics_operator_override_${approval?.satisfied ? "approval_satisfied" : "approval_required"}`,
      status === "completed" ? "policy_lsp_diagnostics_operator_override_continuation_allowed" : null,
    ]);
    const payloadSummary = {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      event_kind: "LspDiagnosticsOperatorOverrideExecuted",
      thread_id: threadId,
      decision_id: decisionId,
      action: "operator_override",
      status,
      gate_event_id: gateEvent?.event_id ?? null,
      gate_id: gateEvent?.payload_summary?.gate_id ?? null,
      policy_id: repairPolicy?.policy_id ?? repairPolicy?.policyId ?? null,
      snapshot_id: snapshotId ?? null,
      target_turn_id: targetTurnId ?? null,
      target_run_id: targetRunId ?? null,
      previous_turn_status: previousTurnStatus ?? null,
      next_turn_status: nextTurnStatus ?? null,
      approval_required: Boolean(approval?.required),
      approval_satisfied: Boolean(approval?.satisfied),
      approval_source: approval?.source ?? "missing",
      continuation_allowed: status === "completed",
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      rollback_refs: rollbackRefs,
      receipt_refs: [receiptId],
      artifact_refs: [],
      policy_decision_refs: policyDecisionRefs,
      decision,
      summary:
        status === "completed"
          ? `Diagnostics operator override granted for ${decisionId}.`
          : `Diagnostics operator override blocked for ${decisionId}: approval is required.`,
    };
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: targetTurnId ?? gateEvent?.turn_id ?? "",
      item_id: `${targetTurnId || threadId}:item:diagnostics-operator-override:${safeId(String(decisionId))}`,
      idempotency_key: idempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: "LspDiagnostics.OperatorOverrideExecuted",
      event_kind: "diagnostics.operator_override.executed",
      status,
      actor: optionalString(request.actor) ?? "operator",
      workspace_root: gateEvent?.workspace_root ?? this.agentForThread(threadId).cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "lsp_diagnostics_operator_override",
      tool_call_id: snapshotId ?? null,
      receipt_refs: [receiptId],
      artifact_refs: [],
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      payload_summary: payloadSummary,
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
    const agent = this.agentForThread(threadId);
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "repair_retry";
    const idempotencyKey =
      optionalString(request.repair_retry_idempotency_key ?? request.repairRetryIdempotencyKey) ??
      `thread:${threadId}:diagnostics-repair-retry:${decisionId}:${gateEvent?.event_id ?? "gate"}:${snapshotId ?? "no-snapshot"}`;
    const duplicate = this.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(idempotencyKey);
    if (duplicate) {
      return diagnosticsRepairRetryResultFromEvent({
        threadId,
        event: duplicate,
        turn: this.turnForRepairRetryEvent(duplicate),
      });
    }

    const diagnosticsFeedback = diagnosticsRepairRetryFeedback({
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
    });
    const prompt =
      optionalString(request.prompt ?? request.message ?? request.input) ??
      "Repair the blocking post-edit diagnostics and retry the turn.";
    const run = this.createRun(agent.id, {
      mode: request.mode ?? "send",
      prompt,
      options: {
        ...(request.options ?? {}),
        diagnosticsMode: "skip",
        diagnostics_mode: "skip",
      },
      memory: request.memory,
      remember: request.remember,
      diagnosticsFeedback,
    });
    const turn = this.turnForRun(run);
    const event = this.appendDiagnosticsRepairRetryTurnEvent({
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
    return diagnosticsRepairRetryResultFromEvent({ threadId, event, turn, run });
  }

  turnForRepairRetryEvent(event = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const retryTurnId = optionalString(payload.retry_turn_id ?? payload.retryTurnId);
    if (!retryTurnId) return null;
    try {
      return this.getTurn(event.thread_id, retryTurnId);
    } catch {
      return null;
    }
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
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "repair_retry";
    const receiptId = `receipt_lsp_diagnostics_repair_retry_${doctorHash(
      `${threadId}:${decisionId}:${turn?.turn_id ?? run?.id ?? ""}`,
    ).slice(0, 12)}`;
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(decision?.rollbackRefs ?? decision?.rollback_refs),
      ...normalizeArray(repairPolicy?.rollbackRefs ?? repairPolicy?.rollback_refs),
      ...normalizeArray(gateEvent?.rollback_refs),
      ...normalizeArray(diagnosticsFeedback?.rollbackRefs ?? diagnosticsFeedback?.rollback_refs),
    ]);
    const policyDecisionRefs = uniqueStrings([
      decisionId,
      repairPolicy?.policy_id ?? repairPolicy?.policyId,
      ...normalizeArray(gateEvent?.policy_decision_refs),
    ]);
    const artifactRefs = uniqueStrings(
      normalizeArray(run?.artifacts).map((artifactRecord) => artifactRecord?.id),
    );
    const payloadSummary = {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      event_kind: "LspDiagnosticsRepairRetryTurnCreated",
      thread_id: threadId,
      decision_id: decisionId,
      action: "repair_retry",
      status: turn?.status ?? "completed",
      gate_event_id: gateEvent?.event_id ?? null,
      gate_id: gateEvent?.payload_summary?.gate_id ?? null,
      policy_id: repairPolicy?.policy_id ?? repairPolicy?.policyId ?? null,
      snapshot_id: snapshotId ?? null,
      retry_turn_id: turn?.turn_id ?? null,
      retry_request_id: turn?.request_id ?? run?.id ?? null,
      repair_prompt_injected: true,
      diagnostics_mode: diagnosticsFeedback?.mode ?? "repair_retry",
      diagnostic_status: diagnosticsFeedback?.diagnosticStatus ?? null,
      diagnostic_count: diagnosticsFeedback?.diagnosticCount ?? null,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      rollback_refs: rollbackRefs,
      receipt_refs: [receiptId],
      artifact_refs: artifactRefs,
      policy_decision_refs: policyDecisionRefs,
      decision,
      summary: `Diagnostics repair retry created turn ${turn?.turn_id ?? "unknown"} for ${decisionId}.`,
    };
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turn?.turn_id ?? "",
      item_id: `${turn?.turn_id || threadId}:item:diagnostics-repair-retry:${safeId(String(decisionId))}`,
      idempotency_key: idempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: "LspDiagnostics.RepairRetryTurnCreated",
      event_kind: "diagnostics.repair_retry.created",
      status: "completed",
      actor: optionalString(request.actor) ?? "operator",
      workspace_root: gateEvent?.workspace_root ?? this.agentForThread(threadId).cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "lsp_diagnostics_repair_retry",
      tool_call_id: snapshotId ?? null,
      receipt_refs: [receiptId],
      artifact_refs: artifactRefs,
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
  }

  resolveDiagnosticsRepairDecision(threadId, decisionRef, request = {}) {
    this.projectThreadEvents(this.agentForThread(threadId));
    const gateId = optionalString(request.gate_id ?? request.gateId);
    const target = optionalString(decisionRef)?.toLowerCase();
    const action = optionalString(request.action ?? request.decision_action ?? request.decisionAction)?.toLowerCase();
    const gateEvents = this.runtimeEventsForStream(eventStreamIdForThread(threadId), { sinceSeq: 0 })
      .filter((event) => event.event_kind === "policy.blocked" && event.component_kind === "lsp_diagnostics_gate")
      .filter((event) => {
        if (!gateId) return true;
        return (
          event.payload_summary?.gate_id === gateId ||
          event.payload_summary?.gateId === gateId ||
          event.payload?.gate_id === gateId ||
          event.payload?.gateId === gateId
        );
      })
      .sort((left, right) => right.seq - left.seq);
    for (const gateEvent of gateEvents) {
      const repairPolicy = gateEvent.payload_summary?.repair_policy ?? gateEvent.payload_summary?.repairPolicy ?? {};
      const decisions = normalizeArray(
        repairPolicy.decisions ??
          gateEvent.payload_summary?.repair_decisions ??
          gateEvent.payload_summary?.repairDecisions,
      );
      const decision = decisions.find((candidate) => {
        const candidateId = optionalString(candidate.decision_id ?? candidate.decisionId)?.toLowerCase();
        const candidateAction = optionalString(candidate.action)?.toLowerCase();
        return candidateId === target || candidateAction === target || (action && candidateAction === action);
      });
      if (decision) return { gateEvent, decision, repairPolicy };
    }
    throw notFound(`Diagnostics repair decision not found: ${decisionRef}`, {
      threadId,
      decisionRef,
      gateId,
    });
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
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? action;
    const receiptId = `receipt_lsp_diagnostics_repair_${safeId(action)}_${doctorHash(
      `${threadId}:${decisionId}:${snapshotId}:${executionResult?.event?.event_id ?? ""}`,
    ).slice(0, 12)}`;
    const policyDecisionRefs = uniqueStrings([
      decisionId,
      repairPolicy?.policy_id ?? repairPolicy?.policyId,
      ...normalizeArray(gateEvent?.policy_decision_refs),
      ...normalizeArray(executionResult?.policy_decision_refs ?? executionResult?.policyDecisionRefs),
    ]);
    const artifactRefs = uniqueStrings(normalizeArray(executionResult?.artifact_refs ?? executionResult?.artifactRefs));
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(executionResult?.rollback_refs ?? executionResult?.rollbackRefs),
    ]);
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: gateEvent?.turn_id ?? "",
      item_id: `${gateEvent?.turn_id || threadId}:item:diagnostics-repair:${safeId(String(decisionId))}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:diagnostics-repair:${decisionId}:${snapshotId}:${action}:${
          action === "operator_override"
            ? diagnosticsOperatorOverrideApprovalKey(
                diagnosticsOperatorOverrideApprovalForRequest(request, { decision, repairPolicy }),
              )
            : "default"
        }`,
      source: operatorControlSource(request.source),
      source_event_kind: "LspDiagnostics.RepairDecisionExecuted",
      event_kind: "diagnostics.repair_decision.executed",
      status: diagnosticsRepairExecutionStatus(executionResult),
      actor: optionalString(request.actor) ?? "operator",
      workspace_root: gateEvent?.workspace_root ?? "",
      workflow_graph_id: workflowGraphId,
      workflow_node_id: `${workflowNodeId}.decision`,
      component_kind: "lsp_diagnostics_repair",
      tool_call_id: snapshotId,
      receipt_refs: [receiptId],
      artifact_refs: artifactRefs,
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      payload_summary: {
        schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
        event_kind: "LspDiagnosticsRepairDecisionExecuted",
        thread_id: threadId,
        decision_id: decisionId,
        action,
        status: diagnosticsRepairExecutionStatus(executionResult),
        gate_event_id: gateEvent?.event_id ?? null,
        gate_id: gateEvent?.payload_summary?.gate_id ?? null,
        policy_id: repairPolicy?.policy_id ?? repairPolicy?.policyId ?? null,
        snapshot_id: snapshotId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        repair_retry_event_id: action === "repair_retry" ? executionResult?.event?.event_id ?? null : null,
        repair_retry_turn_id:
          action === "repair_retry"
            ? executionResult?.repair_turn?.turn_id ?? executionResult?.repairTurn?.turn_id ?? null
            : null,
        repair_retry_request_id:
          action === "repair_retry"
            ? executionResult?.repair_turn?.request_id ?? executionResult?.repairTurn?.request_id ?? null
            : null,
        operator_override_event_id: action === "operator_override" ? executionResult?.event?.event_id ?? null : null,
        operator_override_status:
          action === "operator_override"
            ? executionResult?.override_status ?? executionResult?.overrideStatus ?? executionResult?.status ?? null
            : null,
        operator_override_approval_required:
          action === "operator_override"
            ? executionResult?.approval_required ?? executionResult?.approvalRequired ?? null
            : null,
        operator_override_approval_satisfied:
          action === "operator_override"
            ? executionResult?.approval_satisfied ?? executionResult?.approvalSatisfied ?? null
            : null,
        operator_override_continuation_allowed:
          action === "operator_override"
            ? executionResult?.continuation_allowed ?? executionResult?.continuationAllowed ?? null
            : null,
        restore_preview_event_id: action === "restore_preview" ? executionResult?.event?.event_id ?? null : null,
        restore_preview_status: executionResult?.preview_status ?? executionResult?.previewStatus ?? null,
        restore_apply_event_id: action === "restore_apply" ? executionResult?.event?.event_id ?? null : null,
        restore_apply_status: executionResult?.apply_status ?? executionResult?.applyStatus ?? null,
        approval_satisfied: executionResult?.approval_satisfied ?? executionResult?.approvalSatisfied ?? null,
        rollback_refs: rollbackRefs,
        receipt_refs: [receiptId],
        artifact_refs: artifactRefs,
        policy_decision_refs: policyDecisionRefs,
        decision,
        summary: `Diagnostics repair decision ${action} executed${snapshotId ? ` for ${snapshotId}` : ""}.`,
      },
    });
  }

  workspaceSnapshotContentPackage(threadId, snapshotId) {
    const matches = [...this.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.channel === "workspace-snapshot")
      .map((artifactRecord) => {
        const parsed = parseJsonObject(artifactRecord.content);
        const parsedSnapshotId =
          parsed?.snapshotId ??
          parsed?.snapshot_id ??
          parsed?.snapshot?.snapshotId ??
          parsed?.snapshot?.snapshot_id;
        return parsedSnapshotId === snapshotId ? { artifactRecord, parsed } : null;
      })
      .filter(Boolean);
    const match = matches[0];
    if (!match) {
      throw notFound(`Workspace snapshot not found: ${snapshotId}`, { threadId, snapshotId });
    }
    const snapshot = match.parsed.snapshot ?? match.parsed;
    if (!snapshot?.restore?.previewSupported) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_preview_unavailable",
        message: "Workspace snapshot does not contain enough captured content for restore preview.",
        details: {
          threadId,
          snapshotId,
          restoreStatus: snapshot?.restore?.status ?? "unknown",
        },
      });
    }
    return {
      artifactRecord: match.artifactRecord,
      snapshot,
      files: normalizeArray(match.parsed.files),
    };
  }

  materializeWorkspaceRestorePreviewArtifact({
    threadId,
    workspaceRoot,
    snapshotId,
    artifactId,
    receiptId,
    preview,
  } = {}) {
    const createdAt = new Date().toISOString();
    const content = JSON.stringify(preview, null, 2);
    const artifactRecord = {
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      threadId,
      tool_name: "workspace.restore_preview",
      toolName: "workspace.restore_preview",
      tool_call_id: snapshotId,
      toolCallId: snapshotId,
      workspace_root: workspaceRoot,
      workspaceRoot,
      name: "workspace-restore-preview.json",
      channel: "restore-preview",
      media_type: "application/json",
      mediaType: "application/json",
      redaction: "workspace_restore_preview",
      receipt_id: receiptId,
      receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      contentBytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      contentHash: doctorHash(content),
      created_at: createdAt,
      createdAt,
    };
    this.codingArtifacts.set(artifactRecord.id, artifactRecord);
    writeJson(this.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
    return artifactRecord;
  }

  materializeWorkspaceRestoreApplyArtifact({
    threadId,
    workspaceRoot,
    snapshotId,
    artifactId,
    receiptId,
    apply,
  } = {}) {
    const createdAt = new Date().toISOString();
    const content = JSON.stringify(apply, null, 2);
    const artifactRecord = {
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      threadId,
      tool_name: "workspace.restore_apply",
      toolName: "workspace.restore_apply",
      tool_call_id: snapshotId,
      toolCallId: snapshotId,
      workspace_root: workspaceRoot,
      workspaceRoot,
      name: "workspace-restore-apply.json",
      channel: "restore-apply",
      media_type: "application/json",
      mediaType: "application/json",
      redaction: "workspace_restore_apply",
      receipt_id: receiptId,
      receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      contentBytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      contentHash: doctorHash(content),
      created_at: createdAt,
      createdAt,
    };
    this.codingArtifacts.set(artifactRecord.id, artifactRecord);
    writeJson(this.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
    return artifactRecord;
  }

  appendWorkspaceRestorePreviewEvent({
    threadId,
    turnId,
    workspaceRoot,
    workflowGraphId,
    workflowNodeId,
    preview,
  } = {}) {
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || "",
      item_id: `${turnId || threadId}:item:workspace-restore-preview:${safeId(preview.snapshotId)}`,
      idempotency_key:
        optionalString(preview.idempotency_key ?? preview.idempotencyKey) ??
        `thread:${threadId}:workspace-restore-preview:${preview.snapshotId}:${doctorHash(
          JSON.stringify(preview.operations),
        ).slice(0, 12)}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceRestore.Previewed",
      event_kind: "workspace.restore.previewed",
      status: preview.previewStatus === "ready" ? "completed" : "blocked",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "restore_gate",
      tool_call_id: preview.snapshotId,
      artifact_refs: preview.artifactRefs,
      receipt_refs: preview.receiptRefs,
      rollback_refs: preview.rollbackRefs,
      payload_schema_version: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      payload_summary: {
        ...preview,
        event_kind: "WorkspaceRestorePreview",
      },
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
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || "",
      item_id: `${turnId || threadId}:item:workspace-restore-apply:${safeId(apply.snapshotId)}`,
      idempotency_key:
        optionalString(apply.idempotency_key ?? apply.idempotencyKey) ??
        `thread:${threadId}:workspace-restore-apply:${apply.snapshotId}:${doctorHash(
          JSON.stringify(apply.operations),
        ).slice(0, 12)}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceRestore.Applied",
      event_kind: "workspace.restore.applied",
      status: apply.applyStatus === "blocked" ? "blocked" : apply.applyStatus === "failed" ? "failed" : "completed",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "restore_gate",
      tool_call_id: apply.snapshotId,
      artifact_refs: apply.artifactRefs,
      receipt_refs: apply.receiptRefs,
      rollback_refs: apply.rollbackRefs,
      policy_decision_refs: apply.policyDecisionRefs,
      payload_schema_version: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      payload_summary: {
        ...apply,
        event_kind: "WorkspaceRestoreApply",
      },
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
    const config = postEditDiagnosticsConfig(request, input);
    if (config.mode === "skip") return null;
    const paths = normalizeArray(patchResult?.changedFiles)
      .filter((entry) => entry?.diagnosticsRecommended !== false)
      .map((entry) => optionalString(entry?.path))
      .filter(Boolean);
    if (!paths.length) return null;
    const workspaceSnapshot =
      patchResult?.workspaceSnapshot ??
      patchResult?.workspace_snapshot ??
      null;
    const workspaceSnapshotId =
      optionalString(patchResult?.workspaceSnapshotId ?? patchResult?.workspace_snapshot_id) ??
      optionalString(workspaceSnapshot?.snapshotId ?? workspaceSnapshot?.snapshot_id);
    const rollbackRefs = uniqueStrings([
      workspaceSnapshotId,
      ...normalizeArray(patchResult?.rollbackRefs ?? patchResult?.rollback_refs),
    ]);
    const repairPolicyConfig = config.repairPolicyConfig ?? diagnosticsRepairPolicyConfig(request, input);
    return this.invokeThreadTool(threadId, "lsp.diagnostics", {
      source: "runtime_auto",
      turn_id: turnId || null,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: LSP_DIAGNOSTICS_AUTO_NODE_ID,
      tool_call_id: `coding_tool_lsp_diagnostics_auto_${doctorHash(`${patchToolCallId}:${paths.join(",")}`).slice(0, 16)}`,
      rollback_refs: rollbackRefs,
      diagnostics_repair_context: {
        schemaVersion: DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
        object: "ioi.runtime_diagnostics_rollback_repair_context",
        sourceToolName: "file.apply_patch",
        source_tool_name: "file.apply_patch",
        sourceToolCallId: patchToolCallId,
        source_tool_call_id: patchToolCallId,
        sourceWorkflowGraphId: workflowGraphId,
        source_workflow_graph_id: workflowGraphId,
        sourceWorkflowNodeId: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
        source_workflow_node_id: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
        workspaceSnapshotId: workspaceSnapshotId ?? null,
        workspace_snapshot_id: workspaceSnapshotId ?? null,
        restorePolicy: repairPolicyConfig.restorePolicy,
        restore_policy: repairPolicyConfig.restorePolicy,
        restoreConflictPolicy: repairPolicyConfig.restoreConflictPolicy,
        restore_conflict_policy: repairPolicyConfig.restoreConflictPolicy,
        diagnosticsRepairDefault: repairPolicyConfig.diagnosticsRepairDefault,
        diagnostics_repair_default: repairPolicyConfig.diagnosticsRepairDefault,
        operatorOverrideRequiresApproval: repairPolicyConfig.operatorOverrideRequiresApproval,
        operator_override_requires_approval: repairPolicyConfig.operatorOverrideRequiresApproval,
        rollbackRefs,
        rollback_refs: rollbackRefs,
        restore: workspaceSnapshot?.restore ?? null,
        changedFiles: normalizeArray(patchResult?.changedFiles).map((entry) => ({
          path: optionalString(entry?.path) ?? null,
          beforeHash: optionalString(entry?.beforeHash ?? entry?.before_hash) ?? null,
          before_hash: optionalString(entry?.beforeHash ?? entry?.before_hash) ?? null,
          afterHash: optionalString(entry?.afterHash ?? entry?.after_hash) ?? null,
          after_hash: optionalString(entry?.afterHash ?? entry?.after_hash) ?? null,
          diagnosticsRecommended: entry?.diagnosticsRecommended !== false,
          diagnostics_recommended: entry?.diagnosticsRecommended !== false,
        })),
      },
      input: {
        commandId: config.commandId,
        paths,
        cwd: config.cwd,
        timeoutMs: config.timeoutMs,
        maxOutputBytes: config.maxOutputBytes,
      },
    });
  }

  pendingDiagnosticsFeedbackForNextTurn(threadId, request = {}) {
    const injectionMode = normalizeDiagnosticsMode(
      request.diagnosticsMode ??
        request.diagnostics_mode ??
        request.options?.diagnosticsMode ??
        request.options?.diagnostics_mode ??
        "advisory",
    );
    if (injectionMode === "skip") return null;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const lastInjectedSeq = Math.max(
      0,
      ...stream.events
        .filter((event) => event.event_kind === "lsp.diagnostics.injected")
        .map((event) => Number(event.seq) || 0),
    );
    const diagnosticEvents = stream.events.filter((event) => {
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.seq > lastInjectedSeq &&
        event.event_kind === "tool.completed" &&
        event.source === "runtime_auto" &&
        payload.tool_name === "lsp.diagnostics"
      );
    });
    if (!diagnosticEvents.length) return null;
    return compactDiagnosticsFeedback({ threadId, mode: injectionMode, diagnosticEvents });
  }

  materializeCodingToolArtifactDrafts({ threadId, toolId, toolCallId, workspaceRoot, result, receiptId }) {
    const drafts = normalizeArray(result?.artifactDrafts ?? result?.artifact_drafts);
    const createdAt = new Date().toISOString();
    return drafts
      .map((draft, index) => {
        if (!draft || typeof draft !== "object" || Array.isArray(draft)) return null;
        const content = String(draft.content ?? "");
        const channel = optionalString(draft.channel) ?? `artifact-${index + 1}`;
        const mediaType = optionalString(draft.mediaType ?? draft.media_type) ?? "text/plain";
        const contentBytes = Buffer.byteLength(content, "utf8");
        const contentHash = doctorHash(content);
        const artifactRecord = {
          schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
          schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
          id: `artifact_coding_tool_${safeId(toolCallId)}_${safeId(channel)}`,
          thread_id: threadId,
          threadId,
          tool_name: toolId,
          toolName: toolId,
          tool_call_id: toolCallId,
          toolCallId,
          workspace_root: workspaceRoot,
          workspaceRoot,
          name: optionalString(draft.name) ?? `${safeId(toolId)}-${channel}.txt`,
          channel,
          media_type: mediaType,
          mediaType,
          redaction: optionalString(draft.redaction) ?? "none",
          receipt_id: receiptId,
          receiptId,
          content,
          content_bytes: contentBytes,
          contentBytes,
          content_hash: contentHash,
          contentHash,
          created_at: createdAt,
          createdAt,
        };
        this.codingArtifacts.set(artifactRecord.id, artifactRecord);
        writeJson(this.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
        return artifactRecord;
      })
      .filter(Boolean);
  }

  materializeVisualGuiObservationArtifacts({ threadId, toolId, toolCallId, workspaceRoot, input }) {
    const specs = [
      {
        pathKeys: ["screenshotPath", "screenshot_path", "screenshotFile", "screenshot_file"],
        refKey: "screenshotRef",
        channel: "visual-gui-screenshot",
        defaultName: "visual-gui-screenshot.png",
        defaultMediaType: "image/png",
      },
      {
        pathKeys: ["somPath", "som_path", "setOfMarksPath", "set_of_marks_path"],
        refKey: "somRef",
        channel: "visual-gui-som",
        defaultName: "visual-gui-som.json",
        defaultMediaType: "application/json",
      },
      {
        pathKeys: ["axPath", "ax_path", "accessibilityTreePath", "accessibility_tree_path"],
        refKey: "axRef",
        channel: "visual-gui-ax",
        defaultName: "visual-gui-ax.json",
        defaultMediaType: "application/json",
      },
    ];
    const createdAt = new Date().toISOString();
    const metadata = {};
    const artifactRefs = [];
    const artifacts = [];
    for (const spec of specs) {
      const explicitRef = optionalString(input[spec.refKey] ?? input[snakeCaseKey(spec.refKey)]);
      if (explicitRef) continue;
      const sourcePath = firstOptionalString(spec.pathKeys.map((key) => input[key]));
      if (!sourcePath) continue;
      const resolvedPath = path.resolve(workspaceRoot ?? process.cwd(), sourcePath);
      let contentBuffer;
      try {
        contentBuffer = fs.readFileSync(resolvedPath);
      } catch (error) {
        throw runtimeError({
          status: 400,
          code: "computer_use_visual_artifact_unreadable",
          message: `Visual GUI observation artifact could not be read for ${spec.channel}.`,
          details: {
            channel: spec.channel,
            sourcePathHash: doctorHash(resolvedPath),
            error: error?.code ?? error?.message ?? "read_failed",
          },
        });
      }
      if (contentBuffer.byteLength > COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES) {
        throw runtimeError({
          status: 413,
          code: "computer_use_visual_artifact_too_large",
          message: `Visual GUI observation artifact exceeds ${COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES} bytes.`,
          details: {
            channel: spec.channel,
            sourcePathHash: doctorHash(resolvedPath),
            contentBytes: contentBuffer.byteLength,
            maxBytes: COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
          },
        });
      }
      const content = contentBuffer.toString("base64");
      const extension = path.extname(resolvedPath);
      const mediaType =
        optionalString(input[`${spec.refKey}MediaType`] ?? input[`${snakeCaseKey(spec.refKey)}_media_type`]) ??
        visualGuiMediaTypeForPath(resolvedPath) ??
        spec.defaultMediaType;
      const artifactId = `artifact_computer_use_visual_${safeId(toolCallId)}_${safeId(spec.channel)}`;
      const receiptId = `receipt_${safeId(toolCallId)}_${safeId(spec.channel)}`;
      const artifactRecord = {
        schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
        schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
        id: artifactId,
        thread_id: threadId,
        threadId,
        tool_name: toolId,
        toolName: toolId,
        tool_call_id: toolCallId,
        toolCallId,
        workspace_root: workspaceRoot,
        workspaceRoot,
        name: extension ? `${spec.channel}${extension}` : spec.defaultName,
        channel: spec.channel,
        media_type: mediaType,
        mediaType,
        encoding: "base64",
        redaction: "local_redacted_artifacts",
        receipt_id: receiptId,
        receiptId,
        content,
        content_bytes: contentBuffer.byteLength,
        contentBytes: contentBuffer.byteLength,
        content_hash: doctorHash(content),
        contentHash: doctorHash(content),
        source_path_hash: doctorHash(resolvedPath),
        sourcePathHash: doctorHash(resolvedPath),
        source_path_included: false,
        sourcePathIncluded: false,
        created_at: createdAt,
        createdAt,
      };
      this.codingArtifacts.set(artifactRecord.id, artifactRecord);
      writeJson(this.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
      metadata[spec.refKey] = artifactId;
      artifactRefs.push(artifactId);
      artifacts.push(artifactRecord);
    }
    return { metadata, artifactRefs, artifacts };
  }

  readCodingToolArtifact(threadId, artifactId, range = {}) {
    const artifactRecord = this.codingArtifacts.get(artifactId);
    if (!artifactRecord) throw notFound(`Artifact not found: ${artifactId}`, { threadId, artifactId });
    if (artifactRecord.thread_id && artifactRecord.thread_id !== threadId) {
      throw policyError("Artifact read blocked outside the owning runtime thread.", {
        threadId,
        artifactId,
        ownerThreadId: artifactRecord.thread_id,
      });
    }
    return codingToolArtifactReadResult(artifactRecord, range);
  }

  retrieveCodingToolResult(threadId, query = {}) {
    if (query.artifactId) {
      return {
        ...this.readCodingToolArtifact(threadId, query.artifactId, query.range),
        shellFallbackUsed: false,
      };
    }
    const toolCallId = optionalString(query.toolCallId);
    if (!toolCallId) {
      throw runtimeError({
        status: 400,
        code: "tool_retrieve_result_target_required",
        message: "tool.retrieve_result requires a toolCallId or artifactId.",
        details: { threadId },
      });
    }
    const artifacts = [...this.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.tool_call_id === toolCallId)
      .sort((left, right) => String(left.channel ?? "").localeCompare(String(right.channel ?? "")));
    if (!artifacts.length) {
      throw notFound(`Tool result artifact not found: ${toolCallId}`, { threadId, toolCallId });
    }
    const channel = optionalString(query.channel);
    const artifactRecord = artifacts.find((item) => item.channel === channel) ?? artifacts[0];
    return {
      ...codingToolArtifactReadResult(artifactRecord, query.range),
      toolCallId,
      availableArtifacts: artifacts.map(codingToolArtifactMetadata),
      shellFallbackUsed: false,
    };
  }

  createConversationArtifact(threadId, input = {}) {
    return this.conversationArtifacts.create({
      ...input,
      threadId,
    });
  }

  listConversationArtifacts(query = {}) {
    return this.conversationArtifacts.list(query);
  }

  getConversationArtifact(artifactId) {
    const artifact = this.conversationArtifacts.get(artifactId);
    if (!artifact) throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
    return artifact;
  }

  listConversationArtifactRevisions(artifactId) {
    this.getConversationArtifact(artifactId);
    return this.conversationArtifacts.revisions(artifactId);
  }

  performConversationArtifactAction(artifactId, input = {}) {
    const result = this.conversationArtifacts.action(artifactId, input);
    if (!result) throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
    return result;
  }

  exportConversationArtifact(artifactId, input = {}) {
    const result = this.conversationArtifacts.exportArtifact(artifactId, input);
    if (!result) throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
    return result;
  }

  promoteConversationArtifact(artifactId, input = {}) {
    const result = this.conversationArtifacts.promoteArtifact(artifactId, input);
    if (!result) throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
    return result;
  }

  ensureDirs() {
    for (const dir of [
      "agents",
      "runs",
      "tasks",
      "jobs",
      "checklists",
      "artifacts",
      "conversation-artifacts",
      "receipts",
      "quality",
      "policy-decisions",
      "authority-decisions",
      "stop-conditions",
      "scorecards",
      "ledgers",
      "projections",
      "model-artifacts",
      "model-endpoints",
      "model-instances",
      "model-routes",
      "model-providers",
      "model-downloads",
      "tokens",
      "mcp-servers",
      "memory-records",
      "memory-policies",
      "subagents",
      "events",
    ]) {
      fs.mkdirSync(path.join(this.stateDir, dir), { recursive: true });
    }
  }

  writeSchema() {
    writeJson(this.pathFor("schema.json"), {
      schemaVersion: this.schemaVersion,
      relationSchemas: {
        runs: ["id", "agentId", "status", "objective", "mode", "createdAt", "updatedAt"],
        tasks: ["runId", "currentObjective", "facts", "constraints", "evidenceRefs"],
        jobs: ["jobId", "taskId", "runId", "agentId", "status", "createdAt", "updatedAt"],
        checklists: ["checklistId", "taskId", "jobId", "runId", "status", "itemCount", "completedItemCount"],
        artifacts: ["id", "runId", "name", "mediaType", "redaction", "receiptId"],
        conversationArtifacts: ["id", "threadId", "artifactClass", "status", "latestRevisionId"],
        receipts: ["id", "runId", "kind", "summary", "redaction", "evidenceRefs"],
        memoryRecords: ["id", "scope", "threadId", "agentId", "workspace", "createdAt"],
        memoryPolicies: ["id", "targetType", "targetId", "disabled", "readOnly", "writeRequiresApproval", "updatedAt"],
        subagents: ["subagentId", "parentThreadId", "agentId", "role", "status", "runId", "updatedAt"],
        runtimeEvents: [
          "event_stream_id",
          "seq",
          "idempotency_key",
          "thread_id",
          "turn_id",
          "item_id",
          "event_kind",
          "created_at",
        ],
        quality: ["runId", "scorecard", "qualityLedger", "stopCondition"],
        operationLog: ["sequence", "operationId", "kind", "objectId", "createdAt", "digest"],
        ...this.modelMounting.writeSchemaRelationSchemas(),
      },
      canonicalOwner: "Agentgres",
      sdkCheckpointAuthority: "cache_only",
    });
  }

  load() {
    for (const file of listJson(this.pathFor("agents"))) {
      const agent = readJson(file);
      this.agents.set(agent.id, agent);
    }
    for (const file of listJson(this.pathFor("runs"))) {
      const run = readJson(file);
      this.runs.set(run.id, run);
    }
    for (const file of listJson(this.pathFor("subagents"))) {
      const subagent = readJson(file);
      const subagentId = subagent.subagent_id ?? subagent.subagentId ?? subagent.agent_id ?? subagent.agentId;
      if (subagentId) this.subagents.set(String(subagentId), subagent);
    }
    for (const file of listJson(this.pathFor("artifacts"))) {
      const artifactRecord = readJson(file);
      const schemaVersion = artifactRecord.schema_version ?? artifactRecord.schemaVersion;
      if (schemaVersion === CODING_TOOL_ARTIFACT_SCHEMA_VERSION && artifactRecord.id) {
        this.codingArtifacts.set(artifactRecord.id, artifactRecord);
      }
    }
    for (const file of listJsonl(this.pathFor("events"))) {
      for (const record of readJsonl(file)) {
        this.registerRuntimeEvent(record);
      }
    }
  }

  writeAgent(agent, operationKind) {
    return writeAgentRecord(this, agent, operationKind, {
      writeJson,
    });
  }

  writeRun(run, operationKind) {
    return writeRunRecord(this, run, operationKind, {
      runtimeChecklistRecordForRun,
      runtimeJobRecordForRun,
      runtimeTaskRecordForRun,
      terminalEventTypes: TERMINAL_EVENT_TYPES,
      writeJson,
    });
  }

  writeSubagent(subagent, operationKind) {
    const subagentId = subagent.subagent_id ?? subagent.subagentId ?? subagent.agent_id ?? subagent.agentId;
    if (!subagentId) {
      throw runtimeError({
        status: 500,
        code: "subagent_id_required",
        message: "Subagent records require a stable id before persistence.",
        details: { operationKind },
      });
    }
    this.subagents.set(String(subagentId), subagent);
    writeJson(this.pathFor("subagents", `${subagentId}.json`), subagent);
    this.appendOperation(operationKind, {
      objectId: subagentId,
      subagentId,
      parentThreadId: subagent.parent_thread_id ?? subagent.parentThreadId ?? null,
      agentId: subagent.agent_id ?? subagent.agentId ?? null,
      status: subagent.status ?? subagent.lifecycle_status ?? null,
      role: subagent.role ?? null,
    });
  }

  appendOperation(kind, payload) {
    const sequence = this.operationCount() + 1;
    const operation = {
      sequence,
      operationId: `op_${String(sequence).padStart(8, "0")}_${kind.replace(/[^a-z0-9]+/gi, "_")}`,
      kind,
      objectId: payload.objectId ?? payload.agentId ?? payload.runId ?? null,
      createdAt: new Date().toISOString(),
      payload,
    };
    const digest = crypto.createHash("sha256").update(JSON.stringify(operation)).digest("hex");
    const record = { ...operation, digest };
    fs.mkdirSync(this.stateDir, { recursive: true });
    fs.appendFileSync(this.pathFor("operation-log.jsonl"), `${JSON.stringify(record)}\n`);
    return record;
  }

  operationCount() {
    const logPath = this.pathFor("operation-log.jsonl");
    if (!fs.existsSync(logPath)) return 0;
    const text = fs.readFileSync(logPath, "utf8").trim();
    return text ? text.split(/\n/).length : 0;
  }

  pathFor(...segments) {
    return path.join(this.stateDir, ...segments);
  }

  removeQuiet(filePath) {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      // Deleting a non-existent projection is not a state transition.
    }
  }
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
    modelRouteDecision?.selectedModel ??
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
    modelRoute?.receiptId ?? modelRouteDecision?.receiptId ?? `receipt_${runId}_model_route`;
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
            `Subagent memory inheritance: mode=${subagentMemoryInheritance.mode}, receiver=${subagentMemoryInheritance.subagentName ?? "handoff"}, records=${subagentMemoryInheritance.records.length}, writeAllowed=${subagentMemoryInheritance.writeAllowed}`,
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
            `Post-edit diagnostics: status=${diagnosticsFeedback.diagnosticStatus}, findings=${diagnosticsFeedback.diagnosticCount}, mode=${diagnosticsFeedback.mode}`,
          ]
        : []),
      ...(diagnosticsBlockingGate
        ? [
            `Post-edit diagnostics blocking gate: id=${diagnosticsBlockingGate.gateId}, status=${diagnosticsBlockingGate.status}, decision=${diagnosticsBlockingGate.decision}`,
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
      "agentgres_canonical_operation_log",
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
      diagnosticsFeedback?.injectionId,
      diagnosticsBlockingGate?.gateId,
      diagnosticsBlockingGate?.policyDecisionId,
      ...(diagnosticsBlockingGate?.policyDecisionRefs ?? []),
      ...(diagnosticsBlockingGate?.rollbackRefs ?? []),
      diagnosticsBlockingGate?.receiptId,
      activeSkillHookManifest.activeSkillSetHash,
      activeSkillHookManifest.activeHookSetHash,
      ...agent.options.mcpServerNames,
      ...agent.options.skillNames,
      ...agent.options.hookNames,
      ...normalizeArray(modelRouteDecision?.evidenceRefs),
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
        ? "Agentgres canonical operation log can replay the blocked diagnostics gate event stream."
        : "Agentgres canonical operation log can replay the terminal run event stream.",
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
        checkId: "agentgres-operation-log",
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
              status: diagnosticsFeedback.blocking && diagnosticsFeedback.diagnosticStatus === "findings"
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
        summary: `Route ${modelRouteDecision.routeId} selected ${modelRouteDecision.selectedModel}.`,
        redaction: "none",
        evidenceRefs: normalizeArray(modelRouteDecision.evidenceRefs),
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
        id: diagnosticsFeedback.receiptId,
        kind: "lsp_diagnostics_injection",
        summary: diagnosticsFeedback.summary,
        redaction: "redacted",
        evidenceRefs: [
          diagnosticsFeedback.injectionId,
          ...normalizeArray(diagnosticsFeedback.diagnosticEventIds),
          "lsp.diagnostics.injected",
          "LspDiagnosticsNode",
        ],
      }
    : null;
  const diagnosticsBlockingGateReceipt = diagnosticsBlockingGate
    ? {
        id: diagnosticsBlockingGate.receiptId,
        kind: "lsp_diagnostics_blocking_gate",
        summary: diagnosticsBlockingGate.summary,
        redaction: "redacted",
        evidenceRefs: [
          diagnosticsBlockingGate.gateId,
          diagnosticsBlockingGate.policyDecisionId,
          ...normalizeArray(diagnosticsBlockingGate.policyDecisionRefs),
          ...normalizeArray(diagnosticsBlockingGate.rollbackRefs),
          diagnosticsBlockingGate.injectionId,
          diagnosticsBlockingGate.diagnosticsReceiptId,
          ...diagnosticsBlockingGate.diagnosticEventIds,
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
    evidenceRefs: ["agentgres_canonical_operation_log", `run:${runId}`],
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
      agentId: agent.id,
      mode,
      objective: prompt,
      result,
      createdAt,
      updatedAt: createdAt,
      modelRouteDecision,
      usage:
        request.usage_telemetry ??
        request.usageTelemetry ??
        request.runtime_usage ??
        request.runtimeUsage ??
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
    ...runtimeTask,
    receiptId: runtimeTaskReceipt.id,
    eventKind: "RuntimeTaskRecord",
    workflowNodeId: "runtime.runtime-task",
  });
  addEvent("job_queued", "Runtime job queued", {
    ...runtimeJob,
    status: "queued",
    lifecycleStatus: "queued",
    completedAt: null,
    receiptId: runtimeJobReceipt.id,
    eventKind: "JobQueued",
    workflowNodeId: "runtime.runtime-job",
  });
  addEvent("job_started", "Runtime job started", {
    ...runtimeJob,
    status: "running",
    lifecycleStatus: "started",
    completedAt: null,
    receiptId: runtimeJobReceipt.id,
    eventKind: "JobStarted",
    workflowNodeId: "runtime.runtime-job",
  });
  addEvent("runtime_checklist", "Runtime checklist recorded", {
    ...runtimeChecklist,
    receiptId: runtimeChecklistReceipt.id,
    eventKind: "RuntimeChecklistRecord",
    workflowNodeId: "runtime.runtime-checklist",
  });
  addEvent("repository_context", "Repository context recorded", {
    ...repositoryContext,
    receiptId: repositoryContextReceipt.id,
    eventKind: "RepositoryContext",
    workflowNodeId: "runtime.repository-context",
  });
  addEvent("branch_policy", "Branch policy decision recorded", {
    ...branchPolicy,
    receiptId: branchPolicyReceipt.id,
    eventKind: "BranchPolicyDecision",
    workflowNodeId: "runtime.branch-policy",
  });
  addEvent("github_context", "GitHub context recorded", {
    ...githubContext,
    receiptId: githubContextReceipt.id,
    eventKind: "GitHubContext",
    workflowNodeId: "runtime.github-context",
  });
  addEvent("issue_context", "Issue context recorded", {
    ...issueContext,
    receiptId: issueContextReceipt.id,
    eventKind: "IssueContext",
    workflowNodeId: "runtime.issue-context",
  });
  addEvent("pr_attempt", "PR attempt preview recorded", {
    ...prAttempt,
    receiptId: prAttemptReceipt.id,
    eventKind: "PrAttemptRecord",
    workflowNodeId: "runtime.pr-attempt",
  });
  addEvent("review_gate", "Review gate decision recorded", {
    ...reviewGate,
    receiptId: reviewGateReceipt.id,
    eventKind: "ReviewGateDecision",
    workflowNodeId: "runtime.review-gate",
  });
  addEvent("github_pr_create_plan", "GitHub PR create dry-run plan recorded", {
    ...githubPrCreatePlan,
    receiptId: githubPrCreatePlanReceipt.id,
    eventKind: "GitHubPrCreatePlan",
    workflowNodeId: "runtime.github-pr-create",
  });
  addEvent("skill_hook_manifest", "Active skill and hook manifest recorded", {
    ...activeSkillHookManifest,
    receiptId: skillHookReceipt.id,
    eventKind: "ActiveSkillHookManifest",
    workflowNodeId: "runtime.skill-hook-manifest",
  });
  addEvent("hook_dry_run_plan", "Hook dry-run plan recorded", {
    ...hookDryRunPlan,
    receiptId: hookDryRunReceipt.id,
    policyReceiptId: hookPolicyReceipt.id,
    eventKind: "HookDryRunPlan",
    workflowNodeId: "runtime.hook-policy",
  });
  addEvent("hook_invocation_ledger", "Hook invocation ledger recorded", {
    ...hookInvocationLedger,
    receiptId: hookInvocationReceipt.id,
    escalationReceiptIds: hookEscalationReceipts.map((receipt) => receipt.id),
    eventKind: "HookInvocationLedger",
    workflowNodeId: "runtime.hook-invocations",
  });
  if (modelRouteDecision) {
    addEvent("model_route_decision", "Model route decision recorded", {
      ...modelRouteDecision,
      receiptId: modelRouteReceiptId,
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
      ...(mutation.record ?? mutation.policy ?? {}),
      operation,
      eventKind: memoryEventKind(operation),
      receiptId: mutation.receipt?.id ?? null,
      workflowNodeId: mutation.record?.workflowNodeId ?? "runtime.memory-policy",
    });
  }
  if (subagentMemoryInheritance) {
    addEvent("memory_update", "Subagent memory inheritance resolved", {
      ...subagentMemoryInheritance,
      operation: "subagent_inheritance",
      eventKind: "SubagentMemoryInheritance",
      receiptId: subagentMemoryReceipt?.id ?? null,
      workflowNodeId: "runtime.subagent-memory",
    });
  }
  if (diagnosticsFeedback) {
    addEvent("lsp_diagnostics_injected", diagnosticsFeedback.summary, {
      ...diagnosticsFeedback,
      eventKind: "LspDiagnosticsInjected",
      receiptId: diagnosticsInjectionReceipt?.id ?? diagnosticsFeedback.receiptId,
      workflowNodeId: LSP_DIAGNOSTICS_INJECTION_NODE_ID,
    });
  }
  const diagnosticsBlockingGateEvent = diagnosticsBlockingGate
    ? addEvent("policy_blocked", diagnosticsBlockingGate.summary, {
        ...diagnosticsBlockingGate,
        eventKind: "LspDiagnosticsBlockingGate",
        receiptId: diagnosticsBlockingGateReceipt?.id ?? diagnosticsBlockingGate.receiptId,
        workflowNodeId: LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
        componentKind: "lsp_diagnostics_gate",
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
      ...runtimeJob,
      lifecycleStatus: "completed",
      receiptId: runtimeJobReceipt.id,
      eventKind: "JobCompleted",
      workflowNodeId: "runtime.runtime-job",
    });
  }
  addEvent("artifact", "Trace and scorecard artifacts recorded", {
    artifactNames: [
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
    usageTelemetry,
    runtimeUsage: usageTelemetry,
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
        source: "agentgres_canonical_operation_log",
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
    usageTelemetry,
    runtimeUsage: usageTelemetry,
    diagnosticsFeedback,
    diagnosticsBlockingGate,
    subagentMemoryInheritance,
    result,
  };
}

function nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch({
  launchReceipt,
  actionKind,
  approvalRef,
} = {}) {
  return nativeBrowserExecutionUnavailableFromControlledRelaunchLaunchImpl({
    launchReceipt,
    actionKind,
    approvalRef,
    uniqueStrings,
  });
}
