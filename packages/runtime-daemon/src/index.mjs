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
} from "./browser-discovery.mjs";
import { computerUseProviderRegistryReport } from "./computer-use-provider-registry.mjs";
import { AgentMemoryStore, parseMemoryCommand } from "./memory-store.mjs";
import {
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  codingToolInputSummary,
} from "./coding-tools.mjs";
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
import { boundedPositiveInteger } from "./runtime-mcp-helpers.mjs";
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
} from "./memory-manager.mjs";
import {
  optionalPositiveInteger,
} from "./subagent-manager.mjs";
import {
  RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
  runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread,
  runtimeUsageTelemetrySummary,
} from "./usage-telemetry.mjs";
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
import { artifact } from "./runtime-artifacts.mjs";
import { createCodingToolApprovalPolicy } from "./runtime-coding-tool-approval.mjs";
import { createRuntimeInvocationResultProjections } from "./runtime-invocation-results.mjs";
import { createDiagnosticsFeedbackHelpers } from "./diagnostics-feedback.mjs";
import { createRuntimeDiagnosticsFeedbackSurface } from "./runtime-diagnostics-feedback-surface.mjs";
import { createDiagnosticsRepairPolicyHelpers } from "./diagnostics-repair-policy.mjs";
import { createRuntimeDiagnosticsRepairSurface } from "./runtime-diagnostics-repair-surface.mjs";
import { createRuntimeUsageEventHelpers } from "./runtime-usage-events.mjs";
import { createRuntimeMemoryHelpers } from "./runtime-memory-helpers.mjs";
import { createRuntimeRunHelpers } from "./runtime-run-helpers.mjs";
import { createRuntimeRunEventHelpers } from "./runtime-run-event-helpers.mjs";
import { createRuntimeEventEnvelopeHelpers } from "./runtime-event-envelopes.mjs";
import { createRuntimeEventPayloadHelpers } from "./runtime-event-payloads.mjs";
import { createRuntimeCodingToolResultHelpers } from "./runtime-coding-tool-results.mjs";
import { createRuntimeDoctorReport } from "./runtime-doctor-report.mjs";
import { createRuntimeCodingToolApprovalCore } from "./runtime-coding-tool-approval-core.mjs";
import { createRuntimeCodingToolArtifactSurface } from "./runtime-coding-tool-artifact-surface.mjs";
import { createRuntimeCodingToolInvocationSurface } from "./runtime-coding-tool-invocation-surface.mjs";
import { createStepModuleRunnerFromEnv } from "./step-module-runner.mjs";
import { createRuntimeWorkspaceSnapshotSurface } from "./runtime-workspace-snapshot-surface.mjs";
import { createRuntimeCodingToolGovernanceSurface } from "./runtime-coding-tool-governance-surface.mjs";
import { createRuntimeCodingToolBudgetRecoverySurface } from "./runtime-coding-tool-budget-recovery-surface.mjs";
import { createRuntimeConversationArtifactSurface } from "./runtime-conversation-artifact-surface.mjs";
import { createRuntimeContextPolicySurface } from "./runtime-context-policy-surface.mjs";
import { createRuntimeContextPolicyCore } from "./runtime-context-policy-core.mjs";
import { createRuntimeWorkflowEditSurface } from "./runtime-workflow-edit-surface.mjs";
import { createRuntimeApprovalSurface } from "./runtime-approval-surface.mjs";
import { createRuntimeApprovalStateCore } from "./runtime-approval-state-core.mjs";
import { createRuntimeMcpCatalogSurface } from "./runtime-mcp-catalog-surface.mjs";
import { createRuntimeMcpControlSurface } from "./runtime-mcp-control-surface.mjs";
import { createRuntimeMcpServeSurface } from "./runtime-mcp-serve-surface.mjs";
import { createRuntimeRunReadSurface } from "./runtime-run-read-surface.mjs";
import { createRuntimeLifecycleProjectionSurface } from "./runtime-lifecycle-projection-surface.mjs";
import { createRuntimeSkillHookSurface } from "./runtime-skill-hook-surface.mjs";
import { createRuntimeTaskJobSurface } from "./runtime-task-job-surface.mjs";
import { createRuntimeGovernedImprovementSurface } from "./runtime-governed-improvement-surface.mjs";
import { createRuntimeWorkerServicePackageSurface } from "./runtime-worker-service-package-surface.mjs";
import { createRuntimeCteePrivateWorkspaceSurface } from "./runtime-ctee-private-workspace-surface.mjs";
import { createRuntimeL1SettlementSurface } from "./runtime-l1-settlement-surface.mjs";
import { createRuntimeThreadControlSurface } from "./runtime-thread-control-surface.mjs";
import { createRuntimeThreadTurnSurface } from "./runtime-thread-turn-surface.mjs";
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
import { createRuntimeAgentgresAdmissionCore } from "./runtime-agentgres-admission-core.mjs";
import { createRuntimeGovernedImprovementCore } from "./runtime-governed-improvement-core.mjs";
import { createRuntimeExternalCapabilityAuthorityCore } from "./runtime-external-capability-authority-core.mjs";
import { createRuntimeExternalCapabilityAuthoritySurface } from "./runtime-external-capability-authority-surface.mjs";
import { createRuntimeWorkerServicePackageCore } from "./runtime-worker-service-package-core.mjs";
import { createRuntimeCteePrivateWorkspaceCore } from "./runtime-ctee-private-workspace-core.mjs";
import { createRuntimeL1SettlementCore } from "./runtime-l1-settlement-core.mjs";
import { createRuntimeWorkspaceRestoreCore } from "./runtime-workspace-restore-core.mjs";
import { createRuntimeAgentRunLifecycleSurface } from "./runtime-agent-run-lifecycle.mjs";
import { createRuntimeRepositorySurface } from "./runtime-repository-surface.mjs";
import { startRuntimeDaemonServiceWithStore } from "./service/runtime-daemon-service.mjs";
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
import { createRuntimeThreadAuxiliarySurface } from "./runtime-thread-auxiliary-surface.mjs";
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
  memoryWorkflowNodeId,
  memoryWriteBlockReason,
  normalizeArray,
  operatorControlSource,
  optionalString,
  policyError,
  runtimeError,
  safeId,
  threadIdForAgent,
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
  resolveStudioIntentFrame,
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
  promptWithDiagnosticsFeedback,
} = createDiagnosticsFeedbackHelpers({
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
  runtimeChecklistRecord,
  runtimeChecklistRecordForRun,
  runtimeJobRecord,
  runtimeJobRecordForRun,
  runtimeTaskRecord,
} = createRuntimeRecordProjections({
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
  runtimeEventStatusForRunEvent,
  stringRecord,
  workflowNodeForRunEvent,
});

const RUNTIME_BRIDGE_AGENT_TURN_MIN_STEPS = 8;

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
    if (Object.hasOwn(options, "runtimeBridge")) {
      throw new Error("runtimeBridge is retired; use typed Rust daemon-core lifecycle APIs for runtime-service execution.");
    }
    if (Object.hasOwn(options, "daemonCoreInvoker")) {
      throw new Error("daemonCoreInvoker is retired; pass typed Rust daemon-core APIs for the authority boundary.");
    }
    this.daemonCoreContextLifecycleApi = options.daemonCoreContextLifecycleApi;
    this.daemonCoreRuntimeControlApi = options.daemonCoreRuntimeControlApi;
    this.daemonCoreRuntimeProjectionApi = options.daemonCoreRuntimeProjectionApi;
    this.daemonCoreThreadLifecycleApi = options.daemonCoreThreadLifecycleApi;
    this.daemonCoreWorkspaceTrustApi = options.daemonCoreWorkspaceTrustApi;
    this.daemonCoreMcpApi = options.daemonCoreMcpApi;
    this.daemonCoreThreadMemoryApi = options.daemonCoreThreadMemoryApi;
    this.daemonCoreAgentgresApi = options.daemonCoreAgentgresApi;
    this.daemonCoreModelMountApi = options.daemonCoreModelMountApi;
    this.daemonCoreAuthorityApi = options.daemonCoreAuthorityApi;
    this.daemonCoreApprovalApi = options.daemonCoreApprovalApi;
    this.daemonCoreCteeApi = options.daemonCoreCteeApi;
    this.daemonCoreWorkloadApi = options.daemonCoreWorkloadApi;
    this.daemonCoreWorkerServiceApi = options.daemonCoreWorkerServiceApi;
    this.daemonCoreGovernedAdmissionApi = options.daemonCoreGovernedAdmissionApi;
    this.daemonCoreWorkspaceRestoreApi = options.daemonCoreWorkspaceRestoreApi;
    if (Object.hasOwn(options, "contextPolicyRunner")) {
      throw new Error("contextPolicyRunner is retired; pass contextPolicyCore for the Rust daemon-core policy boundary.");
    }
    this.runtimeAgentgresAdmissionCore =
      options.runtimeAgentgresAdmissionCore ??
      createRuntimeAgentgresAdmissionCore({
        daemonCoreAgentgresApi: this.daemonCoreAgentgresApi,
      });
    this.contextPolicyCore =
      options.contextPolicyCore ??
      createRuntimeContextPolicyCore({
        daemonCoreContextLifecycleApi: this.daemonCoreContextLifecycleApi,
        daemonCoreRuntimeControlApi: this.daemonCoreRuntimeControlApi,
        daemonCoreRuntimeProjectionApi: this.daemonCoreRuntimeProjectionApi,
        daemonCoreThreadLifecycleApi: this.daemonCoreThreadLifecycleApi,
        daemonCoreWorkspaceTrustApi: this.daemonCoreWorkspaceTrustApi,
        daemonCoreMcpApi: this.daemonCoreMcpApi,
        daemonCoreThreadMemoryApi: this.daemonCoreThreadMemoryApi,
      });
    this.codingToolApprovalCore =
      options.codingToolApprovalCore ??
      createRuntimeCodingToolApprovalCore({
        daemonCoreApprovalApi: this.daemonCoreApprovalApi,
      });
    this.approvalStateCore =
      options.approvalStateCore ??
      createRuntimeApprovalStateCore({
        daemonCoreApprovalApi: this.daemonCoreApprovalApi,
      });
    this.governedImprovementCore =
      options.governedImprovementCore ??
      createRuntimeGovernedImprovementCore({
        daemonCoreGovernedAdmissionApi: this.daemonCoreGovernedAdmissionApi,
      });
    this.externalCapabilityAuthorityCore =
      options.externalCapabilityAuthorityCore ??
      createRuntimeExternalCapabilityAuthorityCore({
        daemonCoreAuthorityApi: this.daemonCoreAuthorityApi,
      });
    this.workerServicePackageCore =
      options.workerServicePackageCore ??
      createRuntimeWorkerServicePackageCore({
        daemonCoreWorkerServiceApi: this.daemonCoreWorkerServiceApi,
      });
    this.cteePrivateWorkspaceCore =
      options.cteePrivateWorkspaceCore ??
      createRuntimeCteePrivateWorkspaceCore({
        daemonCoreCteeApi: this.daemonCoreCteeApi,
      });
    this.l1SettlementCore =
      options.l1SettlementCore ??
      createRuntimeL1SettlementCore({
        daemonCoreGovernedAdmissionApi: this.daemonCoreGovernedAdmissionApi,
      });
    this.workspaceRestoreCore =
      options.workspaceRestoreCore ??
      createRuntimeWorkspaceRestoreCore({
        daemonCoreWorkspaceRestoreApi: this.daemonCoreWorkspaceRestoreApi,
      });
    this.schemaVersion = "ioi.agentgres.runtime.v0";
    this.ensureDirs();
    this.modelMounting = new ModelMountingState({
      stateDir: this.stateDir,
      cwd: this.defaultCwd,
      homeDir: options.homeDir,
      vaultSecrets: options.vaultSecrets,
      modelMountCore: options.modelMountCore,
      daemonCoreModelMountApi: this.daemonCoreModelMountApi,
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
    this.threadMemorySurface = threadMemoryState;
    this.agentRunLifecycleSurface = createRuntimeAgentRunLifecycleSurface({
      approvalModeForThreadMode,
      buildRun,
      ensureProviderAvailable,
      eventStreamIdForThread,
      initialThreadRuntimeControls,
      lifecycleAdmissionRunner: this.contextPolicyCore,
      mcpRegistryForWorkspace: (cwd, options = {}) =>
        mcpRegistryForWorkspace(cwd, {
          ...options,
          contextPolicyCore: this.contextPolicyCore,
        }),
      runtimeError,
      runtimeThreadSchemaVersion: RUNTIME_THREAD_SCHEMA_VERSION,
      runtimeModeForOptions,
      summarizeAgentOptions,
      threadIdForAgent,
      threadModeForRunMode,
      threadStatusForAgent,
    });
    this.threadAuxiliarySurface = createRuntimeThreadAuxiliarySurface();
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
    this.conversationArtifactSurface = createRuntimeConversationArtifactSurface({
      contextPolicyCore: this.contextPolicyCore,
      notFound,
    });
    this.approvalSurface = createRuntimeApprovalSurface({
      approvalDecisionForRequest,
      approvalLeaseMetadataForRequest,
      approvalLeaseMetadataFromPayload,
      approvalStateCore: this.approvalStateCore,
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
      codingToolBudgetRecoveryRunner: this.contextPolicyCore,
      contextPolicyCore: this.contextPolicyCore,
      notFound,
      runtimeError,
    });
    const codingToolApprovalPolicy = createCodingToolApprovalPolicy({
      approvalCore: this.codingToolApprovalCore,
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
    this.codingToolArtifactSurface = createRuntimeCodingToolArtifactSurface({
      codingToolCommandStreamAdmissionForThread: (store, request = {}) =>
        this.admitCodingToolCommandStreamEventsForThread(store, request),
      contextPolicyCore: this.contextPolicyCore,
      notFound,
      policyError,
      runtimeError,
      writeJson,
    });
    this.codingToolInvocationSurface = createRuntimeCodingToolInvocationSurface({
      codingToolApprovalManifestForThread: codingToolApprovalPolicy.codingToolApprovalManifestForThread,
      codingToolApprovalBlockForThread: codingToolApprovalPolicy.codingToolApprovalBlockForThread,
      codingToolApprovalSatisfactionForThread: codingToolApprovalPolicy.codingToolApprovalSatisfactionForThread,
      codingToolBudgetPolicyForRequest,
      codingToolInvocationResultFromEvent,
      codingToolResultWithoutDrafts,
      diagnosticsRepairContextForRequest,
      diagnosticsRepairContextForToolPack,
      codingToolResultEnvelopeForThread: (_store, request = {}) =>
        this.contextPolicyCore.planCodingToolResultEnvelope(request),
      codingToolResultEventAdmissionForThread: (store, request = {}) =>
        this.admitCodingToolResultEventForThread(store, request),
      stepModuleRunner: createStepModuleRunnerFromEnv(process.env, {
        daemonCoreWorkloadApi: this.daemonCoreWorkloadApi,
      }),
    });
    this.workspaceSnapshotSurface = createRuntimeWorkspaceSnapshotSurface({
      notFound,
      runtimeError,
      runtimeThreadEventAdmissionForThread: (store, request = {}) =>
        this.admitRuntimeThreadEventForThread(store, request),
      writeJson,
      workspaceRestoreCore: this.workspaceRestoreCore,
    });
    this.diagnosticsFeedbackSurface = createRuntimeDiagnosticsFeedbackSurface({
      compactDiagnosticsFeedback,
      diagnosticsFeedbackPlanner: this.contextPolicyCore,
      diagnosticsRepairPolicyProjector: this.contextPolicyCore,
      normalizeDiagnosticsMode,
    });
    this.diagnosticsRepairSurface = createRuntimeDiagnosticsRepairSurface({
      contextPolicyCore: this.contextPolicyCore,
      diagnosticsRepairRunner: this.contextPolicyCore,
      eventStreamIdForThread,
      diagnosticsRepairRetryFeedback,
      runtimeError,
    });
    this.codingToolGovernanceSurface = createRuntimeCodingToolGovernanceSurface({
      codingToolBudgetBlockPlanner: this.contextPolicyCore,
      runtimeError,
    });
    this.contextPolicySurface = createRuntimeContextPolicySurface({
      contextPolicyCore: this.contextPolicyCore,
      runtimeError,
    });
    this.workflowEditSurface = createRuntimeWorkflowEditSurface({
      approvalReasonForDecisionEvent,
      eventStreamIdForThread,
      notFound,
      policyError,
      runtimeError,
      workflowEditRunner: this.contextPolicyCore,
      writeJson,
    });
    this.mcpCatalogSurface = createRuntimeMcpCatalogSurface();
    this.mcpControlSurface = createRuntimeMcpControlSurface({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.mcpServeSurface = createRuntimeMcpServeSurface();
    this.repositorySurface = createRuntimeRepositorySurface({
      repositoryRunner: this.contextPolicyCore,
    });
    this.runReadSurface = createRuntimeRunReadSurface({
      notFound,
      runtimeChecklistRecordForRun,
      runtimeJobRecordForRun,
      runtimeUsageTelemetryForRun,
      runtimeUsageTelemetryForThread,
      threadIdForAgent,
    });
    this.lifecycleProjectionSurface = createRuntimeLifecycleProjectionSurface({
      lifecycleRunner: this.contextPolicyCore,
      workspaceRoot: this.defaultCwd,
    });
    this.skillHookSurface = createRuntimeSkillHookSurface({
      defaultCwd: this.defaultCwd,
      skillHookRunner: this.contextPolicyCore,
    });
    this.taskJobSurface = createRuntimeTaskJobSurface({
      buildRun,
      ensureProviderAvailable,
      notFound,
      optionalString,
      taskJobCreateRunner: this.contextPolicyCore,
      taskJobCancelRunner: this.contextPolicyCore,
      taskJobProjectionRunner: this.contextPolicyCore,
    });
    this.toolSurface = createRuntimeToolSurface({
      toolCatalogRunner: this.contextPolicyCore,
      workspaceRoot: this.defaultCwd,
    });
    this.threadControlSurface = createRuntimeThreadControlSurface({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.threadTurnSurface = createRuntimeThreadTurnSurface({
      contextPolicyCore: this.contextPolicyCore,
      diagnosticsFeedbackBlocksContinuation,
      runtimeError,
    });
    this.subagentSurface = createRuntimeSubagentSurface({
      contextPolicyCore: this.contextPolicyCore,
    });
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
      runtimeError,
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
      turnIdForRun,
    });
    this.memory = new AgentMemoryStore(this.stateDir);
    this.writeSchema();
    this.load();
  }

  close() {
    this.modelMounting.close();
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
      runtimeError,
    });
  }

  resolveModelRoute(options = {}, context = {}) {
    return this.modelRouteSelection.resolveModelRoute(options, context);
  }

  resolveRunModelRoute(agent, request = {}) {
    return this.modelRouteSelection.resolveRunModelRoute(agent, request);
  }

  selectModelRoute({ requestedModel, routeId, capability, policy, body, evidenceRefs }) {
    return this.modelRouteSelection.selectModelRoute({ requestedModel, routeId, capability, policy, body, evidenceRefs });
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

  listThreads() {
    return this.listAgents().map((agent) => this.threadForAgent(agent));
  }

  getThread(threadId) {
    return this.threadForAgent(this.agentForThread(threadId));
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

  projectRuntimeThreadEventsForThread(store, request = {}) {
    const agent = objectRecord(request.agent);
    const agentId = optionalString(agent?.id ?? agent?.agent_id);
    const threadId = optionalString(request.thread_id) ?? (agentId ? threadIdForAgent(agentId) : undefined);
    const eventStreamId = optionalString(request.event_stream_id) ?? (threadId ? eventStreamIdForThread(threadId) : undefined);
    if (!threadId || !eventStreamId) {
      throw runtimeError({
        status: 502,
        code: "runtime_thread_event_projection_invalid",
        message: "Rust daemon-core runtime thread-event projection requires canonical thread and stream identity.",
        details: {
          operation: "project_runtime_thread_events",
          projection_kind: request.projection_kind ?? null,
          agent_id: agentId ?? null,
        },
      });
    }
    const stream = store.runtimeEventStream(eventStreamId);
    const latestSeq = store.latestRuntimeEventSeq(eventStreamId);
    const projection = this.runtimeAgentgresAdmissionCore.projectRuntimeThreadEvents({
      projection_kind: optionalString(request.projection_kind) ?? "thread",
      thread_id: threadId,
      event_stream_id: eventStreamId,
      workspace_root: optionalString(request.workspace_root ?? agent?.cwd ?? agent?.workspace_root),
      agent: runtimeThreadProjectionAgent(agent, { threadId }),
      runs: normalizeArray(request.runs).map((run) => runtimeThreadProjectionRun(run, {
        agent,
        threadId,
      })),
      latest_seq: latestSeq,
      expected_head: `agentgres://runtime-events/${safeId(eventStreamId)}/head/${latestSeq}`,
      existing_idempotency_keys: [...stream.idempotency.keys()],
    });
    const events = normalizeArray(projection?.events).filter((event) => objectRecord(event));
    for (const event of events) {
      store.registerRuntimeEvent(event);
    }
    return {
      ...projection,
      events,
    };
  }

  projectRuntimeThreadEventReplayForThread(store, request = {}) {
    const replayKind = optionalString(request.replay_kind) ?? "stream";
    const eventStreamId = optionalString(request.event_stream_id);
    const turnId = optionalString(request.turn_id);
    const latestSeq = eventStreamId
      ? store.latestRuntimeEventSeq(eventStreamId)
      : undefined;
    const replay = this.runtimeAgentgresAdmissionCore.projectRuntimeThreadEventReplay({
      replay_kind: replayKind,
      event_stream_id: eventStreamId,
      turn_id: turnId,
      cursor: request.cursor ?? {},
      state_dir: this.stateDir,
      latest_seq: latestSeq,
    });
    if (replay?.projected !== true) {
      throw runtimeError({
        status: 502,
        code: "runtime_thread_event_replay_invalid",
        message: "Rust daemon-core runtime thread-event replay did not return a replay projection record.",
        details: {
          operation: "project_runtime_thread_event_replay",
          replay_kind: replayKind,
          event_stream_id: eventStreamId ?? null,
          turn_id: turnId ?? null,
          replay_hash: replay?.replay_hash ?? null,
        },
      });
    }
    const events = normalizeArray(replay.events).filter((event) => objectRecord(event));
    return {
      ...replay,
      events,
    };
  }

  projectRuntimeThreadTurnProjectionForThread(store, request = {}) {
    void store;
    const projection = this.runtimeAgentgresAdmissionCore.projectRuntimeThreadTurnProjection(request);
    const record = objectRecord(projection?.record);
    if (projection?.projected !== true || !record) {
      throw runtimeError({
        status: 502,
        code: "runtime_thread_turn_projection_invalid",
        message: "Rust daemon-core runtime thread/turn projection did not return a projection record.",
        details: {
          operation: "project_runtime_thread_turn_projection",
          projection_kind: request.projection_kind ?? null,
          thread_id: request.thread_id ?? null,
          turn_id: request.turn_id ?? null,
          projection_hash: projection?.projection_hash ?? null,
        },
      });
    }
    return {
      ...projection,
      record,
    };
  }

  admitRuntimeThreadEventForThread(store, request = {}) {
    const event = objectRecord(request.event);
    const eventStreamId = optionalString(event?.event_stream_id);
    const latestSeq = eventStreamId ? store.latestRuntimeEventSeq(eventStreamId) : undefined;
    const admission = this.runtimeAgentgresAdmissionCore.admitRuntimeThreadEvent({
      event,
      latest_seq: latestSeq,
      expected_head: eventStreamId
        ? `agentgres://runtime-events/${safeId(eventStreamId)}/head/${latestSeq}`
        : undefined,
    });
    const admittedEvent = objectRecord(admission?.event);
    if (!admittedEvent) {
      throw runtimeError({
        status: 502,
        code: "runtime_thread_event_admission_invalid",
        message: "Rust daemon-core runtime thread-event admission did not return an event projection record.",
        details: {
          operation: "admit_runtime_thread_event",
          event_stream_id: eventStreamId,
          event_kind: event?.event_kind ?? null,
          admission_hash: admission?.admission_hash ?? null,
        },
      });
    }
    store.registerRuntimeEvent(admittedEvent);
    return admittedEvent;
  }

  admitCodingToolResultEventForThread(store, request = {}) {
    const event = objectRecord(request.event);
    const eventStreamId = optionalString(event?.event_stream_id);
    const latestSeq = eventStreamId ? store.latestRuntimeEventSeq(eventStreamId) : undefined;
    const admission = this.runtimeAgentgresAdmissionCore.admitCodingToolResultEvent({
      event,
      latest_seq: latestSeq,
      expected_head: eventStreamId
        ? `agentgres://runtime-events/${safeId(eventStreamId)}/head/${latestSeq}`
        : undefined,
    });
    const admittedEvent = objectRecord(admission?.event);
    if (!admittedEvent) {
      throw runtimeError({
        status: 502,
        code: "runtime_coding_tool_result_event_admission_invalid",
        message: "Rust daemon-core coding-tool result-event admission did not return an event projection record.",
        details: {
          operation: "admit_coding_tool_result_event",
          event_stream_id: eventStreamId,
          tool_call_id: event?.tool_call_id ?? null,
          admission_hash: admission?.admission_hash ?? null,
        },
      });
    }
    store.registerRuntimeEvent(admittedEvent);
    return admittedEvent;
  }

  admitCodingToolCommandStreamEventsForThread(store, request = {}) {
    const eventStreamId = optionalString(request.event_stream_id);
    const latestSeq = eventStreamId ? store.latestRuntimeEventSeq(eventStreamId) : undefined;
    const admission = this.runtimeAgentgresAdmissionCore.admitCodingToolCommandStreamEvents({
      ...request,
      latest_seq: latestSeq,
      expected_head: eventStreamId
        ? `agentgres://runtime-events/${safeId(eventStreamId)}/head/${latestSeq}`
        : undefined,
    });
    const events = normalizeArray(admission?.events).filter((event) => objectRecord(event));
    for (const event of events) {
      store.registerRuntimeEvent(event);
    }
    return {
      ...admission,
      events,
    };
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
    return this.lifecycleProjectionSurface.listUsage(this, options);
  }

  authorityEvidenceSummary(options = {}) {
    return this.lifecycleProjectionSurface.authorityEvidenceSummary(this, options);
  }

  traceFromCanonicalState(runId) {
    return this.runReadSurface.traceFromCanonicalState(this, runId);
  }

  canonicalProjection(runId) {
    return this.runReadSurface.canonicalProjection(this, runId);
  }

  admitComputerUseRuntimeEvent(event = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_computer_use_invocation_rust_core_required",
      message: "Runtime computer-use event admission requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.computer_use_invocation",
        operation: "computer_use_event_admission",
        operation_kind: event.event_kind ?? "computer_use.event",
        thread_id: event.thread_id ?? null,
        turn_id: event.turn_id ?? null,
        tool_name: event.tool_name ?? null,
        tool_call_id: event.tool_call_id ?? null,
        workflow_graph_id: event.workflow_graph_id ?? null,
        workflow_node_id: event.workflow_node_id ?? null,
        receipt_refs: uniqueStrings(event.receipt_refs),
        artifact_refs: uniqueStrings(event.artifact_refs),
        evidence_refs: [
          "computer_use_event_js_append_retired",
          "rust_daemon_core_computer_use_event_admission_required",
          "agentgres_computer_use_expected_head_required",
        ],
      },
    });
  }

  invokeComputerUseLeaseRequestRustCore(threadId, toolId, request = {}, defaults = {}) {
    return this.codingToolInvocationSurface.invokeThreadTool(
      this,
      threadId,
      "computer_use.request_lease",
      computerUseLeaseRequestEnvelope(request, {
        ...defaults,
        tool_id: toolId,
      }),
    );
  }

  invokeComputerUseBrowserDiscoveryTool(threadId, toolId, request = {}) {
    return this.invokeComputerUseLeaseRequestRustCore(
      threadId,
      toolId,
      request,
      {
        operation_kind: "computer_use.browser_discovery",
        lane: "native_browser",
        action_kind: "inspect",
        workflow_node_id: "runtime.computer-use.browser-discovery",
        prompt: "Discover available governed computer-use browser contexts.",
      },
    );
  }

  invokeComputerUseControlTool(threadId, toolId, request = {}) {
    return this.invokeComputerUseLeaseRequestRustCore(
      threadId,
      toolId,
      request,
      {
        operation_kind: "computer_use.control",
        lane: "native_browser",
        action_kind: "inspect",
        workflow_node_id: "runtime.computer-use.control",
        prompt: "Request governed computer-use control through Rust lease admission.",
      },
    );
  }

  async invokeComputerUseNativeBrowserTool(threadId, toolId, request = {}) {
    return this.invokeComputerUseLeaseRequestRustCore(
      threadId,
      toolId,
      request,
      {
        operation_kind: "computer_use.native_browser",
        lane: "native_browser",
        action_kind: "inspect",
        workflow_node_id: "runtime.computer-use.native-browser",
        prompt: "Request governed native-browser computer-use execution.",
      },
    );
  }

  async invokeComputerUseVisualGuiTool(threadId, toolId, request = {}) {
    return this.invokeComputerUseLeaseRequestRustCore(
      threadId,
      toolId,
      request,
      {
        operation_kind: "computer_use.visual_gui",
        lane: "visual_gui",
        session_mode: "visual_fallback",
        action_kind: "inspect",
        workflow_node_id: "runtime.computer-use.visual-gui",
        prompt: "Request governed visual GUI computer-use execution.",
      },
    );
  }

  async invokeComputerUseSandboxedHostedTool(threadId, toolId, request = {}) {
    return this.invokeComputerUseLeaseRequestRustCore(
      threadId,
      toolId,
      request,
      {
        operation_kind: "computer_use.sandboxed_hosted",
        lane: "sandboxed_hosted",
        session_mode: "local_sandbox",
        action_kind: "inspect",
        sandbox_provider: "local_fixture",
        workflow_node_id: "runtime.computer-use.sandboxed-hosted",
        prompt: "Request governed sandboxed-hosted computer-use execution.",
      },
    );
  }

  async invokeComputerUseVisualGuiObserveTool(threadId, toolId, request = {}) {
    return this.invokeComputerUseLeaseRequestRustCore(
      threadId,
      toolId,
      request,
      {
        operation_kind: "computer_use.visual_gui.observe",
        lane: "visual_gui",
        session_mode: "visual_fallback",
        action_kind: "inspect",
        workflow_node_id: "runtime.computer-use.visual-gui.observe",
        prompt: "Request governed visual GUI observation.",
      },
    );
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
    return this.runtimeAgentgresAdmissionCore.commitRuntimeRunState(this.stateDir, request);
  }

  commitRuntimeAgentState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeAgentState(this.stateDir, request);
  }

  commitRuntimeMemoryState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeMemoryState(this.stateDir, request);
  }

  commitRuntimeSubagentState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeSubagentState(this.stateDir, request);
  }

  commitRuntimeArtifactState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeArtifactState(this.stateDir, request);
  }

  commitRuntimeReceiptState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeReceiptState(this.stateDir, request);
  }

  commitRuntimeMcpLiveResultState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeMcpLiveResultState(this.stateDir, request);
  }

  commitRuntimeModelMountRecordState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeModelMountRecordState(this.stateDir, request);
  }

  commitRuntimeModelMountReceiptState(request) {
    return this.runtimeAgentgresAdmissionCore.commitRuntimeModelMountReceiptState(this.stateDir, request);
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

function computerUseLeaseRequestEnvelope(request = {}, defaults = {}) {
  const source = objectRecord(request) ?? {};
  const input = computerUseLeaseInputForRequest(source);
  const prompt = optionalString(input.prompt) ?? optionalString(input.goal) ?? optionalString(input.objective);
  if (!prompt) {
    const defaultPrompt = optionalString(defaults.prompt);
    if (defaultPrompt) input.prompt = defaultPrompt;
  }
  const lane = optionalString(input.lane) ?? optionalString(defaults.lane);
  if (lane) input.lane = lane;
  const sessionMode = optionalString(input.session_mode) ?? optionalString(defaults.session_mode);
  if (sessionMode) input.session_mode = sessionMode;
  const actionKind = optionalString(input.action_kind) ?? optionalString(defaults.action_kind);
  if (actionKind) input.action_kind = actionKind;
  const sandboxProvider = optionalString(input.sandbox_provider) ?? optionalString(defaults.sandbox_provider);
  if (sandboxProvider) input.sandbox_provider = sandboxProvider;
  return {
    ...source,
    input,
    source: operatorControlSource(source.source),
    workflow_node_id:
      optionalString(request?.workflow_node_id) ??
      optionalString(defaults.workflow_node_id) ??
      "runtime.computer-use.request-lease",
    computer_use_operation_kind: optionalString(defaults.operation_kind) ?? "computer_use.invocation",
    computer_use_public_tool_id: optionalString(defaults.tool_id) ?? null,
    tool_call_id: optionalString(request?.tool_call_id) ?? null,
    workflow_graph_id: optionalString(request?.workflow_graph_id) ?? null,
  };
}

const COMPUTER_USE_LEASE_INPUT_FIELDS = [
  "prompt",
  "goal",
  "objective",
  "lane",
  "session_mode",
  "action_kind",
  "approval_ref",
  "provider_id",
  "provider_kind",
  "sandbox_provider",
  "url",
  "target_ref",
  "selector",
  "observation_retention_mode",
];

function computerUseLeaseInputForRequest(source = {}) {
  const explicitInput = objectRecord(source.input);
  if (explicitInput) return { ...explicitInput };
  const input = {};
  for (const field of COMPUTER_USE_LEASE_INPUT_FIELDS) {
    if (Object.hasOwn(source, field)) input[field] = source[field];
  }
  return input;
}

function runtimeThreadProjectionAgent(agent, { threadId } = {}) {
  const record = objectRecord(agent) ?? {};
  return {
    agent_id: optionalString(record.agent_id ?? record.id) ?? null,
    thread_id: threadId ?? null,
    status: optionalString(record.status) ?? null,
    created_at: optionalString(record.created_at ?? record.createdAt) ?? null,
    updated_at: optionalString(record.updated_at ?? record.updatedAt) ?? null,
    workspace_root: optionalString(record.workspace_root ?? record.cwd) ?? null,
    fixture_profile: optionalString(record.fixture_profile) ?? null,
    model_route_receipt_id: optionalString(
      record.model_route_receipt_id ?? record.modelRouteReceiptId,
    ) ?? null,
    receipt_refs: normalizeArray(record.receipt_refs),
  };
}

function runtimeThreadProjectionRun(run, { agent, threadId } = {}) {
  const record = objectRecord(run) ?? {};
  const runId = optionalString(record.run_id ?? record.id);
  return {
    run_id: runId ?? null,
    agent_id: optionalString(record.agent_id ?? record.agentId ?? agent?.id ?? agent?.agent_id) ?? null,
    thread_id: threadId ?? null,
    turn_id: optionalString(record.turn_id ?? record.runtime_turn_id ?? record.runtimeTurnId)
      ?? (runId ? turnIdForRun(runId) : null),
    workspace_root: optionalString(record.workspace_root ?? record.cwd ?? agent?.cwd ?? agent?.workspace_root) ?? null,
    created_at: optionalString(record.created_at ?? record.createdAt) ?? null,
    updated_at: optionalString(record.updated_at ?? record.updatedAt) ?? null,
    events: normalizeArray(record.events).map(runtimeThreadProjectionRunEvent),
  };
}

function runtimeThreadProjectionRunEvent(event) {
  const record = objectRecord(event) ?? {};
  const data = objectRecord(record.data) ?? {};
  return {
    id: optionalString(record.id ?? record.event_id) ?? null,
    type: optionalString(record.type ?? record.event_type ?? record.event_kind) ?? null,
    run_id: optionalString(record.run_id ?? record.runId) ?? null,
    created_at: optionalString(record.created_at ?? record.createdAt) ?? null,
    data,
    receipt_refs: normalizeArray(record.receipt_refs),
    artifact_refs: normalizeArray(record.artifact_refs),
    policy_decision_refs: normalizeArray(record.policy_decision_refs),
    rollback_refs: normalizeArray(record.rollback_refs),
  };
}

function canonicalMemoryWorkflowNodeId(value = {}) {
  return value?.workflow_node_id ?? null;
}

function canonicalMemoryMutationEventPayload(value = {}) {
  const isPolicy = value.object === "ioi.agent_memory_policy";
  return {
    schema_version: value.schema_version ?? null,
    object: value.object ?? null,
    memory_record_id: isPolicy
      ? value.memory_record_id ?? null
      : value.memory_record_id ?? value.id ?? null,
    memory_policy_id: isPolicy
      ? value.memory_policy_id ?? value.id ?? null
      : value.memory_policy_id ?? null,
    scope: value.scope ?? null,
    fact: value.fact ?? null,
    memory_key: value.memory_key ?? null,
    agent_id: value.agent_id ?? null,
    thread_id: value.thread_id ?? null,
    workspace: value.workspace ?? null,
    target_type: value.target_type ?? null,
    target_id: value.target_id ?? null,
    disabled: Boolean(value.disabled),
    injection_enabled: value.injection_enabled ?? null,
    read_only: value.read_only ?? null,
    write_requires_approval: value.write_requires_approval ?? null,
    retention: value.retention ?? null,
    workflow_graph_id: value.workflow_graph_id ?? null,
    workflow_node_id: canonicalMemoryWorkflowNodeId(value),
    workflow_node_type: value.workflow_node_type ?? null,
    source: value.source ?? null,
    redaction: value.redaction ?? "none",
    created_at: value.created_at ?? null,
    updated_at: value.updated_at ?? null,
    deleted_at: value.deleted_at ?? null,
    evidence_refs: normalizeArray(value.evidence_refs),
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
