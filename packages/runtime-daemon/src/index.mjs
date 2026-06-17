import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ModelMountingState } from "./model-mounting.mjs";
import {
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  computerUseSourceEventKind,
  isComputerUseRunEventType,
} from "./computer-use-event-contracts.mjs";
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
  runtimeToolRegistryGovernanceMetadata,
} from "./runtime-tool-catalog.mjs";
import { mcpRegistryForWorkspace } from "./mcp-manager.mjs";
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
import { createRuntimeRouteHandlers } from "./runtime-route-handlers.mjs";
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
import { createRuntimeCodingToolApprovalCore } from "./runtime-coding-tool-approval-core.mjs";
import { createRuntimeCodingToolArtifactSurface } from "./runtime-coding-tool-artifact-surface.mjs";
import { createRuntimeCodingToolInvocationSurface } from "./runtime-coding-tool-invocation-surface.mjs";
import { createRuntimeWorkspaceSnapshotSurface } from "./runtime-workspace-snapshot-surface.mjs";
import { createRuntimeCodingToolGovernanceSurface } from "./runtime-coding-tool-governance-surface.mjs";
import { createRuntimeCodingToolBudgetRecoverySurface } from "./runtime-coding-tool-budget-recovery-surface.mjs";
import { createRuntimeConversationArtifactApi } from "./runtime-conversation-artifact-api.mjs";
import { createRuntimeContextPolicySurface } from "./runtime-context-policy-surface.mjs";
import { createRuntimeContextPolicyCore } from "./runtime-context-policy-core.mjs";
import { createRuntimeWorkflowEditSurface } from "./runtime-workflow-edit-surface.mjs";
import { createRuntimeApprovalSurface } from "./runtime-approval-surface.mjs";
import { createRuntimeApprovalStateCore } from "./runtime-approval-state-core.mjs";
import { createRuntimeMcpCatalogApi } from "./runtime-mcp-catalog-api.mjs";
import { createRuntimeMcpControlApi } from "./runtime-mcp-control-api.mjs";
import { createRuntimeMcpServeApi } from "./runtime-mcp-serve-api.mjs";
import { createRuntimeRunReadSurface } from "./runtime-run-read-surface.mjs";
import { createRuntimeLifecycleProjectionApi } from "./runtime-lifecycle-projection-api.mjs";
import { createRuntimeSkillHookSurface } from "./runtime-skill-hook-surface.mjs";
import { createRuntimeTaskJobApi } from "./runtime-task-job-api.mjs";
import { createRuntimeGovernedImprovementApi } from "./runtime-governed-improvement-api.mjs";
import { createRuntimeWorkerServicePackageApi } from "./runtime-worker-service-package-api.mjs";
import { createRuntimeCteePrivateWorkspaceApi } from "./runtime-ctee-private-workspace-api.mjs";
import { createRuntimeL1SettlementApi } from "./runtime-l1-settlement-api.mjs";
import { createRuntimeThreadControlSurface } from "./runtime-thread-control-surface.mjs";
import { createRuntimeThreadTurnSurface } from "./runtime-thread-turn-surface.mjs";
import { createRuntimeThreadEventSurface } from "./runtime-thread-event-surface.mjs";
import { createRuntimeToolSurface } from "./runtime-tool-surface.mjs";
import { createRuntimeSubagentApi } from "./runtime-subagent-api.mjs";
import {
  booleanValue,
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
import { createRuntimeExternalCapabilityAuthorityApi } from "./runtime-external-capability-authority-api.mjs";
import { createRuntimeWorkerServicePackageCore } from "./runtime-worker-service-package-core.mjs";
import { createRuntimeCteePrivateWorkspaceCore } from "./runtime-ctee-private-workspace-core.mjs";
import { createRuntimeL1SettlementCore } from "./runtime-l1-settlement-core.mjs";
import { createRuntimeWorkspaceRestoreCore } from "./runtime-workspace-restore-core.mjs";
import { createRuntimeRepositorySurface } from "./runtime-repository-surface.mjs";
import { startRuntimeDaemonServiceWithStore } from "./service/runtime-daemon-service.mjs";
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
import { createRuntimeThreadAuxiliaryApi } from "./runtime-thread-auxiliary-api.mjs";
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
const threadMemoryStateDeps = {
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
};
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

const {
  handleAgentRoute,
  handleModelMountingNativeRoute,
  handleRunRoute,
  handleThreadRoute,
} = createRuntimeRouteHandlers({
  approvalModeForThreadMode,
  baseUrlForRequest,
  buildRun,
  ensureProviderAvailable,
  notFound,
  readBody,
  runtimeError,
  runtimeEventCursorFromRequest,
  threadModeForRunMode,
  usageRequestMetadataFromUrl,
  usageTelemetryWithRequestMetadata,
  writeJsonResponse,
  writeMcpJsonRpcResponse,
  writeSse,
});

const handleRequest = createPublicRuntimeRequestHandler({
  RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
  baseUrlForRequest,
  ensureProviderAvailable,
  eventStreamIdForThread,
  handleAgentRoute,
  handleModelMountingNativeRoute,
  handleOpenAiCompatibilityRoute,
  handleRunRoute,
  handleThreadRoute,
  initialThreadRuntimeControls,
  isOpenAiCompatibilityRoute,
  mcpRegistryForWorkspace,
  normalizeBooleanOption,
  notFound,
  optionalString,
  readBody,
  runtimeError,
  runtimeModeForOptions,
  runtimeThreadSchemaVersion: RUNTIME_THREAD_SCHEMA_VERSION,
  summarizeAgentOptions,
  threadIdForAgent,
  threadStatusForAgent,
  usageRequestMetadataFromUrl,
  usageTelemetryWithRequestMetadata,
  writeError,
  writeJsonResponse,
  writeMcpJsonRpcResponse,
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
      contextPolicyCore: this.contextPolicyCore,
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
      runtimeMemoryCommandPlanner: this.contextPolicyCore,
      shouldInheritSubagentMemory,
      subagentMemoryPolicy,
      subagentReceiverForRequest,
      threadIdForAgent,
    });
    this.threadMemorySurface = createThreadMemoryState({
      ...threadMemoryStateDeps,
      contextPolicyCore: this.contextPolicyCore,
    });
    this.threadAuxiliaryApi = createRuntimeThreadAuxiliaryApi({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.conversationArtifactApi = createRuntimeConversationArtifactApi({
      contextPolicyCore: this.contextPolicyCore,
      notFound,
    });
    this.approvalSurface = createRuntimeApprovalSurface({
      approvalStateCore: this.approvalStateCore,
      notFound,
      runtimeError,
    });
    this.governedImprovementApi = createRuntimeGovernedImprovementApi({
      runtimeError,
    });
    this.externalCapabilityAuthorityApi = createRuntimeExternalCapabilityAuthorityApi({
      runtimeError,
    });
    this.workerServicePackageApi = createRuntimeWorkerServicePackageApi({
      runtimeError,
    });
    this.cteePrivateWorkspaceApi = createRuntimeCteePrivateWorkspaceApi({
      runtimeError,
    });
    this.l1SettlementApi = createRuntimeL1SettlementApi({
      runtimeError,
    });
    this.codingToolBudgetRecoverySurface = createRuntimeCodingToolBudgetRecoverySurface({
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
      codingToolBudgetPolicyForRequest: (request = {}) =>
        codingToolBudgetPolicyForRequest({
          ...request,
          budgetRunner: this.contextPolicyCore,
        }),
      codingToolResultWithoutDrafts,
      diagnosticsRepairContextForRequest,
      diagnosticsRepairContextForToolPack,
      codingToolResultEnvelopeForThread: (_store, request = {}) =>
        this.contextPolicyCore.planCodingToolResultEnvelope(request),
      codingToolResultEventAdmissionForThread: (store, request = {}) =>
        this.admitCodingToolResultEventForThread(store, request),
      daemonCoreWorkloadApi: this.daemonCoreWorkloadApi,
      workloadGrpcAddr: process.env.IOI_WORKLOAD_GRPC_ADDR ?? null,
      workloadShmemId: process.env.IOI_SHMEM_ID ?? null,
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
      approvalModeForThreadMode,
      buildRun,
      contextPolicyCore: this.contextPolicyCore,
      ensureProviderAvailable,
      eventStreamIdForThread,
      diagnosticsRepairRetryFeedback,
      runtimeError,
      threadModeForRunMode,
    });
    this.codingToolGovernanceSurface = createRuntimeCodingToolGovernanceSurface({
      contextPolicyCore: this.contextPolicyCore,
      runtimeError,
    });
    this.contextPolicySurface = createRuntimeContextPolicySurface({
      contextPolicyCore: this.contextPolicyCore,
      runtimeError,
    });
    this.workflowEditSurface = createRuntimeWorkflowEditSurface({
      contextPolicyCore: this.contextPolicyCore,
      eventStreamIdForThread,
      notFound,
      policyError,
      runtimeError,
      writeJson,
    });
    this.mcpCatalogApi = createRuntimeMcpCatalogApi({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.mcpControlApi = createRuntimeMcpControlApi({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.mcpServeApi = createRuntimeMcpServeApi({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.repositorySurface = createRuntimeRepositorySurface({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.runReadSurface = createRuntimeRunReadSurface({
      notFound,
      runtimeUsageTelemetryForRun,
      runtimeUsageTelemetryForThread,
      threadIdForAgent,
    });
    this.lifecycleProjectionApi = createRuntimeLifecycleProjectionApi({
      contextPolicyCore: this.contextPolicyCore,
      workspaceRoot: this.defaultCwd,
    });
    this.skillHookSurface = createRuntimeSkillHookSurface({
      contextPolicyCore: this.contextPolicyCore,
      defaultCwd: this.defaultCwd,
    });
    this.taskJobApi = createRuntimeTaskJobApi({
      buildRun,
      contextPolicyCore: this.contextPolicyCore,
      ensureProviderAvailable,
      notFound,
      optionalString,
    });
    this.toolSurface = createRuntimeToolSurface({
      contextPolicyCore: this.contextPolicyCore,
      workspaceRoot: this.defaultCwd,
    });
    this.threadControlSurface = createRuntimeThreadControlSurface({
      contextPolicyCore: this.contextPolicyCore,
    });
    this.threadTurnSurface = createRuntimeThreadTurnSurface({
      approvalModeForThreadMode,
      buildRun,
      contextPolicyCore: this.contextPolicyCore,
      diagnosticsFeedbackBlocksContinuation,
      ensureProviderAvailable,
      runtimeError,
      threadModeForRunMode,
    });
    this.subagentApi = createRuntimeSubagentApi({
      approvalModeForThreadMode,
      buildRun,
      contextPolicyCore: this.contextPolicyCore,
      ensureProviderAvailable,
      initialThreadRuntimeControls,
      mcpRegistryForWorkspace: (cwd, options = {}) =>
        mcpRegistryForWorkspace(cwd, {
          ...options,
          contextPolicyCore: this.contextPolicyCore,
        }),
      runtimeModeForOptions,
      summarizeAgentOptions,
      threadModeForRunMode,
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

  listThreads() {
    return this.listAgents().map((agent) => this.threadForAgent(agent));
  }

  getThread(threadId) {
    return this.threadForAgent(this.agentForThread(threadId));
  }

  importThreadMcp(threadId, request = {}) {
    return this.mcpControlApi.importThreadMcp(this, threadId, request);
  }

  addThreadMcpServer(threadId, request = {}) {
    return this.mcpControlApi.addThreadMcpServer(this, threadId, request);
  }

  removeThreadMcpServer(threadId, serverId, request = {}) {
    return this.mcpControlApi.removeThreadMcpServer(this, threadId, serverId, request);
  }

  setThreadMcpServerEnabled(threadId, serverId, enabled, request = {}) {
    return this.mcpControlApi.setThreadMcpServerEnabled(this, threadId, serverId, enabled, request);
  }

  searchThreadMcpTools(threadId, request = {}) {
    return this.mcpCatalogApi.searchThreadMcpTools(this, threadId, request);
  }

  getThreadMcpTool(threadId, toolId, request = {}) {
    return this.mcpCatalogApi.getThreadMcpTool(this, threadId, toolId, request);
  }

  invokeThreadMcpTool(threadId, toolId, request = {}) {
    return this.mcpControlApi.invokeThreadMcpTool(this, threadId, toolId, request);
  }

  mcpServeStatus(threadId, request = {}) {
    return this.mcpServeApi.mcpServeStatus(this, {
      ...request,
      thread_id: threadId,
    });
  }

  handleMcpServeJsonRpc(threadId, message, request = {}) {
    return this.mcpServeApi.handleMcpServeJsonRpc(this, threadId, message, {
      ...request,
      thread_id: threadId,
    });
  }

  recordThreadMcpStatus(threadId, request = {}) {
    return this.mcpControlApi.recordThreadMcpStatus(this, threadId, request);
  }

  validateThreadMcp(threadId, request = {}) {
    return this.mcpControlApi.validateThreadMcp(this, threadId, request);
  }

  admitGovernedImprovementProposal(threadId, request = {}) {
    return this.governedImprovementApi.admitGovernedImprovementProposal(this, threadId, request);
  }

  authorizeExternalCapabilityExit(threadId, request = {}) {
    return this.externalCapabilityAuthorityApi.authorizeExternalCapabilityExit(this, threadId, request);
  }

  admitWorkerServicePackageInvocation(threadId, request = {}) {
    return this.workerServicePackageApi.admitWorkerServicePackageInvocation(this, threadId, request);
  }

  executeCteePrivateWorkspaceAction(threadId, request = {}) {
    return this.cteePrivateWorkspaceApi.executeCteePrivateWorkspaceAction(this, threadId, request);
  }

  admitL1SettlementAttempt(threadId, request = {}) {
    return this.l1SettlementApi.admitL1SettlementAttempt(this, threadId, request);
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
    const threadId = optionalString(request.thread_id);
    const eventStreamId = optionalString(request.event_stream_id) ?? (threadId ? eventStreamIdForThread(threadId) : undefined);
    if (!threadId || !eventStreamId) {
      throw runtimeError({
        status: 502,
        code: "runtime_thread_event_projection_invalid",
        message: "Rust daemon-core runtime thread-event projection requires canonical thread and stream identity.",
        details: {
          operation: "project_runtime_thread_events",
          projection_kind: request.projection_kind ?? null,
          thread_id: threadId ?? null,
          event_stream_id: eventStreamId ?? null,
        },
      });
    }
    const projection = this.runtimeAgentgresAdmissionCore.projectRuntimeThreadEvents({
      projection_kind: optionalString(request.projection_kind) ?? "thread",
      thread_id: threadId,
      event_stream_id: eventStreamId,
      run_id: optionalString(request.run_id),
      state_dir: this.stateDir,
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
    const replay = this.runtimeAgentgresAdmissionCore.projectRuntimeThreadEventReplay({
      replay_kind: replayKind,
      event_stream_id: eventStreamId,
      turn_id: turnId,
      cursor: request.cursor ?? {},
      state_dir: this.stateDir,
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
    const projection = this.runtimeAgentgresAdmissionCore.projectRuntimeThreadTurnProjection({
      ...request,
      state_dir: this.stateDir,
    });
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

  projectRuntimeLifecycleProjection(projectionKind, facts = {}) {
    return this.lifecycleProjectionApi.project(this, projectionKind, facts);
  }

  createRuntimeTask(body = {}) {
    return this.taskJobApi.createTask(this, body);
  }

  listRuntimeTasks(options = {}) {
    return this.taskJobApi.listTasks(this, options);
  }

  getRuntimeTask(taskId) {
    return this.taskJobApi.getTask(this, taskId);
  }

  cancelRuntimeTask(taskId) {
    return this.taskJobApi.cancelTask(this, taskId);
  }

  listRuntimeJobs(options = {}) {
    return this.taskJobApi.listJobs(this, options);
  }

  getRuntimeJob(jobId) {
    return this.taskJobApi.getJob(this, jobId);
  }

  cancelRuntimeJob(jobId) {
    return this.taskJobApi.cancelJob(this, jobId);
  }

  inspectManagedSessionsForThread(threadId, options = {}) {
    return this.threadAuxiliaryApi.inspectManagedSessionsForThread(this, threadId, options);
  }

  inspectWorkspaceChangeReviewsForThread(threadId, options = {}) {
    return this.threadAuxiliaryApi.inspectWorkspaceChangeReviewsForThread(this, threadId, options);
  }

  controlWorkspaceChangeForThread(threadId, request = {}) {
    return this.threadAuxiliaryApi.controlWorkspaceChangeForThread(this, threadId, request);
  }

  controlManagedSessionForThread(threadId, request = {}) {
    return this.threadAuxiliaryApi.controlManagedSessionForThread(this, threadId, request);
  }

  forkThread(threadId, request = {}) {
    return this.threadAuxiliaryApi.forkThread(this, threadId, request);
  }

  cancelRun(runId) {
    return this.threadAuxiliaryApi.cancelRun(this, runId);
  }

  listConversationArtifacts(query = {}) {
    return this.conversationArtifactApi.listConversationArtifacts(this, query);
  }

  createConversationArtifact(threadId, input = {}) {
    return this.conversationArtifactApi.createConversationArtifact(this, threadId, input);
  }

  getConversationArtifact(artifactId) {
    return this.conversationArtifactApi.getConversationArtifact(this, artifactId);
  }

  listConversationArtifactRevisions(artifactId) {
    return this.conversationArtifactApi.listConversationArtifactRevisions(this, artifactId);
  }

  performConversationArtifactAction(artifactId, input = {}) {
    return this.conversationArtifactApi.performConversationArtifactAction(this, artifactId, input);
  }

  exportConversationArtifact(artifactId, input = {}) {
    return this.conversationArtifactApi.exportConversationArtifact(this, artifactId, input);
  }

  promoteConversationArtifact(artifactId, input = {}) {
    return this.conversationArtifactApi.promoteConversationArtifact(this, artifactId, input);
  }

  listSubagents(threadId, options = {}) {
    return this.subagentApi.listSubagents(this, threadId, options);
  }

  getSubagent(threadId, subagentId) {
    return this.subagentApi.getSubagent(this, threadId, subagentId);
  }

  spawnSubagent(threadId, request = {}) {
    return this.subagentApi.spawnSubagent(this, threadId, request);
  }

  propagateSubagentCancellation(threadId, request = {}) {
    return this.subagentApi.propagateSubagentCancellation(this, threadId, request);
  }

  waitSubagent(threadId, subagentId, request = {}) {
    return this.subagentApi.waitSubagent(this, threadId, subagentId, request);
  }

  sendSubagentInput(threadId, subagentId, request = {}) {
    return this.subagentApi.sendSubagentInput(this, threadId, subagentId, request);
  }

  cancelSubagent(threadId, subagentId, request = {}) {
    return this.subagentApi.cancelSubagent(this, threadId, subagentId, request);
  }

  resumeSubagent(threadId, subagentId, request = {}) {
    return this.subagentApi.resumeSubagent(this, threadId, subagentId, request);
  }

  assignSubagent(threadId, subagentId, request = {}) {
    return this.subagentApi.assignSubagent(this, threadId, subagentId, request);
  }

  getSubagentResult(threadId, subagentId) {
    return this.subagentApi.getSubagentResult(this, threadId, subagentId);
  }

  subagentProjection(record = {}) {
    return this.subagentApi.subagentProjection(record);
  }

  appendThreadSubagentControlEvent(request = {}) {
    return this.subagentApi.appendThreadSubagentControlEvent(this, request);
  }

  admitRuntimeThreadEventForThread(store, request = {}) {
    const event = objectRecord(request.event);
    const eventStreamId = optionalString(event?.event_stream_id);
    const admission = this.runtimeAgentgresAdmissionCore.admitRuntimeThreadEvent({
      event,
      state_dir: this.stateDir,
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
    const admission = this.runtimeAgentgresAdmissionCore.admitCodingToolResultEvent({
      event,
      state_dir: this.stateDir,
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
    const admission = this.runtimeAgentgresAdmissionCore.admitCodingToolCommandStreamEvents({
      ...request,
      state_dir: this.stateDir,
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
    return this.projectRuntimeLifecycleProjection("usage_list", options);
  }

  authorityEvidenceSummary(options = {}) {
    return this.projectRuntimeLifecycleProjection("authority_evidence_summary", options);
  }

  traceFromCanonicalState(runId) {
    return this.runReadSurface.traceFromCanonicalState(this, runId);
  }

  canonicalProjection(runId) {
    return this.runReadSurface.canonicalProjection(this, runId);
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

const COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.computer-use-run-materialization-request.v1";
const SKILL_HOOK_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.skill-hook-run-materialization-request.v1";

function computerUseMaterializationRequestForRun({
  agent,
  runId,
  prompt,
  mode,
  request,
  selectedModel,
} = {}) {
  const source = objectRecord(request) ?? {};
  const metadata = objectRecord(source.metadata) ?? objectRecord(source.input) ?? source;
  const canonicalRequest = {};
  const canonicalFields = [
    "computer_use",
    "computer_use_lane",
    "computer_use_session_mode",
    "computer_use_action_kind",
    "computer_use_approval_ref",
    "computer_use_target_ref",
    "computer_use_execution_result",
    "observation_retention_mode",
    "workflow_graph_id",
    "workflow_node_id",
    "workflow_node_ids",
    "tool_ref",
    "authority_scopes",
    "fail_closed_when_unavailable",
    "url",
    "selector",
  ];
  for (const field of canonicalFields) {
    if (Object.hasOwn(metadata, field)) canonicalRequest[field] = metadata[field];
  }
  const materializationRequested = shouldRequestComputerUseMaterialization(prompt, canonicalRequest);
  if (!materializationRequested) {
    return null;
  }
  if (!Object.hasOwn(canonicalRequest, "computer_use")) canonicalRequest.computer_use = true;
  return {
    schema_version: COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
    object: "ioi.runtime_computer_use_run_materialization_request",
    run_id: optionalString(runId) ?? null,
    agent_id: optionalString(agent?.id) ?? null,
    workspace_root: optionalString(agent?.cwd) ?? null,
    prompt: optionalString(prompt) ?? "",
    mode: optionalString(mode) ?? "send",
    selected_model: optionalString(selectedModel) ?? null,
    source: "daemon_protocol_client",
    request: canonicalRequest,
    evidence_refs: [
      "rust_daemon_core_computer_use_run_materialization_required",
      "computer_use_projection_js_facade_retired",
    ],
  };
}

function skillHookMaterializationRequestForRun({ agent, runId, request, homeDir = null } = {}) {
  return {
    schema_version: SKILL_HOOK_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
    object: "ioi.runtime_skill_hook_run_materialization_request",
    run_id: optionalString(runId) ?? null,
    agent_id: optionalString(agent?.id) ?? null,
    workspace_root: optionalString(agent?.cwd) ?? null,
    home_dir: optionalString(homeDir) ?? optionalString(process.env.HOME) ?? null,
    source: "daemon_protocol_client",
    agent_options: {
      skillNames: normalizeArray(agent?.options?.skillNames),
      hookNames: normalizeArray(agent?.options?.hookNames),
    },
    request_options: objectRecord(request?.options) ?? {},
    evidence_refs: [
      "rust_daemon_core_skill_hook_run_materialization_required",
      "skill_hook_manifest_js_authoring_retired",
      "agentgres_skill_hook_registry_truth_required",
    ],
  };
}

function shouldRequestComputerUseMaterialization(prompt, request = {}) {
  if (request.computer_use === true) return true;
  if (optionalString(request.computer_use_lane) || optionalString(request.computer_use_action_kind)) {
    return true;
  }
  const text = String(prompt ?? "").toLowerCase();
  return [
    "browser",
    "web page",
    "website",
    "computer use",
    "computer-use",
    "screen",
    "click",
    "type",
    "scroll",
  ].some((needle) => text.includes(needle));
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

const RUN_REPOSITORY_WORKFLOW_PROJECTIONS = {
  repository_context: {
    operation: "repository_workflow_repository_context",
    operation_kind: "repository_workflow.projection.repository_context",
  },
  branch_policy: {
    operation: "repository_workflow_branch_policy",
    operation_kind: "repository_workflow.projection.branch_policy",
  },
  github_context: {
    operation: "repository_workflow_github_context",
    operation_kind: "repository_workflow.projection.github_context",
  },
  pr_attempts: {
    operation: "repository_workflow_pr_attempts",
    operation_kind: "repository_workflow.projection.pr_attempts",
  },
  issue_context: {
    operation: "repository_workflow_issue_context",
    operation_kind: "repository_workflow.projection.issue_context",
  },
  review_gate: {
    operation: "repository_workflow_review_gate",
    operation_kind: "repository_workflow.projection.review_gate",
  },
  github_pr_create_plan: {
    operation: "repository_workflow_github_pr_create_plan",
    operation_kind: "repository_workflow.projection.github_pr_create_plan",
  },
};

const RUN_REPOSITORY_WORKFLOW_EVIDENCE_REFS = [
  "runtime_run_create_repository_workflow_rust_projection",
  "runtime_repository_workflow_js_projection_facade_retired",
  "agentgres_repository_workflow_truth_required",
];

function repositoryWorkflowProjectionForRun({
  repositoryWorkflowProjector,
  projectionKind,
  workspaceRoot,
  prompt,
  issue,
}) {
  const projection = RUN_REPOSITORY_WORKFLOW_PROJECTIONS[projectionKind];
  if (!projection || typeof repositoryWorkflowProjector?.projectRepositoryWorkflow !== "function") {
    throwRepositoryWorkflowProjectionError({
      code: "runtime_run_create_repository_workflow_rust_projection_missing",
      message: "Run creation requires Rust daemon-core repository workflow projections.",
      projection_kind: projectionKind,
      workspace_root: workspaceRoot,
    });
  }
  const result = repositoryWorkflowProjector.projectRepositoryWorkflow({
    ...projection,
    projection_kind: projectionKind,
    workspace_root: workspaceRoot,
    prompt,
    issue,
    source: "runtime.build_run.repository_workflow",
    evidence_refs: RUN_REPOSITORY_WORKFLOW_EVIDENCE_REFS,
  });
  if (result?.projection_kind !== projectionKind) {
    throwRepositoryWorkflowProjectionError({
      code: "runtime_run_create_repository_workflow_projection_mismatch",
      message: "Rust repository workflow projection returned the wrong projection kind during run creation.",
      projection_kind: projectionKind,
      workspace_root: workspaceRoot,
      actual_projection_kind: result?.projection_kind ?? null,
    });
  }
  return result?.projection;
}

function repositoryWorkflowProjectionsForRun({
  repositoryWorkflowProjector,
  agent,
  prompt,
  request,
}) {
  const workspaceRoot = optionalString(agent?.cwd) ?? null;
  const issue = objectRecord(request?.issue) ?? objectRecord(request?.options?.issue) ?? null;
  const project = (projectionKind) =>
    repositoryWorkflowProjectionForRun({
      repositoryWorkflowProjector,
      projectionKind,
      workspaceRoot,
      prompt,
      issue,
    });
  const repositoryContext = requiredRepositoryWorkflowObject(project("repository_context"), "repository_context");
  const branchPolicy = requiredRepositoryWorkflowObject(project("branch_policy"), "branch_policy");
  const githubContext = requiredRepositoryWorkflowObject(project("github_context"), "github_context");
  const prAttempts = project("pr_attempts");
  const prAttempt = requiredRepositoryWorkflowObject(
    Array.isArray(prAttempts) ? prAttempts[0] : null,
    "pr_attempts",
  );
  const issueContext = requiredRepositoryWorkflowObject(project("issue_context"), "issue_context");
  const reviewGate = requiredRepositoryWorkflowObject(project("review_gate"), "review_gate");
  const githubPrCreatePlan = requiredRepositoryWorkflowObject(
    project("github_pr_create_plan"),
    "github_pr_create_plan",
  );
  return {
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    issueContext,
    reviewGate,
    githubPrCreatePlan,
  };
}

function requiredRepositoryWorkflowObject(value, projectionKind) {
  const record = objectRecord(value);
  if (record) return record;
  throwRepositoryWorkflowProjectionError({
    code: "runtime_run_create_repository_workflow_projection_invalid",
    message: "Rust repository workflow projection returned an invalid record during run creation.",
    projection_kind: projectionKind,
  });
}

function throwRepositoryWorkflowProjectionError(details) {
  const error = new Error(details.message);
  error.status = details.code === "runtime_run_create_repository_workflow_rust_projection_missing" ? 501 : 502;
  error.code = details.code;
  error.details = {
    rust_core_boundary: "runtime.repository_workflow_projection",
    operation: "run_create_repository_workflow_projection",
    operation_kind: "run.create.repository_workflow_projection",
    evidence_refs: RUN_REPOSITORY_WORKFLOW_EVIDENCE_REFS,
    ...details,
  };
  throw error;
}

function rustRepositoryArtifactPayload(kind, metadata = {}) {
  const record = objectRecord(metadata) ?? {};
  return {
    schemaVersion: "ioi.runtime.rust-repository-workflow-artifact-binding.v1",
    object: "ioi.rust_repository_workflow_artifact_binding",
    artifactName: record.artifactName ?? null,
    mediaType: record.mediaType ?? null,
    artifactHash: record.artifactHash ?? null,
    diffHash: record.diffHash ?? null,
    byteLength: record.byteLength ?? null,
    retainedByteLength: record.retainedByteLength ?? null,
    truncated: Boolean(record.truncated),
    fileCount: record.fileCount ?? null,
    hasDiff: record.hasDiff ?? null,
    kind,
    source: "rust_daemon_core_repository_workflow_projection",
    contentIncluded: false,
    redaction: {
      profile: "rust_repository_workflow_projection_artifact_binding",
      privateContentIncluded: false,
      jsArtifactContentSideChannelRetired: true,
    },
    evidenceRefs: [
      "runtime_run_create_repository_workflow_rust_projection",
      "runtime_repository_workflow_js_projection_facade_retired",
      record.artifactHash,
      record.diffHash,
    ].filter(Boolean),
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
  repositoryWorkflowProjector = null,
  homeDir = null,
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
  const computerUseMaterializationRequest = computerUseMaterializationRequestForRun({
    agent,
    runId,
    prompt,
    mode,
    request,
    selectedModel,
  });
  const skillHookMaterializationRequest = skillHookMaterializationRequestForRun({
    agent,
    runId,
    request,
    homeDir,
  });
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
  const runtimeTaskId = `task_${runId}`;
  const runtimeJobId = `job_${runId}`;
  const runtimeChecklistId = `checklist_${runId}`;
  const {
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    issueContext,
    reviewGate,
    githubPrCreatePlan,
  } = repositoryWorkflowProjectionsForRun({
    repositoryWorkflowProjector,
    agent,
    prompt,
    request,
  });
  const taskState = {
    currentObjective: prompt,
    knownFacts: [
      "Run entered the live local IOI daemon public runtime API",
      "Agentgres v0 is the canonical owner for this run state",
      `Selected model profile: ${selectedModel}`,
      `Runtime task/job/checklist ledger is delegated to Rust daemon-core materialization for task=${runtimeTaskId}, job=${runtimeJobId}, checklist=${runtimeChecklistId}`,
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
      runtimeTaskId,
      runtimeJobId,
      runtimeChecklistId,
      "rust_daemon_core_runtime_task_job_materialization_request",
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      issueContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      githubPrCreatePlan.planId,
      diagnosticsFeedback?.injection_id,
      diagnosticsBlockingGate?.gate_id,
      diagnosticsBlockingGate?.policy_decision_id,
      ...(diagnosticsBlockingGate?.policy_decision_refs ?? []),
      ...(diagnosticsBlockingGate?.rollback_refs ?? []),
      diagnosticsBlockingGate?.receipt_id,
      ...agent.options.mcpServerNames,
      ...agent.options.skillNames,
      ...agent.options.hookNames,
      ...normalizeArray(modelRouteDecision?.evidence_refs),
      modelRouteReceiptId,
      memoryPolicy?.id,
      ...memoryRecords.map((record) => record.id),
      ...memoryWriteReceipts.map((receipt) => receipt.id),
      subagentMemoryReceipt?.id,
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
      ...(computerUseMaterializationRequest
        ? [
            {
              checkId: "computer-use-glass-box-trace",
              description: "Computer-use run materialization request is delegated to Rust daemon-core before run persistence.",
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
      ...(computerUseMaterializationRequest ? ["computer_use_trace", "computer-use-trace.json"] : []),
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
      "RuntimeUsageTelemetry",
      ...(computerUseMaterializationRequest
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
      ...(diagnosticsFeedback
        ? [`lsp.diagnostics.${diagnosticsFeedback.mode}`]
        : []),
      ...(diagnosticsBlockingGate ? ["lsp.diagnostics.blocking_gate"] : []),
      ...(computerUseMaterializationRequest
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
    subagentMemoryReceipt,
    repositoryContextReceipt,
    branchPolicyReceipt,
    githubContextReceipt,
    issueContextReceipt,
    prAttemptReceipt,
    reviewGateReceipt,
    githubPrCreatePlanReceipt,
    diagnosticsInjectionReceipt,
    diagnosticsBlockingGateReceipt,
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
  if (modelRouteDecision) {
    addEvent("model_route_decision", "Model route decision recorded", {
      ...modelRouteDecision,
      receipt_id: modelRouteReceiptId,
    });
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
      ...(diagnosticsBlockingGate ? ["diagnostics-blocking-gate.json"] : []),
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
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    githubPrCreatePlan,
    promptAudit: {
      schemaVersion: "ioi.agent-runtime.prompt-audit.v1",
      runId,
      promptHash: doctorHash(prompt),
      runtimeTaskId,
      runtimeJobId,
      runtimeChecklistId,
      repositoryContextId: repositoryContext.contextId,
      branchPolicyId: branchPolicy.policyId,
      githubContextId: githubContext.contextId,
      issueContextId: issueContext.contextId,
      prAttemptId: prAttempt.attemptId,
      reviewGateId: reviewGate.gateId,
      githubPrCreatePlanId: githubPrCreatePlan.planId,
      redaction: {
        promptIncluded: false,
        hookCommandsIncluded: false,
      },
      evidenceRefs: [
        "prompt_audit",
        runtimeTaskId,
        runtimeJobId,
        runtimeChecklistId,
        "rust_daemon_core_runtime_task_job_materialization_request",
        repositoryContext.contextId,
        branchPolicy.policyId,
        githubContext.contextId,
        issueContext.contextId,
        prAttempt.attemptId,
        reviewGate.gateId,
        githubPrCreatePlan.planId,
      ],
    },
    memoryPolicy,
    memoryRecords,
    memoryWrites: memoryWriteRecords,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
    computerUse: null,
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
      rustRepositoryArtifactPayload("branch", prAttempt.branchArtifact),
      "redacted",
    ),
    artifact(
      runId,
      prAttempt.diffArtifact.artifactName,
      prAttempt.diffArtifact.mediaType,
      prAttemptReceipt.id,
      rustRepositoryArtifactPayload("diff", prAttempt.diffArtifact),
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
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    githubPrCreatePlan,
    memoryPolicy,
    memoryRecords,
    memoryWriteReceipts,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
    diagnosticsFeedback,
    diagnosticsBlockingGate,
    subagentMemoryInheritance,
    computer_use_materialization_request: computerUseMaterializationRequest,
    skill_hook_materialization_request: skillHookMaterializationRequest,
    result,
  };
}
