export { Agent, AgentMemory, AgentSubagent, Cursor, CursorCompatibleAgent, createAgentPlatform } from "./agent.js";
export {
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  computerActionHasGrounding,
  defaultComputerUseHarnessContract,
  isActionProposalReadyForExecution,
} from "./computer-use.js";
export { Run } from "./run.js";
export { Thread, Turn } from "./thread.js";
export { IoiAgentError, ensureIoiAgentError } from "./errors.js";
export { createRuntimeSubstrateClient, runtimeThreadEventFromEnvelope } from "./substrate-client.js";
export {
  RUNTIME_APPROVAL_MODES,
  RUNTIME_EVENT_SOURCES,
  RUNTIME_ITEM_ACTORS,
  RUNTIME_ITEM_KINDS,
  RUNTIME_ITEM_STATUSES,
  RUNTIME_THREAD_EVENT_TYPES,
  RUNTIME_THREAD_MODES,
  RUNTIME_THREAD_STATUSES,
  RUNTIME_TTI_SCHEMA_VERSION_LITERALS,
  RUNTIME_TTI_SCHEMA_VERSIONS,
  RUNTIME_TURN_STATUSES,
} from "./messages.js";
export type {
  AgentMemoryPathProjection,
  AgentMemoryProjection,
  DeleteMemoryRecordInput,
  MemoryListOptions,
  MemoryPolicyInput,
  MemoryPolicyUpdateResult,
  RememberMemoryInput,
  RememberMemoryResult,
  RuntimeAgentRecord,
  RuntimeArtifact,
  RuntimeEventStreamOptions,
  RuntimeRunRecord,
  RuntimeSubstrateClient,
  RuntimeThreadToolInvocationResult,
  RuntimeThreadToolInvokeInput,
  RuntimeThreadCompactInput,
  RuntimeThreadCreateInput,
  RuntimeThreadForkInput,
  RuntimeThreadMemoryDeleteInput,
  RuntimeThreadMemoryEditInput,
  RuntimeThreadMemoryInput,
  RuntimeThreadMemoryWriteInput,
  RuntimeThreadMcpInput,
  RuntimeThreadModeInput,
  RuntimeThreadModelInput,
  RuntimeThreadThinkingInput,
  RuntimeUsageListInput,
  RuntimeUsageListResult,
  RuntimeUsageTelemetry,
  RuntimeMemoryStatusOptions,
  RuntimeMemoryValidationInput,
  RuntimeMcpJsonRpcRequest,
  RuntimeMcpJsonRpcResponse,
  RuntimeMcpListOptions,
  RuntimeMcpServeRpcInput,
  RuntimeMcpServerControlInput,
  RuntimeMcpToolSearchInput,
  RuntimeMcpToolInvokeInput,
  RuntimeMcpValidationInput,
  RuntimeSubagentCancellationPropagationResult,
  RuntimeSubagentControlInput,
  RuntimeSubagentLifecycleStatus,
  RuntimeSubagentListInput,
  RuntimeSubagentListResult,
  RuntimeSubagentOutputContractStatus,
  RuntimeSubagentRecord,
  RuntimeSubagentResult,
  RuntimeToolListOptions,
  RuntimeTurnCreateInput,
  RuntimeTurnInterruptInput,
  RuntimeTurnSteerInput,
  UpdateMemoryRecordInput,
} from "./substrate-client.js";
export type {
  ActionProposal,
  AffordanceGraph,
  AffordanceRecord,
  ComputerAction,
  ComputerActionKind,
  ComputerControlAdapterContract,
  ComputerUseHarnessContract,
  ComputerUseLane,
  ComputerUseLease,
  ComputerUseObservationBundle,
  ComputerUseRunState,
  ComputerUseSessionMode,
  ComputerUseTargetEntry,
  ComputerUseVerificationReceipt,
  ComputerUseVerificationStatus,
  EnvironmentOptionRejection,
  EnvironmentSelectionReceipt,
  ObservationRetentionMode,
  TargetIndex,
} from "./computer-use.js";
export type {
  AgentOptions,
  CloudAgentOptions,
  DryRunOptions,
  HandoffOptions,
  HostedWorkerProvider,
  LearnOptions,
  LocalAgentOptions,
  McpServerConfig,
  ModelSelection,
  PlanOptions,
  SandboxOptions,
  SelfHostedWorkerProvider,
  SelfHostedWorkerOptions,
  SendOptions,
  StreamOptions,
  SubagentDefinition,
} from "./options.js";
export type { ThreadCreateOptions } from "./thread.js";
export type {
  AgentQualityLedgerProjection,
  AgentMemoryPolicy,
  AgentMemoryRecord,
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  ModelRouteDecision,
  RuntimeAccountProfile,
  RuntimeApprovalMode,
  RuntimeEventEnvelope,
  RuntimeEventSource,
  RuntimeItemActor,
  RuntimeItemKind,
  RuntimeItemRecord,
  RuntimeItemStatus,
  RuntimeMemoryStatus,
  RuntimeMemoryValidationIssue,
  RuntimeMemoryValidationResult,
  RuntimeMcpCatalogSummary,
  RuntimeMcpServerEntry,
  RuntimeMcpInvocationRecord,
  RuntimeMcpInvocationResult,
  RuntimeMcpStatus,
  RuntimeMcpToolEntry,
  RuntimeMcpToolSearchResult,
  RuntimeMcpValidationIssue,
  RuntimeMcpValidationResult,
  RuntimeNodeProfile,
  RuntimeReceipt,
  RuntimeScorecard,
  RuntimeThreadEvent,
  RuntimeThreadEventType,
  RuntimeThreadMode,
  RuntimeThreadRecord,
  RuntimeThreadStatus,
  RuntimeToolCatalogEntry,
  RuntimeTraceBundle,
  RuntimeTurnRecord,
  RuntimeTurnStatus,
  RuntimeUsageRecord,
  SemanticImpactProjection,
  StopConditionProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";
export type {
  ModelArtifact,
  ModelBackend,
  ModelBackendProcess,
  ModelCatalogEntry,
  ModelCatalogProviderStatus,
  ModelCatalogStatus,
  ModelCapability,
  ModelDownloadJob,
  ModelEndpoint,
  ModelInstance,
  ModelInvocationReceipt,
  ModelLifecycleEvent,
  ModelLoadPolicy,
  ModelHardwareEstimate,
  ModelRuntimeEngine,
  ModelRuntimeEngineDefaultLoadOptions,
  ModelRuntimeEngineProfile,
  ModelProviderKind,
  ModelProviderProfile,
  ModelRoute,
  PermissionToken,
  RuntimeModelCatalogEntry,
} from "./model-mounts.js";

export interface RuntimeToolContract {
  stableToolId: string;
  namespace: string;
  displayName: string;
  inputSchema: string;
  outputSchema: string;
  riskDomain: string;
  effectClass: string;
  concurrencyClass: string;
  timeoutDefaultMs: number;
  timeoutMaxMs: number;
  cancellationBehavior: string;
  primitiveCapabilities: string[];
  authorityScopeRequirements: string[];
  policyTarget: string;
  approvalScopeFields: string[];
  evidenceRequirements: string[];
  replayabilityClassification: string;
  redactionPolicy: string;
  ownerModule: string;
  version: string;
}
