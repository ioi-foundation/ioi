export { Agent, AgentSubagent, Cursor, CursorCompatibleAgent, createAgentPlatform } from "./agent.js";
export { Run } from "./run.js";
export { IoiAgentError, ensureIoiAgentError } from "./errors.js";
export { createRuntimeSubstrateClient } from "./substrate-client.js";
export type {
  RuntimeAgentRecord,
  RuntimeArtifact,
  RuntimeRunRecord,
  RuntimeSubstrateClient,
} from "./substrate-client.js";
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
export type {
  AgentQualityLedgerProjection,
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  RuntimeAccountProfile,
  RuntimeNodeProfile,
  RuntimeReceipt,
  RuntimeScorecard,
  RuntimeToolCatalogEntry,
  RuntimeTraceBundle,
  SemanticImpactProjection,
  StopConditionProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";
export type {
  ModelArtifact,
  ModelBackend,
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
