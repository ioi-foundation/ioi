export { Agent, Cursor, CursorCompatibleAgent, createAgentPlatform } from "./agent.js";
export { Run } from "./run.js";
export { IoiAgentError, ensureIoiAgentError } from "./errors.js";
export { createRuntimeSubstrateClient, LocalRuntimeSubstrateClient } from "./substrate-client.js";
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
  LearnOptions,
  LocalAgentOptions,
  McpServerConfig,
  ModelSelection,
  PlanOptions,
  SandboxOptions,
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
  RuntimeReceipt,
  RuntimeScorecard,
  RuntimeTraceBundle,
  SemanticImpactProjection,
  StopConditionProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";

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
  capabilityLeaseRequirements: string[];
  policyTarget: string;
  approvalScopeFields: string[];
  evidenceRequirements: string[];
  replayabilityClassification: string;
  redactionPolicy: string;
  ownerModule: string;
  version: string;
}
