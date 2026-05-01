import type { RuntimeSubstrateClient } from "./substrate-client.js";

export type RuntimeMode = "local" | "cloud" | "hosted" | "selfHosted";
export type StreamMode = "replay" | "tail" | "replay-and-tail";
export type StopReason =
  | "objective_satisfied"
  | "evidence_sufficient"
  | "repeated_failure"
  | "budget_exhausted"
  | "uncertainty_requires_human"
  | "policy_prevents_progress"
  | "external_dependency_blocked"
  | "marginal_improvement_too_low"
  | "unknown";

export interface ModelSelection {
  id: string;
  provider?: string;
  reasoningEffort?: "low" | "medium" | "high" | "xhigh";
}

export interface LocalAgentOptions {
  cwd: string;
  force?: boolean;
  checkpointDir?: string;
}

export interface CloudRepository {
  url: string;
  startingRef?: string;
}

export interface CloudAgentOptions {
  repos?: CloudRepository[];
  autoCreatePR?: boolean;
  endpoint?: string;
}

export interface HostedWorkerProvider {
  endpoint?: string;
  providerId?: string;
  authEnv?: string;
  runtimeManifestUrl?: string;
}

export interface SelfHostedWorkerOptions {
  endpoint?: string;
  workerId?: string;
  manifestPath?: string;
}

export interface SelfHostedWorkerProvider {
  endpoint?: string;
  workerId?: string;
  healthPath?: string;
  authEnv?: string;
}

export interface McpServerConfig {
  command?: string;
  args?: string[];
  url?: string;
  transport?: "stdio" | "http" | "sse";
  env?: Record<string, string>;
}

export interface SubagentDefinition {
  prompt: string;
  model?: ModelSelection;
  description?: string;
}

export interface SandboxOptions {
  profile?: "development" | "production";
  allowNetwork?: boolean;
  allowFilesystemWrites?: boolean;
  approvalPolicy?: "never" | "on-request" | "always";
}

export interface AgentOptions {
  apiKey?: string;
  model?: ModelSelection;
  local?: LocalAgentOptions;
  cloud?: CloudAgentOptions;
  hosted?: CloudAgentOptions & { provider?: HostedWorkerProvider };
  selfHosted?: SelfHostedWorkerOptions;
  mcpServers?: Record<string, McpServerConfig>;
  agents?: Record<string, SubagentDefinition>;
  settings?: Record<string, unknown>;
  sandboxOptions?: SandboxOptions;
  substrateClient?: RuntimeSubstrateClient;
}

export interface SendOptions {
  model?: ModelSelection;
  mcpServers?: Record<string, McpServerConfig>;
  onStep?: (event: unknown) => void | Promise<void>;
  onDelta?: (delta: string) => void | Promise<void>;
  local?: { force?: boolean };
  metadata?: Record<string, unknown>;
}

export interface StreamOptions {
  mode?: StreamMode;
  lastEventId?: string;
  signal?: AbortSignal;
}

export interface PlanOptions extends SendOptions {
  noMutation?: boolean;
}

export interface DryRunOptions extends SendOptions {
  toolClass?: string;
  sideEffectPreview?: boolean;
}

export interface HandoffOptions extends SendOptions {
  receiver?: string;
}

export interface LearnOptions {
  taskFamily: string;
  positive?: string[];
  negative?: string[];
  evidenceRefs?: string[];
}
