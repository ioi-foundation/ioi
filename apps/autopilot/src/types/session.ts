import type {
  SessionClarificationOption as SharedSessionClarificationOption,
  SessionClarificationRequest as SharedSessionClarificationRequest,
  SessionCredentialRequest as SharedSessionCredentialRequest,
  SessionGateInfo as SharedSessionGateInfo,
} from "./agent-ide";
import type { Artifact } from "./artifacts";
import type { ChatMessage, LiabilityLevel } from "./base";
import type {
  BuildArtifactSession,
  ChatArtifactSession,
  ChatOutcomeRequest,
  ChatRendererSession,
} from "./chat-artifacts";
import type { AgentEvent } from "./events";
import {
  normalizeMaterializationWorkGraphFields,
  normalizeWorkGraphTree,
} from "./work-graph-compat";

export type AgentStatus =
  | "requisition"
  | "pending"
  | "negotiating"
  | "running"
  | "paused"
  | "reviewing"
  | "completed"
  | "failed";

export type GateInfo = SharedSessionGateInfo & {
  pii?: PiiReviewInfo;
};

export interface PiiTargetServiceCall {
  kind: "service_call";
  service_id: string;
  method: string;
}

export interface PiiTargetCloudInference {
  kind: "cloud_inference";
  provider: string;
  model: string;
}

export interface PiiTargetAction {
  kind: "action";
  // Action target is tagged in Rust; we treat as opaque for UI rendering.
  [key: string]: unknown;
}

export type PiiTarget =
  | PiiTargetServiceCall
  | PiiTargetCloudInference
  | PiiTargetAction
  | Record<string, unknown>;

export interface PiiReviewInfo {
  decision_hash: string;
  target_label: string;
  span_summary: string;
  class_counts?: Record<string, number>;
  severity_counts?: Record<string, number>;
  stage2_prompt: string;
  deadline_ms: number;
  target_id?: PiiTarget | null;
}

export interface Receipt {
  duration: string;
  actions: number;
  cost?: string;
}

export type CredentialRequest = SharedSessionCredentialRequest;

export type ClarificationOption = SharedSessionClarificationOption;

export type ClarificationRequest = SharedSessionClarificationRequest;

export interface SessionChecklistItem {
  item_id: string;
  label: string;
  status: string;
  detail?: string | null;
  updated_at_ms: number;
}

export interface SessionBackgroundTaskRecord {
  task_id: string;
  session_id?: string | null;
  label: string;
  status: string;
  detail?: string | null;
  latest_output?: string | null;
  can_stop?: boolean;
  updated_at_ms: number;
}

export interface SessionFileContext {
  session_id?: string | null;
  workspace_root: string;
  pinned_files: string[];
  recent_files: string[];
  explicit_includes: string[];
  explicit_excludes: string[];
  updated_at_ms: number;
}

export interface PolicyContext {
  name: string;
  mode: "strict" | "standard" | "elevated";
  constraints: string[];
}

export interface WorkGraphAgent {
  id: string;
  parentId: string | null;
  name: string;
  role: string;
  status: AgentStatus;
  budget_used: number;
  budget_cap: number;
  policy_hash: string;
  estimated_cost?: number;
  current_thought?: string;
  artifacts_produced: number;
  generation?: number;
}

export interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: "Idle" | "Running" | "Gate" | "Complete" | "Failed";
  progress: number;
  total_steps: number;
  current_step: string;
  receipt?: Receipt;
  gate_info?: GateInfo;
  history: ChatMessage[];
  events: AgentEvent[];
  artifacts: Artifact[];
  run_bundle_id?: string;
  liability_level?: LiabilityLevel;
  generation: number;
  lineage_id: string;
  fitness_score: number;
  work_graph_tree: WorkGraphAgent[];
  processed_steps: Set<string>;
  visual_hash?: string;
  pending_request_hash?: string;
  session_id?: string;
  policy?: PolicyContext;
  is_secure_session?: boolean;
  credential_request?: CredentialRequest;
  clarification_request?: ClarificationRequest;
  session_checklist: SessionChecklistItem[];
  background_tasks: SessionBackgroundTaskRecord[];
  chat_session?: ChatArtifactSession | null;
  chat_outcome?: ChatOutcomeRequest | null;
  renderer_session?: ChatRendererSession | null;
  build_session?: BuildArtifactSession | null;
}

export type AgentTaskModelInput = Omit<AgentTask, "processed_steps" | "work_graph_tree"> & {
  processed_steps?: Set<string> | string[] | null;
  work_graph_tree?: WorkGraphAgent[] | null;
};

export function normalizeAgentTaskModel(task: AgentTaskModelInput): AgentTask {
  const processedSteps =
    task.processed_steps instanceof Set
      ? task.processed_steps
      : new Set(
          Array.isArray(task.processed_steps) ? task.processed_steps : [],
        );

  const chatSession = task.chat_session
    ? {
        ...task.chat_session,
        materialization: normalizeMaterializationWorkGraphFields(
          task.chat_session.materialization,
        ),
      }
    : task.chat_session;

  return {
    ...task,
    work_graph_tree: normalizeWorkGraphTree(task),
    processed_steps: processedSteps,
    chat_session: chatSession,
    session_checklist: Array.isArray(task.session_checklist)
      ? task.session_checklist
      : [],
    background_tasks: Array.isArray(task.background_tasks)
      ? task.background_tasks
      : [],
  };
}

export interface WalletConnectorAuthRecordView {
  connectorId: string;
  providerFamily: string;
  authProtocol: string;
  state: string;
  accountLabel?: string | null;
  mailbox?: string | null;
  grantedScopes: string[];
  credentialAliases: Record<string, string>;
  metadata: Record<string, string>;
  updatedAtMs: number;
  expiresAtMs?: number | null;
  lastValidatedAtMs?: number | null;
}

export interface WalletConnectorAuthGetResult {
  fetchedAtMs: number;
  record: WalletConnectorAuthRecordView;
}

export type { ChatMessage } from "./base";
export type {
  SessionBranchSnapshot,
  SessionCompactionPolicy,
  SessionCompactionPruneDecision,
  SessionCompactionSnapshot,
  SessionHookSnapshot,
  SessionRemoteEnvSnapshot,
  SessionSummary,
} from "./session-continuity";
