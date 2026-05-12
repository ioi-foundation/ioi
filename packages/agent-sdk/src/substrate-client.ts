import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { IoiAgentError, type IoiAgentErrorCode } from "./errors.js";
import {
  eventStreamIdForThread,
  mockRuntimeCursorSeq,
  mockRuntimeEnvelopeForSdkEvent,
  mockRuntimeEventEnvelope,
  runtimeThreadEventFromEnvelope,
  runtimeTurnStatusForRun,
  turnIdForRun,
} from "./runtime-events.js";
import type {
  AgentOptions,
  CloudAgentOptions,
  DryRunOptions,
  HandoffOptions,
  LearnOptions,
  McpServerConfig,
  PlanOptions,
  RuntimeMode,
  SendOptions,
} from "./options.js";
import type {
  AgentMemoryPolicy,
  AgentMemoryRecord,
  AgentQualityLedgerProjection,
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  ModelRouteDecision,
  PostconditionProjection,
  ProbeProjection,
  RuntimeReceipt,
  RuntimeAccountProfile,
  RuntimeEventEnvelope,
  RuntimeNodeProfile,
  RuntimeScorecard,
  RuntimeThreadEvent,
  RuntimeThreadRecord,
  RuntimeToolCatalogEntry,
  RuntimeTraceBundle,
  RuntimeTurnRecord,
  SemanticImpactProjection,
  StopConditionProjection,
  SubagentMemoryInheritanceProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";
import type { RuntimeModelCatalogEntry } from "./model-mounts.js";

export { runtimeThreadEventFromEnvelope } from "./runtime-events.js";

export interface RuntimeArtifact {
  id: string;
  runId: string;
  name: string;
  mediaType: string;
  redaction: "none" | "redacted";
  receiptId: string;
  content: string;
}

export interface RuntimeAgentRecord {
  id: string;
  status: "active" | "archived" | "closed";
  runtime: RuntimeMode;
  cwd: string;
  modelId: string;
  requestedModelId?: string;
  modelRouteId?: string;
  modelRouteEndpointId?: string | null;
  modelRouteProviderId?: string | null;
  modelRouteReceiptId?: string | null;
  modelRouteDecision?: ModelRouteDecision | null;
  createdAt: string;
  updatedAt: string;
  options: AgentOptionsSummary;
}

export interface AgentOptionsSummary {
  localCwd?: string;
  cloudConfigured: boolean;
  selfHostedConfigured: boolean;
  mcpServerNames: string[];
  skillNames: string[];
  hookNames: string[];
  subagentNames: string[];
  sandboxProfile: string;
}

export interface RuntimeRunRecord {
  id: string;
  agentId: string;
  status: "queued" | "running" | "completed" | "canceled" | "failed" | "blocked";
  objective: string;
  mode: "send" | "plan" | "dry_run" | "handoff" | "learn";
  createdAt: string;
  updatedAt: string;
  events: IOISDKMessage[];
  conversation: ConversationMessage[];
  receipts: RuntimeReceipt[];
  artifacts: RuntimeArtifact[];
  trace: RuntimeTraceBundle;
  modelRouteDecision?: ModelRouteDecision | null;
  modelRouteReceiptId?: string | null;
  memoryPolicy?: AgentMemoryPolicy | null;
  memoryRecords?: AgentMemoryRecord[];
  memoryWriteReceipts?: RuntimeReceipt[];
  subagentMemoryInheritance?: SubagentMemoryInheritanceProjection | null;
  result: string;
}

export interface AgentMemoryProjection {
  schemaVersion: "ioi.agent-runtime.memory.v1";
  object: "ioi.agent_memory_projection";
  threadId: string | null;
  agentId: string | null;
  workspace: string | null;
  policy?: AgentMemoryPolicy;
  paths?: AgentMemoryPathProjection;
  filters?: MemoryListOptions;
  records: AgentMemoryRecord[];
  totalMatches?: number;
}

export interface MemoryListOptions {
  threadId?: string;
  scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  memoryKey?: string;
  query?: string;
  q?: string;
  limit?: number;
  redaction?: "none" | "redacted" | string;
}

export interface RememberMemoryInput {
  text: string;
  memoryKey?: string;
  scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  threadId?: string;
  workflowGraphId?: string;
  workflowNodeId?: string;
  workflowNodeType?: string;
  writeApproved?: boolean;
}

export interface RememberMemoryResult {
  record: AgentMemoryRecord;
  receipt: RuntimeReceipt;
}

export interface UpdateMemoryRecordInput {
  text: string;
  threadId?: string;
  writeApproved?: boolean;
}

export interface DeleteMemoryRecordInput {
  threadId?: string;
  writeApproved?: boolean;
}

export interface MemoryPolicyInput {
  threadId?: string;
  targetType?: "agent" | "thread" | "workflow" | "subagent" | string;
  targetId?: string;
  disabled?: boolean;
  injectionEnabled?: boolean;
  readOnly?: boolean;
  writeRequiresApproval?: boolean;
  retention?: string;
  redaction?: "none" | "redacted" | string;
  subagentInheritance?: "none" | "explicit" | "read_only" | "full" | string;
  scope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
}

export interface MemoryPolicyUpdateResult {
  policy: AgentMemoryPolicy;
  receipt: RuntimeReceipt;
}

export interface AgentMemoryPathProjection {
  schemaVersion: "ioi.agent-runtime.memory.v1";
  object: "ioi.agent_memory_path_projection";
  threadId: string | null;
  agentId: string | null;
  workspace: string | null;
  recordsPath: string;
  policiesPath: string;
  effectivePolicyId: string;
}

export interface RuntimeThreadCreateInput {
  options?: AgentOptions;
  runtime_profile?: string;
  goal?: string;
  max_steps?: number;
  [key: string]: unknown;
}

export interface RuntimeThreadForkInput {
  options?: AgentOptions;
  [key: string]: unknown;
}

export interface RuntimeTurnCreateInput {
  prompt?: string;
  message?: string;
  input?: string;
  mode?: RuntimeRunRecord["mode"];
  options?: SendOptions | PlanOptions | DryRunOptions | HandoffOptions;
  memory?: SendOptions["memory"];
  remember?: string;
  [key: string]: unknown;
}

export interface RuntimeEventStreamOptions {
  sinceSeq?: number;
  lastEventId?: string;
  signal?: AbortSignal;
}

export interface RuntimeSubstrateClient {
  createThread(input?: RuntimeThreadCreateInput): Promise<RuntimeThreadRecord>;
  listThreads(): Promise<RuntimeThreadRecord[]>;
  getThread(threadId: string): Promise<RuntimeThreadRecord>;
  resumeThread(threadId: string): Promise<RuntimeThreadRecord>;
  forkThread(threadId: string, input?: RuntimeThreadForkInput): Promise<RuntimeThreadRecord>;
  submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord>;
  listTurns(threadId: string): Promise<RuntimeTurnRecord[]>;
  getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord>;
  streamThreadEvents(threadId: string, options?: RuntimeEventStreamOptions): AsyncIterable<RuntimeThreadEvent>;
  createAgent(options: AgentOptions): Promise<RuntimeAgentRecord>;
  resumeAgent(agentId: string): Promise<RuntimeAgentRecord>;
  closeAgent(agentId: string): Promise<void>;
  reloadAgent(agentId: string): Promise<RuntimeAgentRecord>;
  listAgents(): Promise<RuntimeAgentRecord[]>;
  getAgent(agentId: string): Promise<RuntimeAgentRecord>;
  archiveAgent(agentId: string): Promise<RuntimeAgentRecord>;
  unarchiveAgent(agentId: string): Promise<RuntimeAgentRecord>;
  deleteAgent(agentId: string): Promise<void>;
  send(agentId: string, prompt: string, options?: SendOptions): Promise<RuntimeRunRecord>;
  plan(agentId: string, prompt: string, options?: PlanOptions): Promise<RuntimeRunRecord>;
  dryRun(agentId: string, prompt: string, options?: DryRunOptions): Promise<RuntimeRunRecord>;
  handoff(agentId: string, prompt: string, options?: HandoffOptions): Promise<RuntimeRunRecord>;
  learn(agentId: string, options: LearnOptions): Promise<RuntimeRunRecord>;
  streamRun(runId: string, options?: { lastEventId?: string }): AsyncIterable<IOISDKMessage>;
  waitRun(runId: string): Promise<IOIRunResult>;
  cancelRun(runId: string): Promise<RuntimeRunRecord>;
  getRun(runId: string): Promise<RuntimeRunRecord>;
  listRuns(agentId?: string): Promise<RuntimeRunRecord[]>;
  conversation(runId: string): Promise<ConversationMessage[]>;
  listArtifacts(runId: string): Promise<RuntimeArtifact[]>;
  downloadArtifact(runId: string, artifactId: string): Promise<RuntimeArtifact>;
  exportTrace(runId: string): Promise<RuntimeTraceBundle>;
  replayTrace(runId: string): AsyncIterable<IOISDKMessage>;
  inspectRun(runId: string): Promise<RuntimeTraceBundle>;
  scorecard(runId: string): Promise<RuntimeScorecard>;
  listModels(): Promise<RuntimeModelCatalogEntry[]>;
  listRepositories(): Promise<Array<{ url: string; source: string; status: string }>>;
  getAccount(): Promise<RuntimeAccountProfile>;
  listRuntimeNodes(): Promise<RuntimeNodeProfile[]>;
  listTools(): Promise<RuntimeToolCatalogEntry[]>;
  rememberMemory(agentId: string, input: RememberMemoryInput): Promise<RememberMemoryResult>;
  listMemory(agentId: string, options?: MemoryListOptions): Promise<AgentMemoryProjection>;
  updateMemory(agentId: string, memoryId: string, input: UpdateMemoryRecordInput): Promise<RememberMemoryResult>;
  deleteMemory(agentId: string, memoryId: string, input?: DeleteMemoryRecordInput): Promise<RememberMemoryResult>;
  getMemoryPolicy(agentId: string, options?: { threadId?: string }): Promise<AgentMemoryPolicy>;
  setMemoryPolicy(agentId: string, input: MemoryPolicyInput): Promise<MemoryPolicyUpdateResult>;
  memoryPath(agentId: string, options?: { threadId?: string }): Promise<AgentMemoryPathProjection>;
}

export interface RuntimeSubstrateClientOptions {
  cwd?: string;
  checkpointDir?: string;
  endpoint?: string;
  apiKey?: string;
  headers?: Record<string, string>;
}

export function createRuntimeSubstrateClient(
  options: RuntimeSubstrateClientOptions = {},
): RuntimeSubstrateClient {
  return new DaemonRuntimeSubstrateClient(options);
}

export function createMockRuntimeSubstrateClient(
  options: RuntimeSubstrateClientOptions = {},
): RuntimeSubstrateClient {
  return new MockRuntimeSubstrateClient(options);
}

export class DaemonRuntimeSubstrateClient implements RuntimeSubstrateClient {
  private readonly endpoint?: string;
  private readonly apiKey?: string;
  private readonly headers: Record<string, string>;

  constructor(options: RuntimeSubstrateClientOptions = {}) {
    this.endpoint = options.endpoint ?? process.env.IOI_DAEMON_ENDPOINT;
    this.apiKey = options.apiKey ?? process.env.IOI_DAEMON_TOKEN;
    this.headers = options.headers ?? {};
  }

  async createThread(input: RuntimeThreadCreateInput = {}): Promise<RuntimeThreadRecord> {
    return this.request("createThread", "POST", "/v1/threads", input);
  }

  async listThreads(): Promise<RuntimeThreadRecord[]> {
    return this.request("listThreads", "GET", "/v1/threads");
  }

  async getThread(threadId: string): Promise<RuntimeThreadRecord> {
    return this.request("getThread", "GET", `/v1/threads/${encodePath(threadId)}`);
  }

  async resumeThread(threadId: string): Promise<RuntimeThreadRecord> {
    return this.request("resumeThread", "POST", `/v1/threads/${encodePath(threadId)}/resume`);
  }

  async forkThread(threadId: string, input: RuntimeThreadForkInput = {}): Promise<RuntimeThreadRecord> {
    return this.request("forkThread", "POST", `/v1/threads/${encodePath(threadId)}/fork`, input);
  }

  async submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord> {
    return this.request("submitTurn", "POST", `/v1/threads/${encodePath(threadId)}/turns`, input);
  }

  async listTurns(threadId: string): Promise<RuntimeTurnRecord[]> {
    return this.request("listTurns", "GET", `/v1/threads/${encodePath(threadId)}/turns`);
  }

  async getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord> {
    return this.request(
      "getTurn",
      "GET",
      `/v1/threads/${encodePath(threadId)}/turns/${encodePath(turnId)}`,
    );
  }

  async *streamThreadEvents(
    threadId: string,
    options: RuntimeEventStreamOptions = {},
  ): AsyncIterable<RuntimeThreadEvent> {
    const events = await this.requestRuntimeEvents(
      "streamThreadEvents",
      `/v1/threads/${encodePath(threadId)}/events${runtimeEventQuery(options)}`,
    );
    for (const event of events) {
      options.signal?.throwIfAborted();
      yield runtimeThreadEventFromEnvelope(event);
    }
  }

  async createAgent(options: AgentOptions): Promise<RuntimeAgentRecord> {
    return this.request("createAgent", "POST", "/v1/agents", { options });
  }

  async resumeAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("resumeAgent", "POST", `/v1/agents/${encodePath(agentId)}/resume`);
  }

  async closeAgent(agentId: string): Promise<void> {
    await this.request("closeAgent", "POST", `/v1/agents/${encodePath(agentId)}/close`);
  }

  async reloadAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("reloadAgent", "POST", `/v1/agents/${encodePath(agentId)}/reload`);
  }

  async listAgents(): Promise<RuntimeAgentRecord[]> {
    return this.request("listAgents", "GET", "/v1/agents");
  }

  async getAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("getAgent", "GET", `/v1/agents/${encodePath(agentId)}`);
  }

  async archiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("archiveAgent", "POST", `/v1/agents/${encodePath(agentId)}/archive`);
  }

  async unarchiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    return this.request("unarchiveAgent", "POST", `/v1/agents/${encodePath(agentId)}/unarchive`);
  }

  async deleteAgent(agentId: string): Promise<void> {
    await this.request("deleteAgent", "DELETE", `/v1/agents/${encodePath(agentId)}`);
  }

  async send(agentId: string, prompt: string, options: SendOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("send", agentId, prompt, options);
  }

  async plan(agentId: string, prompt: string, options: PlanOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("plan", agentId, prompt, options);
  }

  async dryRun(agentId: string, prompt: string, options: DryRunOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("dry_run", agentId, prompt, options);
  }

  async handoff(agentId: string, prompt: string, options: HandoffOptions = {}): Promise<RuntimeRunRecord> {
    return this.createRun("handoff", agentId, prompt, options);
  }

  async learn(agentId: string, options: LearnOptions): Promise<RuntimeRunRecord> {
    return this.request("learn", "POST", `/v1/agents/${encodePath(agentId)}/runs`, {
      mode: "learn",
      options,
    });
  }

  async *streamRun(runId: string, options: { lastEventId?: string } = {}): AsyncIterable<IOISDKMessage> {
    const query = options.lastEventId ? `?lastEventId=${encodeURIComponent(options.lastEventId)}` : "";
    const events = await this.requestEvents("streamRun", `/v1/runs/${encodePath(runId)}/events${query}`);
    for (const event of eventsFromResponse(events)) {
      yield event;
    }
  }

  async waitRun(runId: string): Promise<IOIRunResult> {
    return this.request("waitRun", "GET", `/v1/runs/${encodePath(runId)}/wait`);
  }

  async cancelRun(runId: string): Promise<RuntimeRunRecord> {
    return this.request("cancelRun", "POST", `/v1/runs/${encodePath(runId)}/cancel`);
  }

  async getRun(runId: string): Promise<RuntimeRunRecord> {
    return this.request("getRun", "GET", `/v1/runs/${encodePath(runId)}`);
  }

  async listRuns(agentId?: string): Promise<RuntimeRunRecord[]> {
    const query = agentId ? `?agentId=${encodeURIComponent(agentId)}` : "";
    return this.request("listRuns", "GET", `/v1/runs${query}`);
  }

  async conversation(runId: string): Promise<ConversationMessage[]> {
    return this.request("conversation", "GET", `/v1/runs/${encodePath(runId)}/conversation`);
  }

  async listArtifacts(runId: string): Promise<RuntimeArtifact[]> {
    return this.request("listArtifacts", "GET", `/v1/runs/${encodePath(runId)}/artifacts`);
  }

  async downloadArtifact(runId: string, artifactId: string): Promise<RuntimeArtifact> {
    return this.request(
      "downloadArtifact",
      "GET",
      `/v1/runs/${encodePath(runId)}/artifacts/${encodePath(artifactId)}`,
    );
  }

  async exportTrace(runId: string): Promise<RuntimeTraceBundle> {
    return this.request("exportTrace", "GET", `/v1/runs/${encodePath(runId)}/trace`);
  }

  async *replayTrace(runId: string): AsyncIterable<IOISDKMessage> {
    const events = await this.requestEvents("replayTrace", `/v1/runs/${encodePath(runId)}/replay`);
    for (const event of eventsFromResponse(events)) {
      yield event;
    }
  }

  async inspectRun(runId: string): Promise<RuntimeTraceBundle> {
    return this.request("inspectRun", "GET", `/v1/runs/${encodePath(runId)}/inspect`);
  }

  async scorecard(runId: string): Promise<RuntimeScorecard> {
    return this.request("scorecard", "GET", `/v1/runs/${encodePath(runId)}/scorecard`);
  }

  async listModels(): Promise<RuntimeModelCatalogEntry[]> {
    return this.request("listModels", "GET", "/v1/models");
  }

  async listRepositories(): Promise<Array<{ url: string; source: string; status: string }>> {
    return this.request("listRepositories", "GET", "/v1/repositories");
  }

  async getAccount(): Promise<RuntimeAccountProfile> {
    return this.request("getAccount", "GET", "/v1/account");
  }

  async listRuntimeNodes(): Promise<RuntimeNodeProfile[]> {
    return this.request("listRuntimeNodes", "GET", "/v1/runtime/nodes");
  }

  async listTools(): Promise<RuntimeToolCatalogEntry[]> {
    return this.request("listTools", "GET", "/v1/tools");
  }

  async rememberMemory(agentId: string, input: RememberMemoryInput): Promise<RememberMemoryResult> {
    return this.request("rememberMemory", "POST", `/v1/agents/${encodePath(agentId)}/memory`, input);
  }

  async listMemory(agentId: string, options: MemoryListOptions = {}): Promise<AgentMemoryProjection> {
    const query = memoryListQuery(options);
    return this.request("listMemory", "GET", `/v1/agents/${encodePath(agentId)}/memory${query}`);
  }

  async updateMemory(agentId: string, memoryId: string, input: UpdateMemoryRecordInput): Promise<RememberMemoryResult> {
    return this.request("updateMemory", "PATCH", `/v1/agents/${encodePath(agentId)}/memory/${encodePath(memoryId)}`, input);
  }

  async deleteMemory(agentId: string, memoryId: string, input: DeleteMemoryRecordInput = {}): Promise<RememberMemoryResult> {
    return this.request("deleteMemory", "DELETE", `/v1/agents/${encodePath(agentId)}/memory/${encodePath(memoryId)}`, input);
  }

  async getMemoryPolicy(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPolicy> {
    const query = options.threadId ? `?threadId=${encodeURIComponent(options.threadId)}` : "";
    return this.request("getMemoryPolicy", "GET", `/v1/agents/${encodePath(agentId)}/memory/policy${query}`);
  }

  async setMemoryPolicy(agentId: string, input: MemoryPolicyInput): Promise<MemoryPolicyUpdateResult> {
    return this.request("setMemoryPolicy", "PATCH", `/v1/agents/${encodePath(agentId)}/memory/policy`, input);
  }

  async memoryPath(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPathProjection> {
    const query = options.threadId ? `?threadId=${encodeURIComponent(options.threadId)}` : "";
    return this.request("memoryPath", "GET", `/v1/agents/${encodePath(agentId)}/memory/path${query}`);
  }

  private createRun(
    mode: RuntimeRunRecord["mode"],
    agentId: string,
    prompt: string,
    options: SendOptions | PlanOptions | DryRunOptions | HandoffOptions,
  ): Promise<RuntimeRunRecord> {
    return this.request(mode, "POST", `/v1/agents/${encodePath(agentId)}/runs`, {
      mode,
      prompt,
      options,
    });
  }

  private async request<T>(
    sdkMethod: string,
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    route: string,
    body?: unknown,
  ): Promise<T> {
    const endpoint = this.requireEndpoint(sdkMethod);
    const url = new URL(route.replace(/^\/+/, ""), endpoint);
    const headers: Record<string, string> = {
      accept: "application/json",
      ...this.headers,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new IoiAgentError({
        code: "network",
        message: `IOI daemon request failed for ${sdkMethod}.`,
        cause: error,
        details: { method: sdkMethod, endpoint: this.endpoint, route },
      });
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;
    const text = await response.text();
    const parsed = parseDaemonResponseBody(text);
    if (!response.ok) {
      throw errorFromDaemonResponse({
        sdkMethod,
        route,
        status: response.status,
        requestId,
        parsed,
      });
    }
    return parsed as T;
  }

  private async requestEvents(sdkMethod: string, route: string): Promise<IOISDKMessage[]> {
    const endpoint = this.requireEndpoint(sdkMethod);
    const url = new URL(route.replace(/^\/+/, ""), endpoint);
    const headers: Record<string, string> = {
      accept: "text/event-stream, application/json",
      ...this.headers,
    };
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await fetch(url, { method: "GET", headers });
    } catch (error) {
      throw new IoiAgentError({
        code: "network",
        message: `IOI daemon event stream failed for ${sdkMethod}.`,
        cause: error,
        details: { method: sdkMethod, endpoint: this.endpoint, route },
      });
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;
    const text = await response.text();
    if (!response.ok) {
      throw errorFromDaemonResponse({
        sdkMethod,
        route,
        status: response.status,
        requestId,
        parsed: parseDaemonResponseBody(text),
      });
    }
    const contentType = response.headers.get("content-type") ?? "";
    return contentType.includes("text/event-stream")
      ? parseServerSentEvents(text)
      : eventsFromResponse(parseDaemonResponseBody(text) as IOISDKMessage[] | { events: IOISDKMessage[] });
  }

  private async requestRuntimeEvents(sdkMethod: string, route: string): Promise<RuntimeEventEnvelope[]> {
    const endpoint = this.requireEndpoint(sdkMethod);
    const url = new URL(route.replace(/^\/+/, ""), endpoint);
    const headers: Record<string, string> = {
      accept: "text/event-stream, application/json",
      ...this.headers,
    };
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await fetch(url, { method: "GET", headers });
    } catch (error) {
      throw new IoiAgentError({
        code: "network",
        message: `IOI daemon runtime event stream failed for ${sdkMethod}.`,
        cause: error,
        details: { method: sdkMethod, endpoint: this.endpoint, route },
      });
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;
    const text = await response.text();
    if (!response.ok) {
      throw errorFromDaemonResponse({
        sdkMethod,
        route,
        status: response.status,
        requestId,
        parsed: parseDaemonResponseBody(text),
      });
    }
    const contentType = response.headers.get("content-type") ?? "";
    return contentType.includes("text/event-stream")
      ? parseServerSentRuntimeEvents(text)
      : runtimeEventsFromResponse(parseDaemonResponseBody(text));
  }

  private requireEndpoint(method: string): URL {
    if (!this.endpoint) {
      throw this.unavailableError(method);
    }
    try {
      return new URL(this.endpoint.endsWith("/") ? this.endpoint : `${this.endpoint}/`);
    } catch (error) {
      throw new IoiAgentError({
        code: "config",
        message: "IOI_DAEMON_ENDPOINT must be a valid URL.",
        cause: error,
        details: { endpoint: this.endpoint, method },
      });
    }
  }

  private unavailableError(method: string): IoiAgentError {
    return new IoiAgentError({
      code: "external_blocker",
      message:
        "The default IOI SDK client targets the daemon substrate and is fail-closed until the daemon transport is configured.",
      details: {
        method,
        endpointConfigured: Boolean(this.endpoint),
        requiredEnvironment: ["IOI_DAEMON_ENDPOINT"],
        explicitMockFactory: "@ioi/agent-sdk/testing#createMockRuntimeSubstrateClient",
      },
    });
  }
}

function encodePath(value: string): string {
  return encodeURIComponent(value);
}

function memoryListQuery(options: MemoryListOptions = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function parseDaemonResponseBody(text: string): unknown {
  if (!text.trim()) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new IoiAgentError({
      code: "runtime",
      message: "IOI daemon returned a non-JSON substrate response.",
      cause: error,
      details: { preview: text.slice(0, 240) },
    });
  }
}

function eventsFromResponse(value: unknown): IOISDKMessage[] {
  if (Array.isArray(value)) {
    return normalizeDaemonEvents(value);
  }
  if (value && typeof value === "object" && Array.isArray((value as { events?: unknown[] }).events)) {
    return normalizeDaemonEvents((value as { events: unknown[] }).events);
  }
  throw new IoiAgentError({
    code: "runtime",
    message: "IOI daemon event endpoint returned an invalid event stream projection.",
    details: { value },
  });
}

function parseServerSentEvents(text: string): IOISDKMessage[] {
  const events: unknown[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const dataLines = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trimStart());
    if (dataLines.length === 0) {
      continue;
    }
    const data = dataLines.join("\n").trim();
    if (!data || data === "[DONE]") {
      continue;
    }
    const parsed = parseDaemonResponseBody(data);
    events.push(parsed);
  }
  return normalizeDaemonEvents(events);
}

function parseServerSentRuntimeEvents(text: string): RuntimeEventEnvelope[] {
  const events: unknown[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const dataLines = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trimStart());
    if (dataLines.length === 0) {
      continue;
    }
    const data = dataLines.join("\n").trim();
    if (!data || data === "[DONE]") {
      continue;
    }
    events.push(parseDaemonResponseBody(data));
  }
  return runtimeEventsFromResponse(events);
}

function runtimeEventsFromResponse(value: unknown): RuntimeEventEnvelope[] {
  const values = Array.isArray(value)
    ? value
    : value && typeof value === "object" && Array.isArray((value as { events?: unknown[] }).events)
      ? (value as { events: unknown[] }).events
      : null;
  if (!values) {
    throw new IoiAgentError({
      code: "runtime",
      message: "IOI daemon runtime event endpoint returned an invalid event stream projection.",
      details: { value },
    });
  }
  return values.map((event) => {
    if (!isRuntimeEventEnvelope(event)) {
      throw new IoiAgentError({
        code: "runtime",
        message: "IOI daemon runtime event endpoint returned a non-TTI event envelope.",
        details: { event },
      });
    }
    return event;
  });
}

function runtimeEventQuery(options: RuntimeEventStreamOptions = {}): string {
  const params = new URLSearchParams();
  if (options.sinceSeq !== undefined) {
    params.set("since_seq", String(options.sinceSeq));
  } else if (options.lastEventId) {
    params.set("lastEventId", options.lastEventId);
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function normalizeDaemonEvents(values: unknown[]): IOISDKMessage[] {
  const latestTerminalByRun = new Map<string, number>();
  for (const value of values) {
    if (!isRuntimeEventEnvelope(value) || !isRuntimeTerminalEvent(value)) continue;
    latestTerminalByRun.set(runtimeEventRunId(value), value.seq);
  }
  return values.map((value) => normalizeDaemonEvent(value, latestTerminalByRun));
}

function normalizeDaemonEvent(value: unknown, latestTerminalByRun = new Map<string, number>()): IOISDKMessage {
  if (isSdkMessage(value)) return value;
  if (isRuntimeEventEnvelope(value)) {
    const terminalSuperseded =
      isRuntimeTerminalEvent(value) && latestTerminalByRun.get(runtimeEventRunId(value)) !== value.seq;
    return sdkMessageFromRuntimeEvent(value, { terminalSuperseded });
  }
  throw new IoiAgentError({
    code: "runtime",
    message: "IOI daemon event endpoint returned an invalid event stream projection.",
    details: { value },
  });
}

function isSdkMessage(value: unknown): value is IOISDKMessage {
  return Boolean(
    value &&
      typeof value === "object" &&
      typeof (value as IOISDKMessage).id === "string" &&
      typeof (value as IOISDKMessage).runId === "string" &&
      typeof (value as IOISDKMessage).type === "string" &&
      typeof (value as IOISDKMessage).cursor === "string",
  );
}

function isRuntimeEventEnvelope(value: unknown): value is RuntimeEventEnvelope {
  return Boolean(
    value &&
      typeof value === "object" &&
      (value as RuntimeEventEnvelope).schema_version === "ioi.runtime.event.v1" &&
      typeof (value as RuntimeEventEnvelope).event_id === "string" &&
      typeof (value as RuntimeEventEnvelope).event_stream_id === "string" &&
      typeof (value as RuntimeEventEnvelope).seq === "number",
  );
}

function sdkMessageFromRuntimeEvent(
  event: RuntimeEventEnvelope,
  options: { terminalSuperseded?: boolean } = {},
): IOISDKMessage {
  const payload = event.payload ?? {};
  const type = options.terminalSuperseded ? "step" : sdkMessageTypeFromRuntimeEvent(event);
  return {
    id: event.event_id,
    runId: runtimeEventRunId(event),
    agentId: payload.agent_id ?? event.thread_id.replace(/^thread_/, "agent_"),
    type,
    cursor: `${event.event_stream_id}:${event.seq}`,
    createdAt: event.created_at,
    summary: payload.summary ?? event.event_kind,
    data: {
      ...payload,
      runtimeEventEnvelope: event,
    },
  };
}

function runtimeEventRunId(event: RuntimeEventEnvelope): string {
  return event.payload?.run_id ?? event.turn_id.replace(/^turn_/, "run_");
}

function isRuntimeTerminalEvent(event: RuntimeEventEnvelope): boolean {
  return ["turn.completed", "turn.canceled", "turn.failed"].includes(event.event_kind);
}

function sdkMessageTypeFromRuntimeEvent(event: RuntimeEventEnvelope): IOISDKMessage["type"] {
  const legacyType = event.payload?.legacy_event_type;
  if (typeof legacyType === "string" && isSdkMessageType(legacyType)) return legacyType;
  switch (event.event_kind) {
    case "thread.started":
    case "turn.started":
      return "run_started";
    case "reasoning.delta":
    case "item.delta":
      return "delta";
    case "tool.completed":
    case "tool.failed":
      return "tool_result";
    case "turn.completed":
      return "completed";
    case "turn.canceled":
      return "canceled";
    case "turn.failed":
      return "error";
    case "model.route_decision":
    case "tool.route_decision":
      return "model_route_decision";
    default:
      return "step";
  }
}

function isSdkMessageType(value: string): value is IOISDKMessage["type"] {
  return [
    "run_started",
    "model_route_decision",
    "memory_update",
    "step",
    "delta",
    "tool_call",
    "tool_result",
    "task_state",
    "uncertainty",
    "probe",
    "postcondition_synthesized",
    "semantic_impact",
    "stop_condition",
    "quality_ledger",
    "artifact",
    "completed",
    "canceled",
    "error",
  ].includes(value);
}

function errorFromDaemonResponse({
  sdkMethod,
  route,
  status,
  requestId,
  parsed,
}: {
  sdkMethod: string;
  route: string;
  status: number;
  requestId?: string;
  parsed: unknown;
}): IoiAgentError {
  const record = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  const nested = record.error && typeof record.error === "object"
    ? (record.error as Record<string, unknown>)
    : record;
  const code = normalizeDaemonErrorCode(nested.code, status);
  return new IoiAgentError({
    code,
    status,
    requestId: typeof nested.requestId === "string" ? nested.requestId : requestId,
    retryable: typeof nested.retryable === "boolean" ? nested.retryable : undefined,
    message:
      typeof nested.message === "string"
        ? nested.message
        : `IOI daemon request failed for ${sdkMethod}.`,
    details: {
      method: sdkMethod,
      route,
      daemon: nested.details && typeof nested.details === "object" ? nested.details : record,
    },
  });
}

function normalizeDaemonErrorCode(value: unknown, status: number): IoiAgentErrorCode {
  if (
    value === "auth" ||
    value === "config" ||
    value === "policy" ||
    value === "rate_limit" ||
    value === "network" ||
    value === "model" ||
    value === "tool" ||
    value === "verifier" ||
    value === "postcondition" ||
    value === "not_found" ||
    value === "external_blocker" ||
    value === "runtime"
  ) {
    return value;
  }
  if (status === 401) return "auth";
  if (status === 403) return "policy";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limit";
  if (status === 424) return "external_blocker";
  if (status >= 500) return "network";
  return "runtime";
}

export class MockRuntimeSubstrateClient implements RuntimeSubstrateClient {
  private readonly cwd: string;
  private readonly checkpointDir: string;
  private readonly agents = new Map<string, RuntimeAgentRecord>();
  private readonly runs = new Map<string, RuntimeRunRecord>();
  private readonly memories = new Map<string, AgentMemoryRecord>();
  private readonly memoryPolicies = new Map<string, AgentMemoryPolicy>();

  constructor(options: RuntimeSubstrateClientOptions = {}) {
    this.cwd = path.resolve(options.cwd ?? process.cwd());
    this.checkpointDir = path.resolve(
      options.checkpointDir ?? path.join(this.cwd, ".ioi", "agent-sdk-mock"),
    );
    this.loadCheckpoints();
  }

  async createThread(input: RuntimeThreadCreateInput = {}): Promise<RuntimeThreadRecord> {
    const agent = await this.createAgent(input.options ?? (input as AgentOptions));
    return this.threadRecordForAgent(agent);
  }

  async listThreads(): Promise<RuntimeThreadRecord[]> {
    return (await this.listAgents()).map((agent) => this.threadRecordForAgent(agent));
  }

  async getThread(threadId: string): Promise<RuntimeThreadRecord> {
    return this.threadRecordForAgent(await this.agentForThread(threadId));
  }

  async resumeThread(threadId: string): Promise<RuntimeThreadRecord> {
    const agent = await this.agentForThread(threadId);
    return this.threadRecordForAgent(await this.resumeAgent(agent.id));
  }

  async forkThread(threadId: string, input: RuntimeThreadForkInput = {}): Promise<RuntimeThreadRecord> {
    const source = await this.getThread(threadId);
    const agent = await this.createAgent({
      ...(input.options ?? {}),
      local: input.options?.local ?? { cwd: source.workspace_root },
      model: input.options?.model ?? { id: source.model_route },
    });
    return {
      ...this.threadRecordForAgent(agent),
      agentgres_projection_ref: `forked_from:${source.thread_id}:${source.latest_seq}`,
    };
  }

  async submitTurn(threadId: string, input: RuntimeTurnCreateInput): Promise<RuntimeTurnRecord> {
    const agent = await this.agentForThread(threadId);
    const prompt = input.prompt ?? input.message ?? input.input ?? "";
    const options = {
      ...(input.options ?? {}),
      ...(input.memory ? { memory: input.memory } : {}),
      ...(input.remember ? { memory: { ...(input.options?.memory ?? {}), remember: input.remember } } : {}),
    } as SendOptions;
    const run = await this.createRun(agent.id, prompt, input.mode ?? "send", options);
    return this.turnRecordForRun(run);
  }

  async listTurns(threadId: string): Promise<RuntimeTurnRecord[]> {
    const agent = await this.agentForThread(threadId);
    return (await this.listRuns(agent.id)).map((run) => this.turnRecordForRun(run));
  }

  async getTurn(threadId: string, turnId: string): Promise<RuntimeTurnRecord> {
    const turn = (await this.listTurns(threadId)).find((candidate) => candidate.turn_id === turnId);
    if (!turn) {
      throw new IoiAgentError({ code: "not_found", message: `Turn not found: ${turnId}` });
    }
    return turn;
  }

  async *streamThreadEvents(
    threadId: string,
    options: RuntimeEventStreamOptions = {},
  ): AsyncIterable<RuntimeThreadEvent> {
    const agent = await this.agentForThread(threadId);
    const events = this.threadRuntimeEvents(agent);
    const cursorSeq = mockRuntimeCursorSeq(events, options);
    for (const event of events.filter((candidate) => candidate.seq > cursorSeq)) {
      options.signal?.throwIfAborted();
      yield runtimeThreadEventFromEnvelope(event);
    }
  }

  async createAgent(options: AgentOptions): Promise<RuntimeAgentRecord> {
    const runtime = runtimeModeForOptions(options);
    ensureProviderConfigured(runtime, options);
    const cwd = path.resolve(options.local?.cwd ?? this.cwd);
    const modelRouteDecision = mockModelRouteDecision(options.model, options.model?.id ?? "local:auto");
    const agent: RuntimeAgentRecord = {
      id: `agent_${crypto.randomUUID()}`,
      status: "active",
      runtime,
      cwd,
      modelId: modelRouteDecision.selectedModel ?? options.model?.id ?? "local:auto",
      requestedModelId: modelRouteDecision.requestedModel ?? options.model?.id ?? "local:auto",
      modelRouteId: modelRouteDecision.routeId ?? "route.local-first",
      modelRouteEndpointId: modelRouteDecision.endpointId,
      modelRouteProviderId: modelRouteDecision.providerId,
      modelRouteReceiptId: `receipt_agent_${crypto.randomUUID()}_model_route`,
      modelRouteDecision,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      options: summarizeOptions(cwd, options),
    };
    this.agents.set(agent.id, agent);
    this.persistAgent(agent);
    return agent;
  }

  async resumeAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    return { ...agent, status: agent.status === "closed" ? "active" : agent.status };
  }

  async closeAgent(agentId: string): Promise<void> {
    const agent = await this.getAgent(agentId);
    this.persistAgent({ ...agent, status: "closed", updatedAt: new Date().toISOString() });
  }

  async reloadAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    const reloaded = { ...agent, updatedAt: new Date().toISOString() };
    this.persistAgent(reloaded);
    return reloaded;
  }

  async listAgents(): Promise<RuntimeAgentRecord[]> {
    return [...this.agents.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async getAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new IoiAgentError({ code: "not_found", message: `Agent not found: ${agentId}` });
    }
    return agent;
  }

  async archiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    const archived = { ...agent, status: "archived" as const, updatedAt: new Date().toISOString() };
    this.persistAgent(archived);
    return archived;
  }

  async unarchiveAgent(agentId: string): Promise<RuntimeAgentRecord> {
    const agent = await this.getAgent(agentId);
    const active = { ...agent, status: "active" as const, updatedAt: new Date().toISOString() };
    this.persistAgent(active);
    return active;
  }

  async deleteAgent(agentId: string): Promise<void> {
    const agent = await this.getAgent(agentId);
    const runCount = [...this.runs.values()].filter((run) => run.agentId === agentId).length;
    if (runCount > 0) {
      throw new IoiAgentError({
        code: "policy",
        message:
          "Permanent agent deletion requires data-retention approval when runs exist; archive instead.",
        details: { agentId: agent.id, runCount },
      });
    }
    this.agents.delete(agentId);
    this.rmQuiet(path.join(this.checkpointDir, "agents", `${agentId}.json`));
  }

  async send(
    agentId: string,
    prompt: string,
    options: SendOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "send", options);
  }

  async plan(
    agentId: string,
    prompt: string,
    options: PlanOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "plan", options);
  }

  async dryRun(
    agentId: string,
    prompt: string,
    options: DryRunOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "dry_run", options);
  }

  async handoff(
    agentId: string,
    prompt: string,
    options: HandoffOptions = {},
  ): Promise<RuntimeRunRecord> {
    return this.createRun(agentId, prompt, "handoff", options);
  }

  async learn(agentId: string, options: LearnOptions): Promise<RuntimeRunRecord> {
    return this.createRun(
      agentId,
      `Learn governed task-family updates for ${options.taskFamily}`,
      "learn",
      { metadata: { learn: options } },
    );
  }

  async *streamRun(
    runId: string,
    options: { lastEventId?: string } = {},
  ): AsyncIterable<IOISDKMessage> {
    const run = await this.getRun(runId);
    const start = options.lastEventId
      ? run.events.findIndex((event) => event.id === options.lastEventId) + 1
      : 0;
    for (const event of run.events.slice(Math.max(0, start))) {
      yield event;
    }
  }

  async waitRun(runId: string): Promise<IOIRunResult> {
    const run = await this.getRun(runId);
    return {
      id: run.id,
      agentId: run.agentId,
      status: run.status,
      result: run.result,
      stopCondition: run.trace.stopCondition,
      routeDecision: run.modelRouteDecision ?? run.trace.modelRouteDecision ?? null,
      trace: run.trace,
      scorecard: run.trace.scorecard,
    };
  }

  async cancelRun(runId: string): Promise<RuntimeRunRecord> {
    const run = await this.getRun(runId);
    if (run.status === "completed") {
      const canceled = this.withTerminalReplacement(run, "canceled", {
        reason: "operator canceled after completion request",
      });
      this.persistRun(canceled);
      return canceled;
    }
    const canceled = this.withTerminalReplacement(run, "canceled", {
      reason: "operator canceled run",
    });
    this.persistRun(canceled);
    return canceled;
  }

  async getRun(runId: string): Promise<RuntimeRunRecord> {
    const run = this.runs.get(runId);
    if (!run) {
      throw new IoiAgentError({ code: "not_found", message: `Run not found: ${runId}` });
    }
    return run;
  }

  async listRuns(agentId?: string): Promise<RuntimeRunRecord[]> {
    return [...this.runs.values()]
      .filter((run) => !agentId || run.agentId === agentId)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async conversation(runId: string): Promise<ConversationMessage[]> {
    return (await this.getRun(runId)).conversation;
  }

  async listArtifacts(runId: string): Promise<RuntimeArtifact[]> {
    return (await this.getRun(runId)).artifacts;
  }

  async downloadArtifact(runId: string, artifactId: string): Promise<RuntimeArtifact> {
    const artifact = (await this.listArtifacts(runId)).find((item) => item.id === artifactId);
    if (!artifact) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Artifact not found: ${artifactId}`,
      });
    }
    return artifact;
  }

  async exportTrace(runId: string): Promise<RuntimeTraceBundle> {
    return (await this.getRun(runId)).trace;
  }

  async *replayTrace(runId: string): AsyncIterable<IOISDKMessage> {
    yield* this.streamRun(runId);
  }

  async inspectRun(runId: string): Promise<RuntimeTraceBundle> {
    return this.exportTrace(runId);
  }

  async scorecard(runId: string): Promise<RuntimeScorecard> {
    return (await this.getRun(runId)).trace.scorecard;
  }

  async listModels(): Promise<RuntimeModelCatalogEntry[]> {
    return [
      { id: "local:auto", provider: "ioi-local", cost: "local", quality: "adaptive" },
      { id: "gpt-5.5", provider: "configured-provider", cost: "high", quality: "frontier" },
      { id: "gpt-5.4-mini", provider: "configured-provider", cost: "low", quality: "fast" },
    ];
  }

  async listRepositories(): Promise<Array<{ url: string; source: string; status: string }>> {
    return [{ url: this.cwd, source: "local", status: "available" }];
  }

  async getAccount(): Promise<RuntimeAccountProfile> {
    return {
      id: "local-operator",
      email: process.env.IOI_OPERATOR_EMAIL ?? null,
      authorityLevel: "local",
      privacyClass: "local_private",
      source: "explicit_mock_runtime_substrate_projection",
    };
  }

  async listRuntimeNodes(): Promise<RuntimeNodeProfile[]> {
    return [
      {
        id: "local-mock-projection",
        kind: "local",
        status: "available",
        privacyClass: "local_private",
        evidenceRefs: ["explicit_mock_runtime_substrate_projection"],
      },
      {
        id: "hosted-provider",
        kind: "hosted",
        status: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT,
        privacyClass: "hosted",
        evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
      },
      {
        id: "self-hosted-provider",
        kind: "self_hosted",
        status: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT,
        privacyClass: "workspace",
        evidenceRefs: ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
      },
    ];
  }

  async listTools(): Promise<RuntimeToolCatalogEntry[]> {
    return [
      {
        stableToolId: "fs.read",
        displayName: "Read file",
        primitiveCapabilities: ["prim:fs.read"],
        authorityScopeRequirements: [],
        effectClass: "local_read",
        riskDomain: "filesystem",
        inputSchema: { type: "object", required: ["path"] },
        outputSchema: { type: "object", required: ["content"] },
        evidenceRequirements: ["file_read_receipt"],
      },
      {
        stableToolId: "sys.exec",
        displayName: "Shell command",
        primitiveCapabilities: ["prim:sys.exec"],
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        effectClass: "local_command",
        riskDomain: "host",
        inputSchema: { type: "object", required: ["command"] },
        outputSchema: { type: "object", required: ["exitCode", "stdout", "stderr"] },
        evidenceRequirements: ["shell_receipt", "sandbox_profile"],
      },
      {
        stableToolId: "mcp.invoke",
        displayName: "MCP tool invocation",
        primitiveCapabilities: ["prim:connector.invoke"],
        authorityScopeRequirements: ["scope:mcp.invoke"],
        effectClass: "connector_call",
        riskDomain: "connector",
        inputSchema: { type: "object", required: ["server", "tool"] },
        outputSchema: { type: "object" },
        evidenceRequirements: ["mcp_containment_receipt"],
      },
    ];
  }

  async rememberMemory(agentId: string, input: RememberMemoryInput): Promise<RememberMemoryResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memoryPolicyForAgent(agent, threadId, input);
    const blocked = mockMemoryWriteBlockReason(policy, input, true);
    if (blocked) {
      throw new IoiAgentError({
        code: "policy",
        message: "Memory write blocked by policy.",
        details: { agentId, threadId, reason: blocked, policy },
      });
    }
    const record = mockMemoryRecord(agent, input.text, {
      memoryKey: input.memoryKey,
      scope: input.scope ?? "thread",
      threadId,
      source: "sdk_memory_helper",
      workflowGraphId: input.workflowGraphId ?? null,
      workflowNodeId: input.workflowNodeId ?? "runtime.memory",
      workflowNodeType: input.workflowNodeType ?? "Memory",
    });
    this.memories.set(record.id, record);
    this.persistMemory(record);
    return {
      record,
      receipt: memoryReceipt(record),
    };
  }

  async listMemory(agentId: string, options: MemoryListOptions = {}): Promise<AgentMemoryProjection> {
    const agent = await this.getAgent(agentId);
    const threadId = options.threadId ?? threadIdForAgent(agent.id);
    const records = this.memoryForAgent(agent, threadId, options);
    return {
      schemaVersion: "ioi.agent-runtime.memory.v1",
      object: "ioi.agent_memory_projection",
      threadId,
      agentId: agent.id,
      workspace: agent.cwd,
      policy: this.memoryPolicyForAgent(agent, threadId),
      paths: mockMemoryPath(agent, threadId, this.checkpointDir),
      filters: memoryListFilters(options),
      records,
      totalMatches: records.length,
    };
  }

  async updateMemory(agentId: string, memoryId: string, input: UpdateMemoryRecordInput): Promise<RememberMemoryResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memoryPolicyForAgent(agent, threadId, input);
    const blocked = mockMemoryWriteBlockReason(policy, input, true);
    if (blocked) {
      throw new IoiAgentError({
        code: "policy",
        message: "Memory edit blocked by policy.",
        details: { agentId, threadId, memoryId, reason: blocked, policy },
      });
    }
    const existing = this.memories.get(memoryId);
    if (!existing) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Memory record not found: ${memoryId}`,
        details: { memoryId },
      });
    }
    const updated: AgentMemoryRecord = {
      ...existing,
      fact: input.text,
      updatedAt: new Date().toISOString(),
      source: "sdk_memory_edit",
      evidenceRefs: [...new Set([...existing.evidenceRefs, "memory.edit"])],
    };
    this.persistMemory(updated);
    return { record: updated, receipt: memoryReceipt(updated, "memory_edit", "edit") };
  }

  async deleteMemory(agentId: string, memoryId: string, input: DeleteMemoryRecordInput = {}): Promise<RememberMemoryResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memoryPolicyForAgent(agent, threadId, input);
    const blocked = mockMemoryWriteBlockReason(policy, input, true);
    if (blocked) {
      throw new IoiAgentError({
        code: "policy",
        message: "Memory delete blocked by policy.",
        details: { agentId, threadId, memoryId, reason: blocked, policy },
      });
    }
    const existing = this.memories.get(memoryId);
    if (!existing) {
      throw new IoiAgentError({
        code: "not_found",
        message: `Memory record not found: ${memoryId}`,
        details: { memoryId },
      });
    }
    this.memories.delete(memoryId);
    this.rmQuiet(path.join(this.checkpointDir, "memory", `${memoryId}.json`));
    return { record: existing, receipt: memoryReceipt(existing, "memory_delete", "delete") };
  }

  async getMemoryPolicy(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPolicy> {
    const agent = await this.getAgent(agentId);
    return this.memoryPolicyForAgent(agent, options.threadId ?? threadIdForAgent(agent.id));
  }

  async setMemoryPolicy(agentId: string, input: MemoryPolicyInput): Promise<MemoryPolicyUpdateResult> {
    const agent = await this.getAgent(agentId);
    const threadId = input.threadId ?? threadIdForAgent(agent.id);
    const policy = mockMemoryPolicy(agent, {
      ...this.memoryPolicyForAgent(agent, threadId),
      ...input,
      threadId,
      targetType: input.targetType ?? "thread",
      targetId: input.targetId ?? threadId,
      source: "sdk_memory_policy",
    });
    this.persistMemoryPolicy(policy);
    return { policy, receipt: memoryPolicyReceipt(policy) };
  }

  async memoryPath(agentId: string, options: { threadId?: string } = {}): Promise<AgentMemoryPathProjection> {
    const agent = await this.getAgent(agentId);
    return mockMemoryPath(agent, options.threadId ?? threadIdForAgent(agent.id), this.checkpointDir);
  }

  private async createRun(
    agentId: string,
    prompt: string,
    mode: RuntimeRunRecord["mode"],
    options: SendOptions = {},
  ): Promise<RuntimeRunRecord> {
    const agent = await this.getAgent(agentId);
    if (agent.runtime !== "local") {
      throw new IoiAgentError({
        code: "external_blocker",
        message: `${agent.runtime} runtime provider is not configured for SDK execution.`,
        details: { runtime: agent.runtime, agentId },
      });
    }
    const memory = this.resolveRunMemory(agent, prompt, options, mode);
    const run = buildMockRun(agent, prompt, mode, options, memory);
    await emitCallbacks(run, options);
    this.persistRun(run);
    return run;
  }

  private withTerminalReplacement(
    run: RuntimeRunRecord,
    status: RuntimeRunRecord["status"],
    data: Record<string, unknown>,
  ): RuntimeRunRecord {
    const events = run.events.filter(
      (event) => event.type !== "completed" && event.type !== "canceled",
    );
    const canceledEvent = makeEvent(run.id, run.agentId, events.length, "canceled", "Run canceled", data);
    const stopCondition: StopConditionProjection = {
      reason: "marginal_improvement_too_low",
      evidenceSufficient: true,
      rationale: "Run has an explicit cancellation terminal state and replay pointer.",
    };
    const trace = {
      ...run.trace,
      events: [...events, canceledEvent],
      stopCondition,
      qualityLedger: {
        ...run.trace.qualityLedger,
        failureOntologyLabels: ["operator_cancel"],
      },
    };
    return {
      ...run,
      status,
      updatedAt: new Date().toISOString(),
      events: trace.events,
      trace,
      result: "Run canceled with terminal event continuity preserved.",
    };
  }

  private loadCheckpoints(): void {
    for (const [kind, target] of [
      ["agents", this.agents],
      ["runs", this.runs],
      ["memory", this.memories],
      ["memory-policies", this.memoryPolicies],
    ] as const) {
      const dir = path.join(this.checkpointDir, kind);
      if (!fs.existsSync(dir)) {
        continue;
      }
      for (const file of fs.readdirSync(dir)) {
        if (!file.endsWith(".json")) {
          continue;
        }
        const parsed = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
        target.set(parsed.id, parsed);
      }
    }
  }

  private persistAgent(agent: RuntimeAgentRecord): void {
    this.agents.set(agent.id, agent);
    writeJson(path.join(this.checkpointDir, "agents", `${agent.id}.json`), agent);
  }

  private persistRun(run: RuntimeRunRecord): void {
    this.runs.set(run.id, run);
    writeJson(path.join(this.checkpointDir, "runs", `${run.id}.json`), run);
  }

  private persistMemory(record: AgentMemoryRecord): void {
    this.memories.set(record.id, record);
    writeJson(path.join(this.checkpointDir, "memory", `${record.id}.json`), record);
  }

  private persistMemoryPolicy(policy: AgentMemoryPolicy): void {
    this.memoryPolicies.set(policy.id, policy);
    writeJson(path.join(this.checkpointDir, "memory-policies", `${safeFileName(policy.id)}.json`), policy);
  }

  private memoryForAgent(agent: RuntimeAgentRecord, threadId = threadIdForAgent(agent.id), options: MemoryListOptions = {}): AgentMemoryRecord[] {
    const filters = memoryListFilters(options);
    const records = [...this.memories.values()]
      .filter(
        (record) =>
          record.scope === "global" ||
          record.threadId === threadId ||
          (record.agentId === agent.id && record.scope !== "thread") ||
          (record.workspace === agent.cwd && record.scope === "workspace"),
      )
      .filter((record) => !filters.scope || record.scope === filters.scope)
      .filter((record) => !filters.memoryKey || record.memoryKey === filters.memoryKey)
      .filter((record) => !filters.query || mockMemorySearchText(record).includes(filters.query))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    const limited = filters.limit ? records.slice(0, filters.limit) : records;
    return filters.redaction === "redacted" ? limited.map(redactMockMemoryRecord) : limited;
  }

  private memoryPolicyForAgent(
    agent: RuntimeAgentRecord,
    threadId = threadIdForAgent(agent.id),
    overrides: Partial<MemoryPolicyInput & RememberMemoryInput & UpdateMemoryRecordInput> = {},
  ): AgentMemoryPolicy {
    const stored =
      this.memoryPolicies.get(mockMemoryPolicyId("thread", threadId)) ??
      this.memoryPolicies.get(mockMemoryPolicyId("agent", agent.id));
    return mockMemoryPolicy(agent, {
      ...stored,
      ...mockPolicyFields(overrides),
      threadId,
      targetType: "thread",
      targetId: threadId,
      effective: true,
    });
  }

  private resolveRunMemory(
    agent: RuntimeAgentRecord,
    prompt: string,
    options: SendOptions,
    mode: RuntimeRunRecord["mode"] = "send",
  ): MockRunMemory {
    const threadId = options.memory?.threadId ?? threadIdForAgent(agent.id);
    const command = parseMockMemoryCommand(prompt);
    const policyUpdates: MemoryPolicyUpdateResult[] = [];
    const mutations: MockMemoryMutation[] = [];
    let policy = this.memoryPolicyForAgent(agent, threadId, options.memory ?? {});
    if (command.kind === "disable" || command.kind === "enable") {
      const nextPolicy = mockMemoryPolicy(agent, {
        ...policy,
        threadId,
        targetType: "thread",
        targetId: threadId,
        disabled: command.kind === "disable",
        injectionEnabled: command.kind !== "disable",
        source: `sdk_memory_${command.kind}`,
      });
      this.persistMemoryPolicy(nextPolicy);
      const update = { policy: nextPolicy, receipt: memoryPolicyReceipt(nextPolicy) };
      policyUpdates.push(update);
      mutations.push({ ...update, operation: "policy_update" });
      policy = this.memoryPolicyForAgent(agent, threadId, options.memory ?? {});
    }
    const subagentMemoryInheritance =
      mode === "handoff"
        ? this.resolveSubagentMemoryInheritance(agent, threadId, options, policy)
        : null;
    const effectivePolicy = subagentMemoryInheritance?.effectivePolicy ?? policy;
    const requestedRemember = options.memory?.remember;
    const requestedWrite =
      command.kind === "remember" ||
      command.kind === "edit" ||
      command.kind === "delete" ||
      Boolean(requestedRemember);
    const policyBlockReason = mockMemoryWriteBlockReason(effectivePolicy, options.memory ?? {}, requestedWrite);
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
        writes: [],
        mutations,
        policy: effectivePolicy,
        policyUpdates,
        paths: mockMemoryPath(agent, threadId, this.checkpointDir),
        disabled: Boolean(effectivePolicy.disabled),
        policyBlockReason,
        subagentMemoryInheritance,
      };
    }
    const writes: RememberMemoryResult[] = [];
    if (!policyBlockReason && command.kind === "remember") {
      const record = mockMemoryRecord(agent, command.text, {
        memoryKey: options.memory?.memoryKey,
        scope: effectivePolicy.scope ?? "thread",
        threadId,
        source: "chat_hash_remember",
      });
      this.persistMemory(record);
      const write = { record, receipt: memoryReceipt(record) };
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    } else if (!policyBlockReason && command.kind === "edit") {
      const existing = this.memories.get(command.id);
      if (existing) {
        const record = {
          ...existing,
          fact: command.text,
          source: "sdk_memory_edit",
          updatedAt: new Date().toISOString(),
          evidenceRefs: [...new Set([...existing.evidenceRefs, "memory.edit"])],
        };
        this.persistMemory(record);
        mutations.push({ record, receipt: memoryReceipt(record, "memory_edit", "edit"), operation: "edit" });
      }
    } else if (!policyBlockReason && command.kind === "delete") {
      const record = this.memories.get(command.id);
      if (record) {
        this.memories.delete(record.id);
        this.rmQuiet(path.join(this.checkpointDir, "memory", `${record.id}.json`));
        mutations.push({ record, receipt: memoryReceipt(record, "memory_delete", "delete"), operation: "delete" });
      }
    } else if (!policyBlockReason && requestedRemember) {
      const record = mockMemoryRecord(agent, requestedRemember, {
        memoryKey: options.memory?.memoryKey,
        scope: effectivePolicy.scope ?? "thread",
        threadId,
        source: "sdk_send_memory_option",
      });
      this.persistMemory(record);
      const write = { record, receipt: memoryReceipt(record) };
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    }
    return {
      command: command.kind,
      records: subagentMemoryInheritance?.records ?? this.memoryForAgent(agent, threadId, options.memory ?? {}),
      writes,
      mutations,
      policy: effectivePolicy,
      policyUpdates,
      paths: mockMemoryPath(agent, threadId, this.checkpointDir),
      policyBlockReason,
      subagentMemoryInheritance,
    };
  }

  private resolveSubagentMemoryInheritance(
    agent: RuntimeAgentRecord,
    threadId: string,
    options: SendOptions,
    parentPolicy: AgentMemoryPolicy,
  ): SubagentMemoryInheritanceProjection {
    const memoryOptions = options.memory ?? {};
    const requestedMode = optionalMemoryString(memoryOptions.subagentInheritance) ?? parentPolicy.subagentInheritance ?? "explicit";
    const mode = normalizeSubagentInheritanceMode(requestedMode);
    const receiver = subagentReceiverName(options);
    const filters = memoryListFilters(memoryOptions);
    const parentAllowsInjection = !parentPolicy.disabled && parentPolicy.injectionEnabled !== false;
    const records =
      parentAllowsInjection && shouldInheritSubagentMemory(mode, memoryOptions)
        ? this.memoryForAgent(agent, threadId, {
            ...memoryOptions,
            redaction: memoryOptions.redaction ?? parentPolicy.redaction,
          })
        : [];
    const effectivePolicy = mockSubagentMemoryPolicy(agent, parentPolicy, {
      threadId,
      receiver,
      mode,
    });
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
      ].filter((value): value is string => Boolean(value)),
    };
  }

  private async agentForThread(threadId: string): Promise<RuntimeAgentRecord> {
    const agent = [...this.agents.values()].find((candidate) => threadIdForAgent(candidate.id) === threadId);
    if (!agent) {
      throw new IoiAgentError({ code: "not_found", message: `Thread not found: ${threadId}` });
    }
    return agent;
  }

  private threadRecordForAgent(agent: RuntimeAgentRecord): RuntimeThreadRecord {
    const runs = [...this.runs.values()]
      .filter((run) => run.agentId === agent.id)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    const latestRun = runs.at(-1);
    const threadId = threadIdForAgent(agent.id);
    const events = this.threadRuntimeEvents(agent);
    return {
      schema_version: "ioi.runtime.thread.v1",
      thread_id: threadId,
      session_id: `session_${agent.id}`,
      agent_id: agent.id,
      workspace_root: agent.cwd,
      title: latestRun?.objective ?? agent.cwd,
      mode: "agent",
      approval_mode: "suggest",
      trust_profile: "local_private",
      model_route: agent.modelId,
      status: this.threadRecordStatus(agent),
      latest_turn_id: latestRun ? turnIdForRun(latestRun.id) : null,
      latest_seq: events.at(-1)?.seq ?? 0,
      event_stream_id: eventStreamIdForThread(threadId),
      workflow_graph_id: null,
      harness_binding_id: null,
      agentgres_projection_ref: `agents/${agent.id}.json`,
      created_at: agent.createdAt,
      updated_at: agent.updatedAt,
      archived_at: agent.status === "archived" ? agent.updatedAt : null,
      fixture_profile: "agent_sdk_mock",
    };
  }

  private turnRecordForRun(run: RuntimeRunRecord): RuntimeTurnRecord {
    const turnId = turnIdForRun(run.id);
    const events = this.threadRuntimeEvents(this.agents.get(run.agentId)).filter(
      (event) => event.turn_id === turnId,
    );
    const status = runtimeTurnStatusForRun(run.status);
    return {
      schema_version: "ioi.runtime.turn.v1",
      turn_id: turnId,
      thread_id: threadIdForAgent(run.agentId),
      parent_turn_id: null,
      request_id: run.id,
      status,
      input_item_ids: events.filter((event) => event.event_kind === "turn.started").map((event) => event.item_id),
      output_item_ids: events.filter((event) => event.event_kind !== "turn.started").map((event) => event.item_id),
      seq_start: events.at(0)?.seq ?? null,
      seq_end: status === "running" || status === "queued" ? null : (events.at(-1)?.seq ?? null),
      started_at: run.createdAt,
      completed_at: run.status === "running" || run.status === "queued" ? null : run.updatedAt,
      mode: "agent",
      approval_mode: "suggest",
      model_route_decision_id: run.modelRouteDecision?.decisionId ?? null,
      usage: null,
      stop_reason: run.trace.stopCondition.reason,
      error: run.status === "failed" ? run.result : null,
      rollback_snapshot_id: null,
      quality_ledger_ref: run.trace.qualityLedger.ledgerId,
      workflow_execution_ref: null,
      fixture_profile: "agent_sdk_mock",
    };
  }

  private threadRuntimeEvents(agent?: RuntimeAgentRecord): RuntimeEventEnvelope[] {
    if (!agent) return [];
    const threadId = threadIdForAgent(agent.id);
    const streamId = eventStreamIdForThread(threadId);
    const events: RuntimeEventEnvelope[] = [
      mockRuntimeEventEnvelope({
        agent,
        threadId,
        streamId,
        seq: 1,
        eventKind: "thread.started",
        sourceEventKind: "agent.create",
        itemId: `${threadId}:item:thread-started`,
        payload: {
          event_kind: "ThreadStarted",
          agent_id: agent.id,
          thread_id: threadId,
          status: this.threadRecordStatus(agent),
        },
        createdAt: agent.createdAt,
        componentKind: "runtime_thread",
        workflowNodeId: "runtime.runtime-thread",
      }),
    ];
    const runs = [...this.runs.values()]
      .filter((run) => run.agentId === agent.id)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    for (const run of runs) {
      const turnId = turnIdForRun(run.id);
      for (const event of run.events) {
        events.push(mockRuntimeEnvelopeForSdkEvent({
          agent,
          event,
          run,
          seq: events.length + 1,
          streamId,
          threadId,
          turnId,
        }));
      }
    }
    return events;
  }

  private threadRecordStatus(agent: RuntimeAgentRecord): RuntimeThreadRecord["status"] {
    return agent.status === "archived" ? "archived" : agent.status === "closed" ? "completed" : "active";
  }

  private rmQuiet(filePath: string): void {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      // Best-effort cleanup; mock checkpoints are projections, not canonical runtime state.
    }
  }
}

function runtimeModeForOptions(options: AgentOptions): RuntimeMode {
  if (options.cloud) return "cloud";
  if (options.hosted) return "hosted";
  if (options.selfHosted) return "selfHosted";
  return "local";
}

function ensureProviderConfigured(runtime: RuntimeMode, options: AgentOptions): void {
  if (runtime === "local") {
    return;
  }
  const providerEndpoint =
    endpointForCloud(options.cloud ?? options.hosted) ??
    options.selfHosted?.endpoint ??
    process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ??
    process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  if (!providerEndpoint) {
    throw new IoiAgentError({
      code: "external_blocker",
      message: `${runtime} runtime requested, but no IOI SDK provider endpoint is configured.`,
      details: {
        runtime,
        requiredEnvironment: [
          "IOI_AGENT_SDK_HOSTED_ENDPOINT",
          "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
        ],
      },
    });
  }
}

function endpointForCloud(options?: CloudAgentOptions): string | undefined {
  return options?.endpoint;
}

function summarizeOptions(cwd: string, options: AgentOptions): AgentOptionsSummary {
  const cursorConfig = loadCursorCompatibilityConfig(cwd);
  return {
    localCwd: options.local?.cwd,
    cloudConfigured: Boolean(options.cloud ?? options.hosted),
    selfHostedConfigured: Boolean(options.selfHosted),
    mcpServerNames: [
      ...new Set([
        ...Object.keys(options.mcpServers ?? {}),
        ...Object.keys(cursorConfig.mcpServers),
      ]),
    ],
    skillNames: cursorConfig.skillNames,
    hookNames: cursorConfig.hookNames,
    subagentNames: Object.keys(options.agents ?? {}),
    sandboxProfile: options.sandboxOptions?.profile ?? "development",
  };
}

function loadCursorCompatibilityConfig(cwd: string): {
  mcpServers: Record<string, McpServerConfig>;
  skillNames: string[];
  hookNames: string[];
} {
  const cursorDir = path.join(cwd, ".cursor");
  const mcpPath = path.join(cursorDir, "mcp.json");
  const hooksPath = path.join(cursorDir, "hooks.json");
  const skillsDir = path.join(cursorDir, "skills");
  const mcpServers = fs.existsSync(mcpPath) ? readJson(mcpPath).mcpServers ?? {} : {};
  const hookNames = fs.existsSync(hooksPath) ? Object.keys(readJson(hooksPath)) : [];
  const skillNames = fs.existsSync(skillsDir)
    ? fs.readdirSync(skillsDir).filter((entry) => !entry.startsWith("."))
    : [];
  return { mcpServers, hookNames, skillNames };
}

function mockModelRouteDecision(
  model: SendOptions["model"] | undefined,
  requestedModel: string,
  fallback?: ModelRouteDecision,
): ModelRouteDecision {
  if (!model && fallback) {
    return fallback;
  }
  const routeId = model?.routeId ?? model?.route ?? fallback?.routeId ?? "route.local-first";
  const autoResolved = requestedModel.trim().toLowerCase() === "auto";
  const selectedModel = autoResolved ? "local:auto" : requestedModel;
  const workflowNodeId = model?.workflowNodeId ?? fallback?.workflowNodeId ?? "runtime.model-router";
  const workflowNodeType = model?.workflowNodeType ?? fallback?.workflowNodeType ?? "Model Router";
  return {
    schemaVersion: "ioi.model-route-decision.v1",
    object: "ioi.model_route_decision",
    eventKind: "ModelRouteDecision",
    decisionId: mockStableHash({
      routeId,
      requestedModel,
      selectedModel,
      workflowNodeId,
      reasoningEffort: model?.reasoningEffort ?? model?.thinking,
    }),
    routeId,
    capability: model?.capability ?? fallback?.capability ?? "chat",
    requestedModel,
    requestedModelMode: autoResolved ? "auto" : requestedModel ? "explicit" : "route_default",
    autoResolved,
    selectedModel,
    upstreamModel: selectedModel,
    neverSendAutoUpstream: !autoResolved || selectedModel !== "auto",
    endpointId: selectedModel === "local:auto" ? "endpoint.local.auto" : `endpoint.mock.${selectedModel.replace(/[^a-z0-9]+/gi, "_")}`,
    providerId: "provider.local.folder",
    providerKind: "local_folder",
    providerLabel: "SDK mock local provider",
    reasoningEffort: model?.reasoningEffort ?? model?.thinking ?? fallback?.reasoningEffort ?? "provider_default",
    localRemotePlacement: "local",
    privacyPosture: model?.privacy ?? fallback?.privacyPosture ?? "local_private",
    costEstimateUsd: 0,
    costEstimateSource: "local_default",
    fallbackModel: null,
    fallbackEndpointId: "endpoint.local.auto",
    fallbackAllowed: true,
    fallbackTriggered: false,
    fallbackReason: null,
    rationale: autoResolved
      ? "model=auto resolved to local:auto through route.local-first before provider invocation."
      : `Explicit model ${requestedModel} resolved to ${selectedModel} on local_folder.`,
    policyConstraints: {
      routePrivacy: model?.privacy ?? "local_or_enterprise",
      requestedPrivacy: model?.privacy ?? null,
      providerEligibility: ["local_folder"],
      deniedProviders: ["openai", "anthropic", "gemini"],
      maxCostUsd: model?.maxCostUsd ?? 0,
      allowHostedFallback: Boolean(model?.allowHostedFallback),
      localOnly: model?.privacy === "local_only",
    },
    evaluatedCandidateCount: 1,
    rejectedCandidates: [],
    workflowGraphId: model?.workflowGraphId ?? fallback?.workflowGraphId ?? null,
    workflowNodeId,
    workflowNodeType,
    responseId: null,
    previousResponseId: null,
    policyHash: mockStableHash(model?.policy ?? {}),
    evidenceRefs: [
      "model_router",
      routeId,
      selectedModel === "local:auto" ? "endpoint.local.auto" : null,
      "provider.local.folder",
      autoResolved ? "model_auto_resolved_before_provider_invocation" : null,
    ].filter((value): value is string => Boolean(value)),
  };
}

function mockStableHash(value: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

interface MockRunMemory {
  command: MockMemoryCommand["kind"];
  records: AgentMemoryRecord[];
  writes: RememberMemoryResult[];
  mutations?: MockMemoryMutation[];
  policy?: AgentMemoryPolicy;
  policyUpdates?: MemoryPolicyUpdateResult[];
  paths?: AgentMemoryPathProjection;
  disabled?: boolean;
  policyBlockReason?: string | null;
  subagentMemoryInheritance?: SubagentMemoryInheritanceProjection | null;
}

type MockMemoryCommand =
  | { kind: "none" }
  | { kind: "show" }
  | { kind: "remember"; text: string }
  | { kind: "disable" }
  | { kind: "enable" }
  | { kind: "path" }
  | { kind: "edit"; id: string; text: string }
  | { kind: "delete"; id: string };

type MockMemoryMutation =
  | (RememberMemoryResult & { operation: "write" | "edit" | "delete" })
  | (MemoryPolicyUpdateResult & { operation: "policy_update" });

function parseMockMemoryCommand(prompt: string): MockMemoryCommand {
  const text = String(prompt ?? "").trim();
  const remember = text.match(/^#\s*remember\s+([\s\S]+)$/i);
  if (remember?.[1]?.trim()) return { kind: "remember", text: remember[1].trim() };
  if (/^\/memory(?:\s+show)?\s*$/i.test(text)) return { kind: "show" };
  if (/^\/memory\s+disable\s*$/i.test(text)) return { kind: "disable" };
  if (/^\/memory\s+enable\s*$/i.test(text)) return { kind: "enable" };
  if (/^\/memory\s+path\s*$/i.test(text)) return { kind: "path" };
  const edit = text.match(/^\/memory\s+edit\s+(\S+)\s+([\s\S]+)$/i);
  if (edit?.[1] && edit?.[2]?.trim()) return { kind: "edit", id: edit[1], text: edit[2].trim() };
  const deletion = text.match(/^\/memory\s+(?:delete|remove|forget)\s+(\S+)\s*$/i);
  if (deletion?.[1]) return { kind: "delete", id: deletion[1] };
  return { kind: "none" };
}

function mockMemoryRecord(
  agent: RuntimeAgentRecord,
  text: string,
  fields: {
    memoryKey?: string | null;
    scope: string;
    threadId: string;
    source: string;
    workflowGraphId?: string | null;
    workflowNodeId?: string | null;
    workflowNodeType?: string | null;
  },
): AgentMemoryRecord {
  const now = new Date().toISOString();
  return {
    schemaVersion: "ioi.agent-runtime.memory.v1",
    id: `memory_${crypto.randomUUID()}`,
    object: "ioi.agent_memory_record",
    scope: fields.scope,
    fact: String(text).trim(),
    memoryKey: fields.memoryKey ?? null,
    agentId: agent.id,
    threadId: fields.threadId,
    workspace: agent.cwd,
    workflowGraphId: fields.workflowGraphId ?? null,
    workflowNodeId: fields.workflowNodeId ?? "runtime.memory",
    workflowNodeType: fields.workflowNodeType ?? "Memory",
    source: fields.source,
    redaction: "none",
    createdAt: now,
    updatedAt: now,
    evidenceRefs: ["agent_memory_store", "memory.write", agent.id, fields.threadId],
  };
}

function memoryListFilters(options: MemoryListOptions = {}): MemoryListOptions {
  return {
    threadId: options.threadId,
    scope: optionalMemoryString(options.scope),
    memoryKey: optionalMemoryString(options.memoryKey),
    query: optionalMemoryString(options.query ?? options.q)?.toLowerCase(),
    limit: normalizeMemoryLimit(options.limit),
    redaction: options.redaction === "redacted" ? "redacted" : "none",
  };
}

function optionalMemoryString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function normalizeMemoryLimit(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  return Math.min(Math.floor(parsed), 200);
}

function mockMemorySearchText(record: AgentMemoryRecord): string {
  return [
    record.fact,
    record.id,
    record.scope,
    record.memoryKey,
    record.workflowGraphId,
    record.workflowNodeId,
    record.workflowNodeType,
    record.source,
  ]
    .filter((value) => value !== undefined && value !== null)
    .map((value) => String(value).toLowerCase())
    .join("\n");
}

function redactMockMemoryRecord(record: AgentMemoryRecord): AgentMemoryRecord & { factHash: string } {
  return {
    ...record,
    fact: "[REDACTED]",
    factHash: crypto.createHash("sha256").update(record.fact).digest("hex"),
    redaction: "redacted",
  };
}

function memoryReceipt(
  record: AgentMemoryRecord,
  kind: "memory_write" | "memory_edit" | "memory_delete" = "memory_write",
  operation = "write",
): RuntimeReceipt {
  return {
    id: `receipt_${record.id}_${operation}`,
    kind,
    summary:
      kind === "memory_write"
        ? `Remembered ${record.scope} memory for ${record.threadId ?? record.agentId}.`
        : `${kind === "memory_edit" ? "Edited" : "Deleted"} memory record ${record.id}.`,
    redaction: "none",
    evidenceRefs: ["agent_memory_store", `memory.${operation}`, record.id],
  };
}

function mockMemoryPolicy(agent: RuntimeAgentRecord, fields: Partial<AgentMemoryPolicy> & { threadId?: string } = {}): AgentMemoryPolicy {
  const now = new Date().toISOString();
  const targetType = fields.targetType ?? "thread";
  const threadId = fields.threadId ?? threadIdForAgent(agent.id);
  const targetId = fields.targetId ?? threadId;
  return {
    schemaVersion: "ioi.agent-runtime.memory-policy.v1",
    id: mockMemoryPolicyId(targetType, targetId),
    object: "ioi.agent_memory_policy",
    targetType,
    targetId,
    agentId: agent.id,
    threadId,
    workspace: agent.cwd,
    disabled: false,
    injectionEnabled: true,
    readOnly: false,
    writeRequiresApproval: false,
    retention: "persistent",
    redaction: "none",
    subagentInheritance: "explicit",
    scope: "thread",
    source: "sdk_memory_policy_default",
    createdAt: fields.createdAt ?? now,
    updatedAt: now,
    evidenceRefs: ["agent_memory_store", "memory.policy"],
    ...mockPolicyFields(fields),
    effective: fields.effective,
    policyRefs: fields.policyRefs,
  };
}

function mockSubagentMemoryPolicy(
  agent: RuntimeAgentRecord,
  parentPolicy: AgentMemoryPolicy,
  fields: {
    threadId: string;
    receiver: string | null;
    mode: SubagentMemoryInheritanceProjection["mode"];
  },
): AgentMemoryPolicy {
  const targetId = `${fields.threadId}:${fields.receiver ?? "subagent"}`;
  const id = mockMemoryPolicyId("subagent", targetId);
  const disabled = parentPolicy.disabled || fields.mode === "none";
  const injectionEnabled = parentPolicy.injectionEnabled !== false && fields.mode !== "none";
  const readOnly = disabled || parentPolicy.readOnly || fields.mode === "read_only";
  const writeRequiresApproval =
    fields.mode === "explicit" ? true : Boolean(parentPolicy.writeRequiresApproval);
  const now = new Date().toISOString();
  return {
    ...parentPolicy,
    id,
    targetType: "subagent",
    targetId,
    agentId: agent.id,
    threadId: fields.threadId,
    workspace: agent.cwd,
    disabled,
    injectionEnabled,
    readOnly,
    writeRequiresApproval,
    source: "sdk_subagent_memory_inheritance",
    updatedAt: now,
    evidenceRefs: [
      ...new Set([
        ...parentPolicy.evidenceRefs,
        "subagent_memory_inheritance",
        "memory.policy.effective.subagent",
      ]),
    ],
    effective: true,
    policyRefs: [parentPolicy.id].filter(Boolean),
  };
}

function normalizeSubagentInheritanceMode(value: unknown): SubagentMemoryInheritanceProjection["mode"] {
  const mode = optionalMemoryString(value) ?? "explicit";
  return ["none", "explicit", "read_only", "full"].includes(mode) ? mode : "explicit";
}

function shouldInheritSubagentMemory(
  mode: SubagentMemoryInheritanceProjection["mode"],
  options: SendOptions["memory"] = {},
): boolean {
  if (mode === "none") return false;
  if (mode === "explicit") return hasExplicitSubagentMemorySelector(options);
  return true;
}

function hasExplicitSubagentMemorySelector(options: SendOptions["memory"] = {}): boolean {
  return Boolean(
    optionalMemoryString(options?.memoryKey) ??
      optionalMemoryString(options?.query ?? options?.q) ??
      optionalMemoryString(options?.scope),
  );
}

function subagentReceiverName(options: SendOptions): string | null {
  const receiver = (options as HandoffOptions).receiver;
  return optionalMemoryString(receiver) ?? null;
}

function mockPolicyFields(value: object = {}): Partial<AgentMemoryPolicy> {
  const fields: Partial<AgentMemoryPolicy> = {};
  const source = value as Record<string, unknown>;
  for (const key of [
    "disabled",
    "injectionEnabled",
    "readOnly",
    "writeRequiresApproval",
    "retention",
    "redaction",
    "subagentInheritance",
    "scope",
  ] as const) {
    if (source[key] !== undefined) {
      (fields as Record<string, unknown>)[key] = source[key];
    }
  }
  return fields;
}

function memoryPolicyReceipt(policy: AgentMemoryPolicy): RuntimeReceipt {
  return {
    id: `receipt_${policy.id}_${mockStableHash(policy.updatedAt).slice(0, 12)}`,
    kind: "memory_policy",
    summary: `Updated memory policy for ${policy.targetId}.`,
    redaction: "none",
    evidenceRefs: ["agent_memory_store", "memory.policy", policy.id],
  };
}

function subagentMemoryInheritanceReceiptForRun(
  runId: string,
  projection: SubagentMemoryInheritanceProjection,
): RuntimeReceipt {
  return {
    id: `receipt_${runId}_subagent_memory_inheritance`,
    kind: "subagent_memory_inheritance",
    summary: `Subagent memory inheritance ${projection.mode} for ${projection.subagentName ?? "handoff"} exposed ${projection.records.length} record(s).`,
    redaction: projection.effectivePolicy.redaction === "redacted" ? "redacted" : "none",
    evidenceRefs: projection.evidenceRefs,
  };
}

function mockMemoryWriteBlockReason(policy: AgentMemoryPolicy, options: object = {}, requestedWrite = false): string | null {
  if (!requestedWrite) return null;
  const source = options as { writeApproved?: unknown };
  if (policy.disabled) return "memory_disabled";
  if (policy.readOnly) return "memory_read_only";
  if (policy.writeRequiresApproval && !source.writeApproved) return "memory_write_requires_approval";
  return null;
}

function mockMemoryEventKind(operation: MockMemoryMutation["operation"]): string {
  switch (operation) {
    case "policy_update":
      return "MemoryPolicy";
    case "edit":
      return "MemoryEdit";
    case "delete":
      return "MemoryDelete";
    case "write":
    default:
      return "MemoryWrite";
  }
}

function mockMemoryEventSummary(operation: MockMemoryMutation["operation"]): string {
  switch (operation) {
    case "policy_update":
      return "Memory policy updated";
    case "edit":
      return "Memory record edited";
    case "delete":
      return "Memory record deleted";
    case "write":
    default:
      return "Memory write recorded";
  }
}

function mockMemoryPath(agent: RuntimeAgentRecord, threadId: string, checkpointDir: string): AgentMemoryPathProjection {
  return {
    schemaVersion: "ioi.agent-runtime.memory.v1",
    object: "ioi.agent_memory_path_projection",
    threadId,
    agentId: agent.id,
    workspace: agent.cwd,
    recordsPath: path.join(checkpointDir, "memory"),
    policiesPath: path.join(checkpointDir, "memory-policies"),
    effectivePolicyId: mockMemoryPolicyId("thread", threadId),
  };
}

function mockMemoryPolicyId(targetType: string, targetId: string): string {
  return `memory_policy_${targetType}_${safeFileName(targetId)}`;
}

function safeFileName(value: string): string {
  return String(value).replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

function threadIdForAgent(agentId: string): string {
  return agentId.startsWith("agent_") ? `thread_${agentId.slice("agent_".length)}` : `thread_${agentId}`;
}

function buildMockRun(
  agent: RuntimeAgentRecord,
  prompt: string,
  mode: RuntimeRunRecord["mode"],
  options: SendOptions,
  memory: MockRunMemory = { command: "none", records: [], writes: [] },
): RuntimeRunRecord {
  const runId = `run_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const taskFamily = taskFamilyForMode(mode);
  const selectedStrategy = strategyForMode(mode);
  const toolSequence = capabilitySequenceForMode(mode, agent);
  const modelRouteDecision = mockModelRouteDecision(
    options.model,
    options.model?.id ?? agent.requestedModelId ?? agent.modelId,
    agent.modelRouteDecision ?? undefined,
  );
  const modelRouteReceiptId = `receipt_${runId}_model_route`;
  const selectedModel = modelRouteDecision.selectedModel ?? options.model?.id ?? agent.modelId;
  const inlineMcpServerNames = Object.keys(options.mcpServers ?? {});
  const memoryRecords = memory.records;
  const memoryMutations = memory.mutations ?? memory.writes.map((write) => ({ ...write, operation: "write" as const }));
  const memoryWrites = memory.writes.map((write) => write.record);
  const memoryWriteReceipts = memoryMutations.map((write) => write.receipt);
  const memoryPolicy = memory.policy ?? null;
  const subagentMemoryInheritance =
    mode === "handoff" ? memory.subagentMemoryInheritance ?? null : null;
  const subagentMemoryReceipt = subagentMemoryInheritance
    ? subagentMemoryInheritanceReceiptForRun(runId, subagentMemoryInheritance)
    : null;
  const taskState: TaskStateProjection = {
    currentObjective: prompt,
    knownFacts: [
      "SDK run entered through the explicit mock RuntimeSubstrateClient",
      "Authority and trace export are required by the IOI runtime contract",
      `Selected model profile: ${selectedModel}`,
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
      ...memoryRecords.map((record) => `Memory fact (${record.scope}:${record.id}): ${record.fact}`),
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: ["Mock SDK execution writes non-authoritative checkpoint projections"],
    constraints: ["No GUI internals", "No raw receipt dump", "No policy bypass"],
    blockers: [],
    changedObjects: mode === "send" ? [] : [`sdk:${mode}`],
    evidenceRefs: [
      "runtime_substrate_client",
      "agent_sdk_mock_checkpoint",
      ...inlineMcpServerNames,
      ...modelRouteDecision.evidenceRefs,
      modelRouteReceiptId,
      memoryPolicy?.id,
      ...memoryRecords.map((record) => record.id),
      ...memoryWriteReceipts.map((receipt) => receipt.id),
      subagentMemoryReceipt?.id,
    ].filter((value): value is string => Boolean(value)),
  };
  const uncertainty: UncertaintyProjection = {
    ambiguityLevel: mode === "send" ? "low" : "medium",
    selectedAction:
      mode === "dry_run"
        ? "dry_run"
        : mode === "plan"
          ? "verify"
          : mode === "handoff"
            ? "execute"
            : "probe",
    rationale: "Explicit SDK mock runs choose a bounded substrate projection before terminal output.",
    valueOfProbe: mode === "send" ? "medium" : "high",
  };
  const probes: ProbeProjection[] = [
    {
      probeId: `${runId}:probe:substrate`,
      hypothesis: "The explicit SDK mock path can preserve substrate events, trace, receipts, and scorecard.",
      cheapestValidationAction: "Inspect generated local checkpoint and replay event cursor.",
      expectedObservation: "Monotonic event stream with terminal event and trace bundle.",
      result: "confirmed",
      confidenceUpdate: "SDK mock substrate projection is replayable for this run.",
    },
  ];
  const postconditions: PostconditionProjection = {
    objective: prompt,
    taskFamily,
    riskClass: mode === "dry_run" ? "side_effect_preview" : "bounded_local",
    checks: [
      {
        checkId: "event-stream-terminal",
        description: "Event stream contains exactly one terminal event.",
        status: "passed",
      },
      {
        checkId: "trace-export",
        description: "Trace bundle is exportable and replay-compatible.",
        status: "passed",
      },
      {
        checkId: "quality-ledger",
        description: "Quality ledger and stop condition are attached.",
        status: "passed",
      },
    ],
    minimumEvidence: ["events", "receipts", "trace", "scorecard"],
  };
  const semanticImpact: SemanticImpactProjection = {
    changedSymbols: [],
    changedApis: mode === "learn" ? ["agent.learn"] : [],
    changedSchemas: [
      "IOISDKMessage",
      "RuntimeTraceBundle",
      "ModelRouteDecision",
      "AgentMemoryPolicy",
      "SubagentMemoryInheritanceProjection",
    ],
    changedPolicies: [
      ...(mode === "dry_run" ? ["authority.preview_only"] : []),
      ...(memory.policyBlockReason ? [`memory.${memory.policyBlockReason}`] : []),
      ...(memory.policyUpdates?.map(() => "memory.policy") ?? []),
      ...(subagentMemoryInheritance
        ? [`memory.subagent_inheritance.${subagentMemoryInheritance.mode}`]
        : []),
    ],
    affectedTests: ["cursor-sdk-parity-contract"],
    affectedDocs: ["cursor-sdk-harness-parity-plus-master-guide.md"],
    riskClass: postconditions.riskClass,
  };
  const stopCondition: StopConditionProjection = {
    reason: "evidence_sufficient",
    evidenceSufficient: true,
    rationale: "Required SDK trace, replay, postcondition, and scorecard evidence were produced.",
  };
  const qualityLedger: AgentQualityLedgerProjection = {
    ledgerId: `quality_${runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence,
    scorecardMetrics: {
      task_pass_rate: 100,
      recovery_success: 100,
      memory_relevance: mode === "learn" ? 100 : 90,
      tool_quality: 95,
      strategy_roi: 90,
      operator_interventions: 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: [],
  };
  const scorecard: RuntimeScorecard = {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: mode === "learn" ? 1 : 0.9,
    toolQuality: 0.95,
    strategyRoi: 0.9,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
  const receipts: RuntimeReceipt[] = [
    {
      id: modelRouteReceiptId,
      kind: "model_route_selection",
      summary: `Route ${modelRouteDecision.routeId} selected ${modelRouteDecision.selectedModel}.`,
      redaction: "none",
      evidenceRefs: modelRouteDecision.evidenceRefs,
    },
    ...(subagentMemoryReceipt ? [subagentMemoryReceipt] : []),
    ...memoryWriteReceipts,
    {
      id: `receipt_${runId}_authority`,
      kind: "authority_decision",
      summary: "SDK mock action used an explicit non-authoritative runtime substrate projection.",
      redaction: "none",
      evidenceRefs: ["RuntimeSubstratePortContract"],
    },
    {
      id: `receipt_${runId}_trace`,
      kind: "trace_export",
      summary: "Trace export was generated from the explicit SDK mock runtime projection.",
      redaction: "redacted",
      evidenceRefs: ["RuntimeTraceBundle"],
    },
  ];
  const result = resultForMode(mode, agent, prompt, memory);
  const events: IOISDKMessage[] = [];
  const addEvent = (type: IOISDKMessage["type"], summary: string, data?: unknown): IOISDKMessage => {
    const event = makeEvent(runId, agent.id, events.length, type, summary, data);
    events.push(event);
    return event;
  };
  const startedEvent = addEvent("run_started", "Run entered IOI SDK substrate", {
    taskFamily,
    selectedStrategy,
  });
  addEvent("model_route_decision", "Model route decision recorded", {
    ...modelRouteDecision,
    receiptId: modelRouteReceiptId,
  });
  for (const mutation of memoryMutations) {
    addEvent("memory_update", mockMemoryEventSummary(mutation.operation), {
      ...(("record" in mutation ? mutation.record : mutation.policy) ?? {}),
      operation: mutation.operation,
      eventKind: mockMemoryEventKind(mutation.operation),
      receiptId: mutation.receipt.id,
    });
  }
  if (subagentMemoryInheritance) {
    addEvent("memory_update", "Subagent memory inheritance resolved", {
      ...subagentMemoryInheritance,
      operation: "subagent_inheritance",
      eventKind: "SubagentMemoryInheritance",
      receiptId: subagentMemoryReceipt?.id ?? null,
    });
  }
  addEvent("task_state", "Task state projected", taskState);
  addEvent("uncertainty", "Uncertainty assessed", uncertainty);
  addEvent("probe", "Probe completed", probes[0]);
  addEvent("postcondition_synthesized", "Postconditions synthesized", postconditions);
  addEvent("semantic_impact", "Semantic impact classified", semanticImpact);
  const deltaEvent = addEvent("delta", result, { text: result });
  addEvent("stop_condition", "Stop condition recorded", stopCondition);
  addEvent("quality_ledger", "Quality ledger recorded", qualityLedger);
  addEvent("completed", "Run completed", { stopReason: stopCondition.reason });
  const trace: RuntimeTraceBundle = {
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
    memoryPolicy,
    memoryRecords,
    memoryWrites,
    subagentMemoryInheritance,
    stopCondition,
    qualityLedger,
    scorecard,
  };
  const artifacts: RuntimeArtifact[] = [
    {
      id: `artifact_${runId}_trace`,
      runId,
      name: "trace.json",
      mediaType: "application/json",
      redaction: "redacted",
      receiptId: receipts[receipts.length - 1]?.id ?? modelRouteReceiptId,
      content: JSON.stringify(trace, null, 2),
    },
    {
      id: `artifact_${runId}_scorecard`,
      runId,
      name: "scorecard.json",
      mediaType: "application/json",
      redaction: "none",
      receiptId: receipts[receipts.length - 1]?.id ?? modelRouteReceiptId,
      content: JSON.stringify(scorecard, null, 2),
    },
  ];
  return {
    id: runId,
    agentId: agent.id,
    status: "completed",
    objective: prompt,
    mode,
    createdAt,
    updatedAt: createdAt,
    events,
    conversation: [
      { role: "user", content: prompt, eventId: startedEvent.id, createdAt },
      { role: "assistant", content: result, eventId: deltaEvent.id, createdAt },
    ],
    receipts,
    artifacts,
    trace,
    modelRouteDecision,
    modelRouteReceiptId,
    memoryPolicy,
    memoryRecords,
    memoryWriteReceipts,
    subagentMemoryInheritance,
    result,
  };
}

function resultForMode(
  mode: RuntimeRunRecord["mode"],
  agent: RuntimeAgentRecord,
  prompt: string,
  memory: MockRunMemory = { command: "none", records: [], writes: [] },
): string {
  if (memory.command === "disable") {
    return "Memory is disabled for this thread.";
  }
  if (memory.command === "enable") {
    return "Memory is enabled for this thread.";
  }
  if (memory.command === "path") {
    return `Memory records path: ${memory.paths?.recordsPath ?? "unknown"}\nMemory policy path: ${memory.paths?.policiesPath ?? "unknown"}`;
  }
  if (memory.policyBlockReason) {
    return `Memory write blocked by policy: ${memory.policyBlockReason}.`;
  }
  if (memory.command === "edit") {
    const edited = memory.mutations?.find((mutation) => mutation.operation === "edit" && "record" in mutation);
    return edited && "record" in edited ? `Edited memory: ${edited.record.id}` : "No memory was edited.";
  }
  if (memory.command === "delete") {
    const deleted = memory.mutations?.find((mutation) => mutation.operation === "delete" && "record" in mutation);
    return deleted && "record" in deleted ? `Deleted memory: ${deleted.record.id}` : "No memory was deleted.";
  }
  if (memory.disabled && (memory.command === "remember" || memory.command === "show")) {
    return "Memory is disabled for this run.";
  }
  if (memory.command === "remember") {
    return memory.writes.length > 0
      ? `Remembered: ${memory.writes.map((write) => write.record.fact).join("; ")}`
      : "No memory was written because the remember request was empty.";
  }
  if (memory.command === "show") {
    return memory.records.length > 0
      ? `Memory:\n${memory.records.map((record) => `- ${record.fact}`).join("\n")}`
      : "Memory is empty for this thread.";
  }
  switch (mode) {
    case "plan":
      return `Plan-only SDK run recorded objective, constraints, postconditions, and stop reason for: ${prompt}`;
    case "dry_run":
      return "Dry run completed. Side effects were previewed and no tool mutation was executed.";
    case "handoff":
      return "Handoff bundle is complete: objective, state, blockers, evidence, and next action are preserved.";
    case "learn":
      return "Governed learning record created behind memory quality and bounded self-improvement gates.";
    case "send":
      return `IOI SDK mock run completed for ${agent.cwd}. This is a non-authoritative projection; trace, receipts, task state, uncertainty, probe, postconditions, semantic impact, stop condition, and scorecard are available through run.inspect(), run.trace(), and run.scorecard().`;
  }
}

function taskFamilyForMode(mode: RuntimeRunRecord["mode"]): string {
  switch (mode) {
    case "plan":
      return "planning";
    case "dry_run":
      return "safety_preview";
    case "handoff":
      return "delegation";
    case "learn":
      return "learning";
    case "send":
      return "mock_sdk_projection";
  }
}

function strategyForMode(mode: RuntimeRunRecord["mode"]): string {
  switch (mode) {
    case "plan":
      return "plan_only_with_postconditions";
    case "dry_run":
      return "dry_run_before_effect";
    case "handoff":
      return "handoff_with_state_preservation";
    case "learn":
      return "bounded_learning_gate";
    case "send":
      return "explicit_mock_substrate_projection";
  }
}

function capabilitySequenceForMode(mode: RuntimeRunRecord["mode"], agent: RuntimeAgentRecord): string[] {
  const base = ["authority_check", "task_state_projection", "trace_export"];
  if (agent.options.mcpServerNames.length > 0) {
    base.push("mcp_containment");
  }
  if (agent.options.skillNames.length > 0) {
    base.push("skill_instruction_import");
  }
  if (agent.options.hookNames.length > 0) {
    base.push("runtime_event_hook");
  }
  if (mode === "dry_run") {
    base.push("side_effect_preview");
  }
  if (mode === "handoff") {
    base.push("handoff_quality");
  }
  if (mode === "learn") {
    base.push("memory_quality_gate");
  }
  return base;
}

function makeEvent(
  runId: string,
  agentId: string,
  index: number,
  type: IOISDKMessage["type"],
  summary: string,
  data?: unknown,
): IOISDKMessage {
  return {
    id: `${runId}:event:${String(index).padStart(3, "0")}:${type}`,
    runId,
    agentId,
    type,
    cursor: `${runId}:${index}`,
    createdAt: new Date().toISOString(),
    summary,
    data,
  };
}

async function emitCallbacks(run: RuntimeRunRecord, options: SendOptions): Promise<void> {
  for (const event of run.events) {
    if (event.type === "delta") {
      const text =
        event.data && typeof event.data === "object" && "text" in event.data
          ? String(event.data.text)
          : event.summary;
      await options.onDelta?.(text);
    }
    await options.onStep?.(event);
  }
}

function writeJson(filePath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}
