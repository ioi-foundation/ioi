import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { IoiAgentError, type IoiAgentErrorCode } from "./errors.js";
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
  AgentQualityLedgerProjection,
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  PostconditionProjection,
  ProbeProjection,
  RuntimeReceipt,
  RuntimeAccountProfile,
  RuntimeNodeProfile,
  RuntimeScorecard,
  RuntimeToolCatalogEntry,
  RuntimeTraceBundle,
  SemanticImpactProjection,
  StopConditionProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";
import type { RuntimeModelCatalogEntry } from "./model-mounts.js";

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
  result: string;
}

export interface RuntimeSubstrateClient {
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
    method: "GET" | "POST" | "DELETE",
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

function eventsFromResponse(value: IOISDKMessage[] | { events: IOISDKMessage[] }): IOISDKMessage[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && Array.isArray(value.events)) {
    return value.events;
  }
  throw new IoiAgentError({
    code: "runtime",
    message: "IOI daemon event endpoint returned an invalid event stream projection.",
    details: { value },
  });
}

function parseServerSentEvents(text: string): IOISDKMessage[] {
  const events: IOISDKMessage[] = [];
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
    if (!isSdkMessage(parsed)) {
      throw new IoiAgentError({
        code: "runtime",
        message: "IOI daemon SSE stream yielded an invalid SDK event.",
        details: { data: data.slice(0, 240) },
      });
    }
    events.push(parsed);
  }
  return events;
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

  constructor(options: RuntimeSubstrateClientOptions = {}) {
    this.cwd = path.resolve(options.cwd ?? process.cwd());
    this.checkpointDir = path.resolve(
      options.checkpointDir ?? path.join(this.cwd, ".ioi", "agent-sdk-mock"),
    );
    this.loadCheckpoints();
  }

  async createAgent(options: AgentOptions): Promise<RuntimeAgentRecord> {
    const runtime = runtimeModeForOptions(options);
    ensureProviderConfigured(runtime, options);
    const cwd = path.resolve(options.local?.cwd ?? this.cwd);
    const agent: RuntimeAgentRecord = {
      id: `agent_${crypto.randomUUID()}`,
      status: "active",
      runtime,
      cwd,
      modelId: options.model?.id ?? "local:auto",
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
    const run = buildMockRun(agent, prompt, mode, options);
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

function buildMockRun(
  agent: RuntimeAgentRecord,
  prompt: string,
  mode: RuntimeRunRecord["mode"],
  options: SendOptions,
): RuntimeRunRecord {
  const runId = `run_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const taskFamily = taskFamilyForMode(mode);
  const selectedStrategy = strategyForMode(mode);
  const toolSequence = capabilitySequenceForMode(mode, agent);
  const selectedModel = options.model?.id ?? agent.modelId;
  const inlineMcpServerNames = Object.keys(options.mcpServers ?? {});
  const taskState: TaskStateProjection = {
    currentObjective: prompt,
    knownFacts: [
      "SDK run entered through the explicit mock RuntimeSubstrateClient",
      "Authority and trace export are required by the IOI runtime contract",
      `Selected model profile: ${selectedModel}`,
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: ["Mock SDK execution writes non-authoritative checkpoint projections"],
    constraints: ["No GUI internals", "No raw receipt dump", "No policy bypass"],
    blockers: [],
    changedObjects: mode === "send" ? [] : [`sdk:${mode}`],
    evidenceRefs: ["runtime_substrate_client", "agent_sdk_mock_checkpoint", ...inlineMcpServerNames],
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
    changedSchemas: ["IOISDKMessage", "RuntimeTraceBundle"],
    changedPolicies: mode === "dry_run" ? ["authority.preview_only"] : [],
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
  const result = resultForMode(mode, agent, prompt);
  const events = [
    makeEvent(runId, agent.id, 0, "run_started", "Run entered IOI SDK substrate", {
      taskFamily,
      selectedStrategy,
    }),
    makeEvent(runId, agent.id, 1, "task_state", "Task state projected", taskState),
    makeEvent(runId, agent.id, 2, "uncertainty", "Uncertainty assessed", uncertainty),
    makeEvent(runId, agent.id, 3, "probe", "Probe completed", probes[0]),
    makeEvent(
      runId,
      agent.id,
      4,
      "postcondition_synthesized",
      "Postconditions synthesized",
      postconditions,
    ),
    makeEvent(runId, agent.id, 5, "semantic_impact", "Semantic impact classified", semanticImpact),
    makeEvent(runId, agent.id, 6, "delta", result, { text: result }),
    makeEvent(runId, agent.id, 7, "stop_condition", "Stop condition recorded", stopCondition),
    makeEvent(runId, agent.id, 8, "quality_ledger", "Quality ledger recorded", qualityLedger),
    makeEvent(runId, agent.id, 9, "completed", "Run completed", { stopReason: stopCondition.reason }),
  ];
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
      receiptId: receipts[1].id,
      content: JSON.stringify(trace, null, 2),
    },
    {
      id: `artifact_${runId}_scorecard`,
      runId,
      name: "scorecard.json",
      mediaType: "application/json",
      redaction: "none",
      receiptId: receipts[1].id,
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
      { role: "user", content: prompt, eventId: events[0].id, createdAt },
      { role: "assistant", content: result, eventId: events[6].id, createdAt },
    ],
    receipts,
    artifacts,
    trace,
    result,
  };
}

function resultForMode(mode: RuntimeRunRecord["mode"], agent: RuntimeAgentRecord, prompt: string): string {
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
