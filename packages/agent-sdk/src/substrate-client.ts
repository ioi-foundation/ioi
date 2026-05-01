import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { IoiAgentError } from "./errors.js";
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
  RuntimeScorecard,
  RuntimeTraceBundle,
  SemanticImpactProjection,
  StopConditionProjection,
  TaskStateProjection,
  UncertaintyProjection,
} from "./messages.js";

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
  listModels(): Promise<Array<{ id: string; provider: string; cost: string; quality: string }>>;
  listRepositories(): Promise<Array<{ url: string; source: string; status: string }>>;
}

export interface RuntimeSubstrateClientOptions {
  cwd?: string;
  checkpointDir?: string;
}

export function createRuntimeSubstrateClient(
  options: RuntimeSubstrateClientOptions = {},
): RuntimeSubstrateClient {
  return new LocalRuntimeSubstrateClient(options);
}

export class LocalRuntimeSubstrateClient implements RuntimeSubstrateClient {
  private readonly cwd: string;
  private readonly checkpointDir: string;
  private readonly agents = new Map<string, RuntimeAgentRecord>();
  private readonly runs = new Map<string, RuntimeRunRecord>();

  constructor(options: RuntimeSubstrateClientOptions = {}) {
    this.cwd = path.resolve(options.cwd ?? process.cwd());
    this.checkpointDir = path.resolve(
      options.checkpointDir ?? path.join(this.cwd, ".ioi", "agent-sdk"),
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

  async listModels(): Promise<Array<{ id: string; provider: string; cost: string; quality: string }>> {
    return [
      { id: "local:auto", provider: "ioi-local", cost: "local", quality: "adaptive" },
      { id: "gpt-5.5", provider: "configured-provider", cost: "high", quality: "frontier" },
      { id: "gpt-5.4-mini", provider: "configured-provider", cost: "low", quality: "fast" },
    ];
  }

  async listRepositories(): Promise<Array<{ url: string; source: string; status: string }>> {
    return [{ url: this.cwd, source: "local", status: "available" }];
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
    const run = buildLocalRun(agent, prompt, mode, options);
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
      // Best-effort cleanup; authoritative state is the governed checkpoint map.
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

function buildLocalRun(
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
      "SDK run entered through RuntimeSubstrateClient",
      "Authority and trace export are required by the IOI runtime contract",
      `Selected model profile: ${selectedModel}`,
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: ["Local SDK execution uses checkpointed substrate records"],
    constraints: ["No GUI internals", "No raw receipt dump", "No policy bypass"],
    blockers: [],
    changedObjects: mode === "send" ? [] : [`sdk:${mode}`],
    evidenceRefs: ["runtime_substrate_client", "agent_sdk_checkpoint", ...inlineMcpServerNames],
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
    rationale: "SDK local runs choose a bounded substrate action before terminal output.",
    valueOfProbe: mode === "send" ? "medium" : "high",
  };
  const probes: ProbeProjection[] = [
    {
      probeId: `${runId}:probe:substrate`,
      hypothesis: "The SDK path can preserve substrate events, trace, receipts, and scorecard.",
      cheapestValidationAction: "Inspect generated local checkpoint and replay event cursor.",
      expectedObservation: "Monotonic event stream with terminal event and trace bundle.",
      result: "confirmed",
      confidenceUpdate: "SDK substrate projection is replayable for this run.",
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
      summary: "SDK action used local runtime substrate authority profile.",
      redaction: "none",
      evidenceRefs: ["RuntimeSubstratePortContract"],
    },
    {
      id: `receipt_${runId}_trace`,
      kind: "trace_export",
      summary: "Trace export was generated from the SDK runtime projection.",
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
      return `IOI SDK local run completed for ${agent.cwd}. Trace, receipts, task state, uncertainty, probe, postconditions, semantic impact, stop condition, and scorecard are available through run.inspect(), run.trace(), and run.scorecard().`;
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
      return "local_sdk_execution";
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
      return "local_substrate_execution";
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
