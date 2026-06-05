import type { AgentOptions, SendOptions, StreamOptions } from "./options.js";
import {
  createRuntimeSubstrateClient,
  type RuntimeEventStreamOptions,
  type RuntimeSubstrateClient,
  type RuntimeThreadCompactInput,
  type RuntimeThreadCreateInput,
  type RuntimeThreadForkInput,
  type RuntimeThreadMemoryDeleteInput,
  type RuntimeThreadMemoryEditInput,
  type RuntimeThreadMemoryInput,
  type RuntimeThreadMemoryWriteInput,
  type RuntimeThreadMcpInput,
  type RuntimeMcpJsonRpcRequest,
  type RuntimeMcpJsonRpcResponse,
  type RuntimeMcpServerMutationInput,
  type RuntimeMcpToolInvokeInput,
  type RuntimeMcpToolSearchInput,
  type RuntimeSubagentAssignInput,
  type RuntimeSubagentCancelInput,
  type RuntimeSubagentCancellationPropagationInput,
  type RuntimeSubagentCancellationPropagationResult,
  type RuntimeSubagentListInput,
  type RuntimeSubagentListResult,
  type RuntimeSubagentRecord,
  type RuntimeSubagentResumeInput,
  type RuntimeSubagentResult,
  type RuntimeSubagentSendInput,
  type RuntimeSubagentSpawnInput,
  type RuntimeSubagentWaitInput,
  type RuntimeThreadModeInput,
  type RuntimeThreadModelInput,
  type RuntimeThreadThinkingInput,
  type RuntimeTurnCreateInput,
  type RuntimeTurnInterruptInput,
  type RuntimeTurnSteerInput,
  type RememberMemoryResult,
} from "./substrate-client.js";
import type {
  RuntimeMemoryStatus,
  RuntimeMemoryValidationResult,
  RuntimeMcpStatus,
  RuntimeMcpInvocationResult,
  RuntimeMcpToolSearchResult,
  RuntimeMcpValidationResult,
  RuntimeThreadEvent,
  RuntimeThreadRecord,
  RuntimeTurnRecord,
} from "./messages.js";

let defaultThreadClient: RuntimeSubstrateClient | undefined;

export interface ThreadCreateOptions extends AgentOptions {
  request?: Omit<RuntimeThreadCreateInput, "options">;
  runtimeProfile?: string;
  goal?: string;
  maxSteps?: number;
}

function clientForThreadOptions(options?: AgentOptions): RuntimeSubstrateClient {
  if (options?.substrateClient) {
    return options.substrateClient;
  }
  defaultThreadClient ??= createRuntimeSubstrateClient({
    cwd: options?.local?.cwd,
    checkpointDir: options?.local?.checkpointDir,
  });
  return defaultThreadClient;
}

function threadCreateInput(options: ThreadCreateOptions): RuntimeThreadCreateInput {
  const {
    substrateClient: _substrateClient,
    request,
    runtimeProfile,
    goal,
    maxSteps,
    ...agentOptions
  } = options;
  return {
    ...(request ?? {}),
    ...(runtimeProfile ? { runtime_profile: runtimeProfile } : {}),
    ...(goal ? { goal } : {}),
    ...(maxSteps !== undefined ? { max_steps: maxSteps } : {}),
    options: agentOptions,
  };
}

export class Thread {
  readonly id: string;
  readonly agentId: string;
  readonly eventStreamId: string;
  readonly record: RuntimeThreadRecord;
  private readonly client: RuntimeSubstrateClient;

  constructor(client: RuntimeSubstrateClient, record: RuntimeThreadRecord) {
    this.client = client;
    this.record = record;
    this.id = record.thread_id;
    this.agentId = record.agent_id;
    this.eventStreamId = record.event_stream_id;
  }

  static async create(options: ThreadCreateOptions = {}): Promise<Thread> {
    const client = clientForThreadOptions(options);
    return new Thread(client, await client.createThread(threadCreateInput(options)));
  }

  static async open(threadId: string, options: AgentOptions = {}): Promise<Thread> {
    const client = clientForThreadOptions(options);
    return new Thread(client, await client.getThread(threadId));
  }

  static async list(options: AgentOptions = {}): Promise<Thread[]> {
    const client = clientForThreadOptions(options);
    return (await client.listThreads()).map((thread) => new Thread(client, thread));
  }

  async refresh(): Promise<Thread> {
    return new Thread(this.client, await this.client.getThread(this.id));
  }

  async resume(): Promise<Thread> {
    return new Thread(this.client, await this.client.resumeThread(this.id));
  }

  async fork(input: RuntimeThreadForkInput = {}): Promise<Thread> {
    return new Thread(this.client, await this.client.forkThread(this.id, input));
  }

  async compact(input: RuntimeThreadCompactInput = {}): Promise<Thread> {
    return new Thread(this.client, await this.client.compactThread(this.id, input));
  }

  async mode(input: RuntimeThreadModeInput): Promise<Thread> {
    return new Thread(this.client, await this.client.updateThreadMode(this.id, input));
  }

  async model(input: RuntimeThreadModelInput): Promise<Thread> {
    return new Thread(this.client, await this.client.updateThreadModel(this.id, input));
  }

  async thinking(input: RuntimeThreadThinkingInput): Promise<Thread> {
    return new Thread(this.client, await this.client.updateThreadThinking(this.id, input));
  }

  async listSubagents(input: RuntimeSubagentListInput = {}): Promise<RuntimeSubagentListResult> {
    return this.client.listSubagents(this.id, input);
  }

  async spawnSubagent(input: RuntimeSubagentSpawnInput): Promise<RuntimeSubagentRecord> {
    return this.client.spawnSubagent(this.id, input);
  }

  async waitSubagent(
    subagentId: string,
    input: RuntimeSubagentWaitInput = {},
  ): Promise<RuntimeSubagentResult> {
    return this.client.waitSubagent(this.id, subagentId, input);
  }

  async getSubagentResult(subagentId: string): Promise<RuntimeSubagentResult> {
    return this.client.getSubagentResult(this.id, subagentId);
  }

  async sendSubagentInput(
    subagentId: string,
    input: RuntimeSubagentSendInput,
  ): Promise<RuntimeSubagentRecord> {
    return this.client.sendSubagentInput(this.id, subagentId, input);
  }

  async cancelSubagent(
    subagentId: string,
    input: RuntimeSubagentCancelInput = {},
  ): Promise<RuntimeSubagentResult> {
    return this.client.cancelSubagent(this.id, subagentId, input);
  }

  async resumeSubagent(
    subagentId: string,
    input: RuntimeSubagentResumeInput = {},
  ): Promise<RuntimeSubagentResult> {
    return this.client.resumeSubagent(this.id, subagentId, input);
  }

  async assignSubagent(
    subagentId: string,
    input: RuntimeSubagentAssignInput = {},
  ): Promise<RuntimeSubagentRecord> {
    return this.client.assignSubagent(this.id, subagentId, input);
  }

  async propagateSubagentCancellation(
    input: RuntimeSubagentCancellationPropagationInput = {},
  ): Promise<RuntimeSubagentCancellationPropagationResult> {
    return this.client.propagateSubagentCancellation(this.id, input);
  }

  async mcp(input: RuntimeThreadMcpInput = {}): Promise<RuntimeMcpStatus> {
    return this.client.threadMcpStatus(this.id, input);
  }

  async validateMcp(input: RuntimeThreadMcpInput = {}): Promise<RuntimeMcpValidationResult> {
    return this.client.validateThreadMcp(this.id, input);
  }

  async searchMcpTools(input: RuntimeMcpToolSearchInput = {}): Promise<RuntimeMcpToolSearchResult> {
    return this.client.searchThreadMcpTools(this.id, input);
  }

  async getMcpTool(
    toolId: string,
    input: RuntimeMcpToolSearchInput = {},
  ): Promise<RuntimeMcpToolSearchResult> {
    return this.client.getThreadMcpTool(this.id, toolId, input);
  }

  async importMcp(input: RuntimeMcpServerMutationInput = {}): Promise<RuntimeMcpStatus> {
    return this.client.importThreadMcp(this.id, input);
  }

  async addMcpServer(input: RuntimeMcpServerMutationInput = {}): Promise<RuntimeMcpStatus> {
    return this.client.addThreadMcpServer(this.id, input);
  }

  async removeMcpServer(
    serverId: string,
    input: RuntimeMcpServerMutationInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.client.removeThreadMcpServer(this.id, serverId, input);
  }

  async enableMcpServer(
    serverId: string,
    input: RuntimeThreadMcpInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.client.enableThreadMcpServer(this.id, serverId, input);
  }

  async disableMcpServer(
    serverId: string,
    input: RuntimeThreadMcpInput = {},
  ): Promise<RuntimeMcpStatus> {
    return this.client.disableThreadMcpServer(this.id, serverId, input);
  }

  async invokeMcpTool(input: RuntimeMcpToolInvokeInput = {}): Promise<RuntimeMcpInvocationResult> {
    return this.client.invokeThreadMcpTool(this.id, input);
  }

  async mcpServeRpc(
    message: RuntimeMcpJsonRpcRequest | RuntimeMcpJsonRpcRequest[],
    options: RuntimeThreadMcpInput = {},
  ): Promise<RuntimeMcpJsonRpcResponse | RuntimeMcpJsonRpcResponse[] | null> {
    return this.client.threadMcpServeRpc(this.id, message, options);
  }

  async memory(input: RuntimeThreadMemoryInput = {}): Promise<RuntimeMemoryStatus> {
    return this.client.threadMemoryStatus(this.id, input);
  }

  async validateMemory(input: RuntimeThreadMemoryInput = {}): Promise<RuntimeMemoryValidationResult> {
    return this.client.validateThreadMemory(this.id, input);
  }

  async rememberMemory(input: RuntimeThreadMemoryWriteInput): Promise<RememberMemoryResult> {
    return this.client.rememberThreadMemory(this.id, input);
  }

  async updateMemory(
    memoryId: string,
    input: RuntimeThreadMemoryEditInput,
  ): Promise<RememberMemoryResult> {
    return this.client.updateThreadMemory(this.id, memoryId, input);
  }

  async deleteMemory(
    memoryId: string,
    input: RuntimeThreadMemoryDeleteInput = {},
  ): Promise<RememberMemoryResult> {
    return this.client.deleteThreadMemory(this.id, memoryId, input);
  }

  async submit(input: RuntimeTurnCreateInput): Promise<Turn> {
    return new Turn(this.client, await this.client.submitTurn(this.id, input));
  }

  async send(prompt: string, options: SendOptions = {}): Promise<Turn> {
    return this.submit({ prompt, options });
  }

  async turns(): Promise<Turn[]> {
    return (await this.client.listTurns(this.id)).map((turn) => new Turn(this.client, turn));
  }

  async turn(turnId: string): Promise<Turn> {
    return new Turn(this.client, await this.client.getTurn(this.id, turnId));
  }

  async *events(options: RuntimeEventStreamOptions = {}): AsyncIterable<RuntimeThreadEvent> {
    for await (const event of this.client.streamThreadEvents(this.id, options)) {
      options.signal?.throwIfAborted();
      yield event;
    }
  }
}

export class Turn {
  readonly id: string;
  readonly threadId: string;
  readonly runId: string;
  readonly status: RuntimeTurnRecord["status"];
  readonly record: RuntimeTurnRecord;
  private readonly client: RuntimeSubstrateClient;

  constructor(client: RuntimeSubstrateClient, record: RuntimeTurnRecord) {
    this.client = client;
    this.record = record;
    this.id = record.turn_id;
    this.threadId = record.thread_id;
    this.runId = record.request_id;
    this.status = record.status;
  }

  async refresh(): Promise<Turn> {
    return new Turn(this.client, await this.client.getTurn(this.threadId, this.id));
  }

  async interrupt(input: RuntimeTurnInterruptInput = {}): Promise<Turn> {
    return new Turn(this.client, await this.client.interruptTurn(this.threadId, this.id, input));
  }

  async steer(input: RuntimeTurnSteerInput = {}): Promise<Turn> {
    return new Turn(this.client, await this.client.steerTurn(this.threadId, this.id, input));
  }

  async *events(options: RuntimeEventStreamOptions = {}): AsyncIterable<RuntimeThreadEvent> {
    const sinceSeq = options.sinceSeq ?? Math.max(0, (this.record.seq_start ?? 1) - 1);
    for await (const event of this.client.streamThreadEvents(this.threadId, { ...options, sinceSeq })) {
      options.signal?.throwIfAborted();
      if (event.turnId === this.id) {
        yield event;
      }
    }
  }

  stream(options: StreamOptions = {}): AsyncIterable<RuntimeThreadEvent> {
    return this.events({
      lastEventId: options.lastEventId,
      signal: options.signal,
    });
  }
}
