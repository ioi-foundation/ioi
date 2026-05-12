import type { AgentOptions, SendOptions, StreamOptions } from "./options.js";
import {
  createRuntimeSubstrateClient,
  type RuntimeEventStreamOptions,
  type RuntimeSubstrateClient,
  type RuntimeThreadCompactInput,
  type RuntimeThreadCreateInput,
  type RuntimeThreadForkInput,
  type RuntimeTurnCreateInput,
  type RuntimeTurnInterruptInput,
  type RuntimeTurnSteerInput,
} from "./substrate-client.js";
import type { RuntimeThreadEvent, RuntimeThreadRecord, RuntimeTurnRecord } from "./messages.js";

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
