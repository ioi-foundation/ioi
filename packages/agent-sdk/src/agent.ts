import { IoiAgentError } from "./errors.js";
import type { IOIRunResult } from "./messages.js";
import type {
  AgentOptions,
  DryRunOptions,
  HandoffOptions,
  LearnOptions,
  PlanOptions,
  SendOptions,
} from "./options.js";
import { Run } from "./run.js";
import {
  createRuntimeSubstrateClient,
  type RuntimeAgentRecord,
  type RuntimeSubstrateClient,
} from "./substrate-client.js";

let defaultClient: RuntimeSubstrateClient | undefined;

function clientForOptions(options?: AgentOptions): RuntimeSubstrateClient {
  if (options?.substrateClient) {
    return options.substrateClient;
  }
  defaultClient ??= createRuntimeSubstrateClient({
    cwd: options?.local?.cwd,
    checkpointDir: options?.local?.checkpointDir,
  });
  return defaultClient;
}

export class Agent {
  readonly id: string;
  readonly runtime: string;
  readonly cwd: string;
  private readonly client: RuntimeSubstrateClient;

  private constructor(client: RuntimeSubstrateClient, record: RuntimeAgentRecord) {
    this.client = client;
    this.id = record.id;
    this.runtime = record.runtime;
    this.cwd = record.cwd;
  }

  static async create(options: AgentOptions = {}): Promise<Agent> {
    const client = clientForOptions(options);
    return new Agent(client, await client.createAgent(options));
  }

  static async resume(agentId: string, options: AgentOptions = {}): Promise<Agent> {
    const client = clientForOptions(options);
    return new Agent(client, await client.resumeAgent(agentId));
  }

  static async prompt(prompt: string, options: AgentOptions = {}): Promise<IOIRunResult> {
    const agent = await Agent.create(options);
    return (await agent.send(prompt)).wait();
  }

  static async list(options: AgentOptions = {}): Promise<Agent[]> {
    const client = clientForOptions(options);
    const agents = await client.listAgents();
    return agents.map((agent) => new Agent(client, agent));
  }

  static async listRuns(options: AgentOptions = {}): Promise<Run[]> {
    const client = clientForOptions(options);
    const runs = await client.listRuns();
    return runs.map((run) => new Run(client, run));
  }

  static async get(agentId: string, options: AgentOptions = {}): Promise<Agent> {
    const client = clientForOptions(options);
    return new Agent(client, await client.getAgent(agentId));
  }

  static async getRun(
    runId: string,
    options: AgentOptions & { runtime?: string; agentId?: string } = {},
  ): Promise<Run> {
    const client = clientForOptions(options);
    return new Run(client, await client.getRun(runId));
  }

  static async archive(agentId: string, options: AgentOptions = {}): Promise<Agent> {
    const client = clientForOptions(options);
    return new Agent(client, await client.archiveAgent(agentId));
  }

  static async unarchive(agentId: string, options: AgentOptions = {}): Promise<Agent> {
    const client = clientForOptions(options);
    return new Agent(client, await client.unarchiveAgent(agentId));
  }

  static async delete(agentId: string, options: AgentOptions = {}): Promise<void> {
    const client = clientForOptions(options);
    await client.deleteAgent(agentId);
  }

  static readonly messages = {
    list: async (runId: string, options: AgentOptions = {}) => {
      const client = clientForOptions(options);
      return client.conversation(runId);
    },
  };

  async send(prompt: string, options: SendOptions = {}): Promise<Run> {
    return this.wrapRun(await this.client.send(this.id, prompt, options));
  }

  async plan(prompt: string, options: PlanOptions = {}): Promise<Run> {
    return this.wrapRun(await this.client.plan(this.id, prompt, options));
  }

  async dryRun(prompt: string, options: DryRunOptions = {}): Promise<Run> {
    return this.wrapRun(await this.client.dryRun(this.id, prompt, options));
  }

  async handoff(prompt: string, options: HandoffOptions = {}): Promise<Run> {
    return this.wrapRun(await this.client.handoff(this.id, prompt, options));
  }

  async learn(options: LearnOptions): Promise<Run> {
    if (!options.taskFamily.trim()) {
      throw new IoiAgentError({
        code: "config",
        message: "agent.learn requires a taskFamily.",
      });
    }
    return this.wrapRun(await this.client.learn(this.id, options));
  }

  async close(): Promise<void> {
    await this.client.closeAgent(this.id);
  }

  async reload(): Promise<Agent> {
    return new Agent(this.client, await this.client.reloadAgent(this.id));
  }

  async artifacts(): Promise<unknown[]> {
    const runs = await this.client.listRuns(this.id);
    return Promise.all(runs.flatMap((run) => this.client.listArtifacts(run.id)));
  }

  private wrapRun(record: Awaited<ReturnType<RuntimeSubstrateClient["send"]>>): Run {
    return new Run(this.client, record);
  }
}

export const CursorCompatibleAgent = Agent;

export const Cursor = {
  me: async () => ({
    id: "local-operator",
    email: process.env.IOI_OPERATOR_EMAIL ?? null,
    source: "ioi-agent-sdk",
  }),
  models: {
    list: async (options: AgentOptions = {}) => clientForOptions(options).listModels(),
  },
  repositories: {
    list: async (options: AgentOptions = {}) => clientForOptions(options).listRepositories(),
  },
};

export function createAgentPlatform(options: AgentOptions = {}): RuntimeSubstrateClient {
  return clientForOptions(options);
}
