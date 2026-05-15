import type {
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  ModelRouteDecision,
  RuntimeScorecard,
  RuntimeTraceBundle,
} from "./messages.js";
import type { StreamOptions } from "./options.js";
import type {
  ComputerUseHarnessImprovementPlan,
  ComputerUseTrajectoryEvalProjection,
} from "./computer-use.js";
import type { RuntimeArtifact, RuntimeRunRecord, RuntimeSubstrateClient } from "./substrate-client.js";

export class Run {
  readonly id: string;
  readonly agentId: string;
  private readonly client: RuntimeSubstrateClient;

  constructor(client: RuntimeSubstrateClient, record: RuntimeRunRecord) {
    this.client = client;
    this.id = record.id;
    this.agentId = record.agentId;
  }

  async *stream(options: StreamOptions = {}): AsyncIterable<IOISDKMessage> {
    const mode = options.mode ?? "replay-and-tail";
    if (mode === "tail" && !options.lastEventId) {
      return;
    }
    for await (const event of this.client.streamRun(this.id, {
      lastEventId: options.lastEventId,
    })) {
      options.signal?.throwIfAborted();
      yield event;
    }
  }

  wait(): Promise<IOIRunResult> {
    return this.client.waitRun(this.id);
  }

  async cancel(): Promise<Run> {
    return new Run(this.client, await this.client.cancelRun(this.id));
  }

  conversation(): Promise<ConversationMessage[]> {
    return this.client.conversation(this.id);
  }

  status(): Promise<RuntimeRunRecord["status"]> {
    return this.client.getRun(this.id).then((run) => run.status);
  }

  inspect(): Promise<RuntimeTraceBundle> {
    return this.client.inspectRun(this.id);
  }

  trace(): Promise<RuntimeTraceBundle> {
    return this.client.exportTrace(this.id);
  }

  computerUseTrace(): Promise<RuntimeTraceBundle["computerUse"]> {
    return this.client.getRunComputerUseTrace(this.id);
  }

  computerUseTrajectory(): Promise<unknown> {
    return this.client.getRunComputerUseTrajectory(this.id);
  }

  computerUseTrajectoryEval(): Promise<ComputerUseTrajectoryEvalProjection> {
    return this.client.getRunComputerUseTrajectoryEval(this.id);
  }

  computerUseHarnessImprovementPlan(): Promise<ComputerUseHarnessImprovementPlan> {
    return this.client.getRunComputerUseHarnessImprovementPlan(this.id);
  }

  async routeDecision(): Promise<ModelRouteDecision | null> {
    const trace = await this.inspect();
    return trace.modelRouteDecision ?? null;
  }

  replay(): AsyncIterable<IOISDKMessage> {
    return this.client.replayTrace(this.id);
  }

  scorecard(): Promise<RuntimeScorecard> {
    return this.client.scorecard(this.id);
  }

  artifacts(): Promise<RuntimeArtifact[]> {
    return this.client.listArtifacts(this.id);
  }

  artifact(artifactId: string): Promise<RuntimeArtifact> {
    return this.client.downloadArtifact(this.id, artifactId);
  }
}
