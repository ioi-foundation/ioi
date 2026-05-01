import type {
  ConversationMessage,
  IOIRunResult,
  IOISDKMessage,
  RuntimeScorecard,
  RuntimeTraceBundle,
} from "./messages.js";
import type { StreamOptions } from "./options.js";
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
