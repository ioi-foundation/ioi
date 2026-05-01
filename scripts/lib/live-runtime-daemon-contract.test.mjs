import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");

async function importSdk() {
  return import("../../packages/agent-sdk/dist/index.js");
}

async function collect(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

function terminalCount(events) {
  return events.filter((event) => ["completed", "canceled", "failed", "error"].includes(event.type))
    .length;
}

test("local daemon public API persists canonical Agentgres state and replays without terminal duplication", async () => {
  const { Agent, Cursor, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agentgres-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    const run = await agent.send(
      "Create a local SDK run, cancel it, reconnect, and prove no terminal event was duplicated.",
    );
    const firstBatch = [];
    for await (const event of run.stream()) {
      firstBatch.push(event);
      if (firstBatch.length === 4) break;
    }
    const resumed = await collect(run.stream({ lastEventId: firstBatch.at(-1).id }));
    assert.equal(terminalCount([...firstBatch, ...resumed]), 1);

    const canceled = await run.cancel();
    const canceledReplay = await collect(canceled.replay());
    assert.equal(await canceled.status(), "canceled");
    assert.equal(terminalCount(canceledReplay), 1);
    assert.equal(canceledReplay.at(-1)?.type, "canceled");

    const trace = await canceled.trace();
    assert.equal(trace.canonicalState.source, "agentgres_canonical_operation_log");
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "agentgres_canonical_write"));
    assert.equal((await canceled.scorecard()).verifierIndependence, 1);
    assert.ok((await canceled.artifacts()).some((artifact) => artifact.name === "agentgres-projection.json"));

    const operationLog = path.join(stateDir, "operation-log.jsonl");
    assert.ok(fs.existsSync(operationLog));
    assert.ok(fs.readFileSync(operationLog, "utf8").includes("run.cancel"));
    for (const relative of [
      ["runs", `${run.id}.json`],
      ["tasks", `${run.id}.json`],
      ["scorecards", `${run.id}.json`],
      ["ledgers", `${run.id}.json`],
      ["projections", `${run.id}.json`],
    ]) {
      assert.ok(fs.existsSync(path.join(stateDir, ...relative)), relative.join("/"));
    }

    const models = await Cursor.models.list({ substrateClient: client });
    assert.equal(models.at(0)?.provider, "ioi-daemon-local");
    const account = await Cursor.account.get({ substrateClient: client });
    assert.equal(account.source, "ioi-daemon-agentgres");
    const nodes = await Cursor.runtimeNodes.list({ substrateClient: client });
    assert.ok(nodes.some((node) => node.id === "local-daemon-agentgres"));

    const cliView = await fetch(`${daemon.endpoint}/v1/runs/${run.id}/trace`).then((response) =>
      response.json(),
    );
    assert.equal(cliView.canonicalState.runId, run.id);
    assert.equal(cliView.canonicalState.terminalState, "canceled");
  } finally {
    await daemon.close();
  }
});

test("local daemon hosted and self-hosted modes fail closed without provider endpoints", async () => {
  const { Agent, createRuntimeSubstrateClient, IoiAgentError } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-daemon-blocker-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agentgres-blocker-"));
  const savedHosted = process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  const savedSelfHosted = process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  delete process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    await assert.rejects(
      Agent.create({
        local: { cwd },
        hosted: {
          repos: [{ url: "https://example.invalid/ioi.git" }],
          provider: { providerId: "missing-hosted-provider" },
        },
        substrateClient: client,
      }),
      (error) =>
        error instanceof IoiAgentError &&
        error.code === "external_blocker" &&
        error.status === 424,
    );
  } finally {
    await daemon.close();
    if (savedHosted === undefined) delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = savedHosted;
    if (savedSelfHosted === undefined) delete process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT = savedSelfHosted;
  }
});

