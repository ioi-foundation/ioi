// The canonical lifecycle contract, run against the RUST hypervisor-daemon via the SDK
// (createRuntimeSubstrateClient + Agent), mirroring live-runtime-daemon-contract.test.mjs
// test 386's flow. This is the Rust-ready slice of the split-brain repoint: it asserts the
// parity the Rust daemon already satisfies end-to-end through the SDK, and grows as more
// parity lands. The deferred Cursor.models.list (model-mount /v1/models array-shape) is
// the one remaining gap and is NOT asserted here yet. This file is the seed of the contract
// that replaces the JS-daemon contract at full JS-daemon retirement.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

async function importSdk() {
  const bundle = path.join(root, "packages/agent-sdk/dist/index.js");
  const sources = [
    "packages/agent-sdk/src/index.ts",
    "packages/agent-sdk/src/messages.ts",
    "packages/agent-sdk/src/runtime-events.ts",
    "packages/agent-sdk/src/substrate-client.ts",
  ].map((file) => path.join(root, file));
  const bundleMtime = fs.existsSync(bundle) ? fs.statSync(bundle).mtimeMs : 0;
  const sourceIsNewer = sources.some(
    (source) => fs.existsSync(source) && fs.statSync(source).mtimeMs > bundleMtime,
  );
  if (!fs.existsSync(bundle) || sourceIsNewer) {
    execFileSync("npm", ["run", "build", "--workspace=@ioi/agent-sdk"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return import(path.join(root, "packages/agent-sdk/dist/index.js"));
}

async function collect(iterable) {
  const out = [];
  for await (const value of iterable) out.push(value);
  return out;
}

test("Rust hypervisor-daemon satisfies the canonical lifecycle contract via the SDK round-trip", async () => {
  const { Agent, Cursor, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-contract-ws-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-contract-state-"));
  const daemon = await startRustHypervisorDaemon({ stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });

    // --- Agent.create -> agent.send (the SDK send path = POST /v1/agents/:id/runs) ---
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    assert.match(agent.id, /^agent_/, "Agent.create returns an agent record");
    const run = await agent.send("Drive the Rust daemon lifecycle contract via the SDK.");
    assert.match(run.id, /^run_/, "agent.send creates a run");
    assert.equal(run.agentId, agent.id, "run is bound to the agent");

    // --- run.stream() = GET /v1/runs/:id/events ---
    const streamed = [];
    for await (const event of run.stream()) {
      streamed.push(event);
      if (streamed.length >= 4) break;
    }
    assert.ok(streamed.length >= 1, "run.stream() yields runtime events");

    // --- run.trace(): canonical Agentgres projection + materialized task/job/checklist ---
    const trace = await run.trace();
    assert.equal(trace.canonicalState.source, "agentgres_canonical_state_projection");
    assert.equal(trace.runtimeTask.schemaVersion, "ioi.agent-runtime.task-record.v1");
    assert.equal(trace.runtimeTask.object, "ioi.runtime_task");
    assert.equal(trace.runtimeTask.runId, run.id);
    assert.equal(trace.runtimeTask.promptIncluded, false);
    assert.equal(trace.runtimeTask.durable, true);
    assert.equal(trace.runtimeTask.replayable, true);
    assert.equal(trace.runtimeJob.schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(trace.runtimeJob.object, "ioi.runtime_job");
    assert.equal(trace.runtimeJob.queueName, "local-agentgres");
    assert.equal(trace.runtimeChecklist.schemaVersion, "ioi.agent-runtime.checklist-record.v1");
    assert.equal(trace.runtimeChecklist.object, "ioi.runtime_checklist");
    assert.equal(trace.runtimeChecklist.readOnly, true);

    // --- run.scorecard() ---
    assert.equal((await run.scorecard()).verifierIndependence, 1);

    // --- run.artifacts(): the materialized canonical artifacts ---
    const artifacts = await run.artifacts();
    for (const name of ["runtime-task.json", "runtime-job.json", "runtime-checklist.json"]) {
      assert.ok(artifacts.some((artifact) => artifact.name === name), `artifacts include ${name}`);
    }

    // --- the canonical Agentgres state bundle is on disk ---
    for (const dir of ["runs", "tasks", "jobs", "checklists", "scorecards", "ledgers", "projections"]) {
      assert.ok(fs.existsSync(path.join(stateDir, dir)), `state bundle dir ${dir}/ exists`);
    }

    // --- run.cancel() -> the run + its bundle reflect the cancel ---
    const canceled = await run.cancel();
    assert.equal(await canceled.status(), "canceled", "run.cancel() cancels the run");
    const replay = await collect(canceled.replay());
    assert.ok(replay.length >= 1, "run.replay() yields events after cancel");

    // --- Cursor.account + runtimeNodes (canonical Agentgres identifiers) ---
    const account = await Cursor.account.get({ substrateClient: client });
    assert.equal(account.source, "ioi-daemon-agentgres");
    const nodes = await Cursor.runtimeNodes.list({ substrateClient: client });
    assert.ok(nodes.some((node) => node.id === "local-daemon-agentgres"));

    // NOTE (deferred): Cursor.models.list()[0].provider === "ioi-daemon-local" is the
    // model-mount /v1/models array-shape divergence and is not asserted here yet.
  } finally {
    await daemon.close();
  }
});
